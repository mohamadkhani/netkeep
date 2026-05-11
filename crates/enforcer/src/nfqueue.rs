use std::time::{SystemTime, UNIX_EPOCH};

use core_types::{RuleAction, TransportProtocol};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use flow_classifier::{Classifier, RawPacket};
use nfq::{Queue, Verdict};

use crate::{FlowDecision, FlowRegistrar};

/// Real packet processor that reads from an NFQUEUE and applies verdicts.
///
/// Open with `NfqueueProcessor::open`, then call `run_loop` on a dedicated thread.
/// The loop is intentionally blocking — each `recv` call parks the thread until
/// a packet arrives, so no busy-waiting occurs.
pub struct NfqueueProcessor<C, FR> {
    queue: Queue,
    classifier: C,
    registrar: FR,
}

impl<C, FR> NfqueueProcessor<C, FR>
where
    C: Classifier,
    FR: FlowRegistrar,
{
    pub fn open(queue_num: u16, classifier: C, registrar: FR) -> std::io::Result<Self> {
        let mut queue = Queue::open()?;
        queue.bind(queue_num)?;
        Ok(Self { queue, classifier, registrar })
    }

    /// Blocks indefinitely, processing one packet per iteration.
    /// Returns only on unrecoverable socket error.
    pub fn run_loop(&mut self) -> std::io::Result<()> {
        loop {
            let mut msg = self.queue.recv()?;

            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let verdict = match parse_raw_packet(msg.get_payload()) {
                None => Verdict::Drop,
                Some(raw) => {
                    // Pass through loopback (defense-in-depth) and TCP control packets
                    // (SYN/ACK/FIN) with no payload. Accepting SYNs lets the TCP handshake
                    // complete so the TLS ClientHello — which carries the SNI — arrives as
                    // the first classifiable packet.
                    if is_loopback(&raw.dst_ip) || raw.tcp_payload_empty {
                        Verdict::Accept
                    } else {
                        let flow = self.classifier.classify(&raw);
                        match self.registrar.register(flow, now_secs) {
                            FlowDecision::Immediate(RuleAction::Allow) => Verdict::Accept,
                            // Deny rule, Ask without resolution, queue overflow, or pending →
                            // drop the current packet; the app will retransmit after the decision.
                            _ => Verdict::Drop,
                        }
                    }
                }
            };

            msg.set_verdict(verdict);
            self.queue.verdict(msg)?;
        }
    }
}

fn is_loopback(ip: &str) -> bool {
    // IPv4 loopback: 127.0.0.0/8
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        return v4.octets()[0] == 127;
    }
    // IPv6 loopback: ::1, and IPv4-mapped loopback ::ffff:127.x.x.x (Rust's
    // `Ipv6Addr::is_loopback` is false for mapped addresses, so those packets
    // were still queued and produced Ask spam).
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        if v6.is_loopback() {
            return true;
        }
        if let Some(v4) = v6.to_ipv4_mapped() {
            return v4.octets()[0] == 127;
        }
    }
    false
}

/// Parse a raw IP-layer payload (as delivered by NFQUEUE) into a `RawPacket`.
/// Returns `None` for unsupported/malformed packets — caller should drop those.
pub fn parse_raw_packet(payload: &[u8]) -> Option<RawPacket> {
    let sliced = SlicedPacket::from_ip(payload).ok()?;

    let (src_ip, dst_ip) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(s) => {
            let h = s.header();
            (h.source_addr().to_string(), h.destination_addr().to_string())
        }
        NetSlice::Ipv6(s) => {
            let h = s.header();
            (h.source_addr().to_string(), h.destination_addr().to_string())
        }
    };

    let (src_port, dst_port, protocol, sni_hint, tcp_payload_empty) = match sliced.transport.as_ref() {
        Some(TransportSlice::Tcp(t)) => {
            let payload = t.payload();
            let sni = extract_tls_sni(payload);
            (t.source_port(), t.destination_port(), TransportProtocol::Tcp, sni, payload.is_empty())
        }
        Some(TransportSlice::Udp(u)) => {
            let (sp, dp) = (u.source_port(), u.destination_port());
            // Best-effort QUIC detection: UDP to/from port 443.
            let proto =
                if dp == 443 || sp == 443 { TransportProtocol::Quic } else { TransportProtocol::Udp };
            (sp, dp, proto, None, false)
        }
        _ => (0, 0, TransportProtocol::Other, None, false),
    };

    Some(RawPacket {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
        sni_hint,
        ingress_interface: None,
        tcp_payload_empty,
    })
}

/// Extract the TLS SNI hostname from a TCP payload containing a TLS ClientHello.
///
/// TLS record layout:
///   [0]    content type: 0x16 (handshake)
///   [1..2] legacy version: 0x03 0x01 (or 0x03 0x03)
///   [3..4] record length (big-endian u16)
///   [5]    handshake type: 0x01 (ClientHello)
///   [6..8] handshake length (big-endian u24)
///   [9..10] client version
///   [11..42] random (32 bytes)
///   [43]   session id length
///   ...    session id
///   then:  cipher suites length (u16), cipher suites
///   then:  compression methods length (u8), compression methods
///   then:  extensions length (u16), extensions
///     each extension: type (u16) + length (u16) + data
///     SNI extension type = 0x0000
///       SNI list length (u16)
///       SNI entry type (u8, 0x00 = host_name) + name length (u16) + name bytes
fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    // Need at least TLS record header (5) + handshake header (4) + hello header (34+)
    if payload.len() < 43 {
        return None;
    }
    // TLS handshake record
    if payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    // Handshake type must be ClientHello (0x01)
    if payload[5] != 0x01 {
        return None;
    }

    let mut pos = 43; // start of session id length

    // Skip session id
    let session_id_len = *payload.get(pos)? as usize;
    pos += 1 + session_id_len;

    // Skip cipher suites
    let cipher_suites_len = u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]) as usize;
    pos += 2 + cipher_suites_len;

    // Skip compression methods
    let compression_len = *payload.get(pos)? as usize;
    pos += 1 + compression_len;

    // Extensions length
    if pos + 2 > payload.len() {
        return None;
    }
    let extensions_end = pos + 2 + u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    // Walk extensions
    while pos + 4 <= extensions_end && pos + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > payload.len() {
            return None;
        }

        if ext_type == 0x0000 {
            // SNI extension: list_length(u16) + type(u8) + name_length(u16) + name
            if ext_len < 5 {
                return None;
            }
            let ext_data = &payload[pos..pos + ext_len];
            // SNI entry type 0x00 = host_name
            if ext_data[2] != 0x00 {
                return None;
            }
            let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
            if ext_data.len() < 5 + name_len {
                return None;
            }
            return std::str::from_utf8(&ext_data[5..5 + name_len]).ok().map(str::to_string);
        }

        pos += ext_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn build_ipv4_tcp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let payload = b"hello";
        let mut buf = Vec::new();
        PacketBuilder::ipv4(src, dst, 64)
            .tcp(src_port, dst_port, 0, 65535)
            .write(&mut buf, payload)
            .unwrap();
        // NFQUEUE delivers the IP layer, so strip Ethernet (there is none here).
        buf
    }

    fn build_ipv4_udp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let payload = b"hi";
        let mut buf = Vec::new();
        PacketBuilder::ipv4(src, dst, 64)
            .udp(src_port, dst_port)
            .write(&mut buf, payload)
            .unwrap();
        buf
    }

    #[test]
    fn parses_ipv4_tcp_packet() {
        let raw = build_ipv4_tcp([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443);
        let pkt = parse_raw_packet(&raw).expect("parsed");
        assert_eq!(pkt.src_ip, "10.0.0.1");
        assert_eq!(pkt.dst_ip, "1.1.1.1");
        assert_eq!(pkt.src_port, 54321);
        assert_eq!(pkt.dst_port, 443);
        assert_eq!(pkt.protocol, TransportProtocol::Tcp);
    }

    #[test]
    fn parses_ipv4_udp_non_quic() {
        let raw = build_ipv4_udp([192, 168, 1, 1], [8, 8, 8, 8], 12345, 53);
        let pkt = parse_raw_packet(&raw).expect("parsed");
        assert_eq!(pkt.protocol, TransportProtocol::Udp);
        assert_eq!(pkt.dst_port, 53);
    }

    #[test]
    fn udp_port_443_detected_as_quic() {
        let raw = build_ipv4_udp([10, 0, 0, 2], [1, 1, 1, 1], 55000, 443);
        let pkt = parse_raw_packet(&raw).expect("parsed");
        assert_eq!(pkt.protocol, TransportProtocol::Quic);
    }

    #[test]
    fn malformed_payload_returns_none() {
        assert!(parse_raw_packet(&[0xde, 0xad, 0xbe, 0xef]).is_none());
        assert!(parse_raw_packet(&[]).is_none());
    }

    /// Build a minimal TLS ClientHello TCP payload with the given SNI hostname.
    fn build_tls_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let name_len = sni_bytes.len() as u16;
        // SNI extension data: list_len(u16) + entry_type(u8) + name_len(u16) + name
        let sni_ext_data_len = (2 + 1 + 2 + sni_bytes.len()) as u16;
        // Full extension wire size: type(2) + len(2) + data
        let sni_ext_total = 4 + sni_ext_data_len as usize;
        // Minimal ClientHello body: version(2) + random(32) + session_id_len(1) +
        // cipher_suites_len(2) + cipher_suite(2) + compression_len(1) + null(1) +
        // extensions_len(2) + SNI extension
        let hello_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + sni_ext_total;
        // TLS record length: handshake_type(1) + handshake_len(3) + body
        let record_len = (1 + 3 + hello_body_len) as u16;

        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x16, 0x03, 0x01]);          // TLS record header
        buf.extend_from_slice(&record_len.to_be_bytes());
        buf.push(0x01);                                        // handshake type: ClientHello
        buf.push(0x00);
        buf.extend_from_slice(&(hello_body_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x03, 0x03]);                 // client_version TLS 1.2
        buf.extend_from_slice(&[0u8; 32]);                    // random
        buf.push(0x00);                                        // session_id_len = 0
        buf.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);    // cipher_suites
        buf.extend_from_slice(&[0x01, 0x00]);                 // compression: null
        buf.extend_from_slice(&(sni_ext_total as u16).to_be_bytes()); // extensions_len
        buf.extend_from_slice(&[0x00, 0x00]);                 // SNI extension type
        buf.extend_from_slice(&sni_ext_data_len.to_be_bytes());
        buf.extend_from_slice(&(1 + 2 + name_len).to_be_bytes()); // SNI list_len
        buf.push(0x00);                                        // entry type: host_name
        buf.extend_from_slice(&name_len.to_be_bytes());
        buf.extend_from_slice(sni_bytes);
        buf
    }

    #[test]
    fn sni_extracted_from_tls_client_hello() {
        let hello = build_tls_client_hello("example.com");
        assert_eq!(extract_tls_sni(&hello), Some("example.com".to_string()));
    }

    #[test]
    fn sni_not_present_in_non_tls_payload() {
        assert_eq!(extract_tls_sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(extract_tls_sni(&[]), None);
    }

    #[test]
    fn tcp_packet_with_tls_hello_populates_sni_hint() {
        let hello = build_tls_client_hello("secure.example.org");
        let mut buf = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 1], [1, 1, 1, 1], 64)
            .tcp(54321, 443, 0, 65535)
            .write(&mut buf, &hello)
            .unwrap();
        let pkt = parse_raw_packet(&buf).expect("parsed");
        assert_eq!(pkt.sni_hint.as_deref(), Some("secure.example.org"));
    }

    #[test]
    fn tcp_packet_without_tls_has_no_sni_hint() {
        let raw = build_ipv4_tcp([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443);
        let pkt = parse_raw_packet(&raw).expect("parsed");
        assert_eq!(pkt.sni_hint, None);
    }

    #[test]
    fn loopback_includes_ipv4_mapped_127() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.42.3.4"));
        assert!(is_loopback("::1"));
        assert!(is_loopback("::ffff:127.0.0.1"));
        assert!(is_loopback("::ffff:127.255.0.1"));
        assert!(!is_loopback("10.0.0.1"));
        assert!(!is_loopback("::ffff:8.8.8.8"));
        assert!(!is_loopback("2001:db8::1"));
    }
}
