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
                    let flow = self.classifier.classify(&raw);
                    match self.registrar.register(flow, now_secs) {
                        FlowDecision::Immediate(RuleAction::Allow) => Verdict::Accept,
                        // Deny rule, Ask without resolution, queue overflow, or pending →
                        // drop the current packet; the app will retransmit after the decision.
                        _ => Verdict::Drop,
                    }
                }
            };

            msg.set_verdict(verdict);
            self.queue.verdict(msg)?;
        }
    }
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

    let (src_port, dst_port, protocol) = match sliced.transport.as_ref() {
        Some(TransportSlice::Tcp(t)) => {
            (t.source_port(), t.destination_port(), TransportProtocol::Tcp)
        }
        Some(TransportSlice::Udp(u)) => {
            let (sp, dp) = (u.source_port(), u.destination_port());
            // Best-effort QUIC detection: UDP to/from port 443.
            let proto =
                if dp == 443 || sp == 443 { TransportProtocol::Quic } else { TransportProtocol::Udp };
            (sp, dp, proto)
        }
        _ => (0, 0, TransportProtocol::Other),
    };

    Some(RawPacket {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
        sni_hint: None,
        ingress_interface: None,
    })
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
}
