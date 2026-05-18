use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{SlicedPacket, TransportSlice};
use flow_classifier::SniDnsCache;
use nfq::{Queue, Verdict};

/// Passive DNS response snooper.
///
/// Binds to a second NFQUEUE queue (INPUT hook, `bypass` flag) that receives
/// copies of inbound UDP packets with `src_port == 53`. Parses DNS wire-format
/// A and AAAA answers and writes `dst_ip → query_domain` into `SniDnsCache`,
/// then immediately accepts every packet.
///
/// With the nftables `bypass` flag, if this worker is not running (e.g. NFQUEUE
/// not configured, daemon restarting) all DNS responses pass through unaffected.
pub struct DnsSnoopWorker {
    queue: Queue,
    dns_cache: SniDnsCache,
}

impl DnsSnoopWorker {
    pub fn open(queue_num: u16, dns_cache: SniDnsCache) -> std::io::Result<Self> {
        let mut queue = Queue::open()?;
        queue.bind(queue_num)?;
        Ok(Self { queue, dns_cache })
    }

    /// Blocks indefinitely. Returns only on unrecoverable socket error.
    pub fn run_loop(&mut self) -> std::io::Result<()> {
        loop {
            let mut msg = self.queue.recv()?;
            if let Some(entries) = parse_dns_from_ip_packet(msg.get_payload()) {
                for (ip, domain) in entries {
                    self.dns_cache.insert(&ip.to_string(), &domain);
                }
            }
            msg.set_verdict(Verdict::Accept);
            self.queue.verdict(msg)?;
        }
    }
}

/// Extract (resolved_ip, queried_domain) pairs from a raw IP packet
/// (IP header + UDP header + DNS payload).
fn parse_dns_from_ip_packet(payload: &[u8]) -> Option<Vec<(IpAddr, String)>> {
    let sliced = SlicedPacket::from_ip(payload).ok()?;
    let udp = match &sliced.transport {
        Some(TransportSlice::Udp(u)) => u,
        _ => return None,
    };
    // Only DNS responses (src_port == 53, checked defensively even though
    // the nftables rule already filters this).
    if udp.source_port() != 53 {
        return None;
    }
    let results = parse_dns_packet(udp.payload());
    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Parse a DNS response wire-format payload (no IP/UDP headers).
///
/// Returns a list of `(ip_address, queried_domain)` pairs extracted from
/// A (type 1) and AAAA (type 28) answer records. The `queried_domain` comes
/// from the first QNAME in the question section, which is the name the
/// application actually queried — correct even with CNAME chains.
///
/// Returns an empty vec on any parse error or if the packet is a query
/// (not a response), has a non-zero RCODE, or has no usable answers.
pub fn parse_dns_packet(data: &[u8]) -> Vec<(IpAddr, String)> {
    if data.len() < 12 {
        return vec![];
    }
    // Byte 2 bit 7 = QR flag: 1 = response.
    if data[2] & 0x80 == 0 {
        return vec![];
    }
    // Byte 3 bits 0-3 = RCODE: 0 = no error. Skip NXDOMAIN / SERVFAIL etc.
    if data[3] & 0x0F != 0 {
        return vec![];
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if ancount == 0 {
        return vec![];
    }

    let mut pos = 12;

    // Extract the first QNAME — that is the domain the application queried.
    let domain = match read_name(data, &mut pos) {
        Some(d) if !d.is_empty() => d,
        _ => return vec![],
    };
    // Skip QTYPE (2) + QCLASS (2).
    if pos + 4 > data.len() {
        return vec![];
    }
    pos += 4;

    // Skip any additional questions beyond the first.
    for _ in 1..qdcount {
        if skip_name(data, &mut pos).is_none() {
            return vec![];
        }
        if pos + 4 > data.len() {
            return vec![];
        }
        pos += 4;
    }

    // Parse answer resource records.
    let mut results = Vec::new();
    for _ in 0..ancount {
        // NAME field in the answer (often a pointer back to the question).
        if skip_name(data, &mut pos).is_none() {
            break;
        }
        // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes.
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        match rtype {
            1 if rdlength == 4 => {
                let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
                results.push((IpAddr::V4(ip), domain.clone()));
            }
            28 if rdlength == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&data[pos..pos + 16]);
                results.push((IpAddr::V6(Ipv6Addr::from(bytes)), domain.clone()));
            }
            _ => {}
        }
        pos += rdlength;
    }
    results
}

/// Read a DNS domain name at `*pos`, advancing past it. Returns the dot-joined
/// label string (e.g. `"api.example.com"`). Handles label-pointer compression.
fn read_name(data: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    // When we follow a pointer, we save the position right after the 2-byte
    // pointer so `*pos` is updated to the correct resume point on exit.
    let mut resume_pos: Option<usize> = None;
    let mut cur = *pos;
    // Guard against circular pointer loops.
    let mut hops = 0usize;

    loop {
        if hops > 20 {
            return None;
        }
        hops += 1;

        let len = *data.get(cur)?;
        if len == 0 {
            cur += 1;
            break;
        } else if len & 0xC0 == 0xC0 {
            // Pointer: 2 bytes encoding a 14-bit offset into the packet.
            let hi = (len & 0x3F) as usize;
            let lo = *data.get(cur + 1)? as usize;
            if resume_pos.is_none() {
                resume_pos = Some(cur + 2);
            }
            cur = (hi << 8) | lo;
        } else if len & 0xC0 == 0 {
            // Regular label: 1 length byte + `len` ASCII bytes.
            let start = cur + 1;
            let end = start + len as usize;
            if end > data.len() {
                return None;
            }
            let label = std::str::from_utf8(&data[start..end]).ok()?.to_lowercase();
            labels.push(label);
            cur = end;
        } else {
            // Invalid label type (e.g. EDNS extended labels — not used in practice).
            return None;
        }
    }

    *pos = resume_pos.unwrap_or(cur);
    Some(labels.join("."))
}

/// Advance `*pos` past a DNS domain name without decoding it.
/// Handles pointer compression (a pointer byte-pair is the end of the name
/// for the purpose of position tracking in the current record).
fn skip_name(data: &[u8], pos: &mut usize) -> Option<()> {
    loop {
        let len = *data.get(*pos)?;
        if len == 0 {
            *pos += 1;
            return Some(());
        } else if len & 0xC0 == 0xC0 {
            // Pointer — 2 bytes, and the name ends here in the current record.
            *pos += 2;
            return Some(());
        } else if len & 0xC0 == 0 {
            *pos += 1 + len as usize;
        } else {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid DNS response for a single A-record query.
    /// Layout: header | question (QNAME + QTYPE=A + QCLASS=IN) | answer (PTR + TYPE + CLASS + TTL + RDLEN + RDATA)
    fn build_a_response(domain: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&[
            0x00, 0x01, // ID = 1
            0x81, 0x80, // QR=1 (response), OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ]);
        // Question: QNAME
        let qname_start = pkt.len();
        encode_name(&mut pkt, domain);
        pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
                                              // Answer: NAME as pointer to QNAME
        let ptr_offset = qname_start as u16;
        pkt.push(0xC0 | ((ptr_offset >> 8) as u8));
        pkt.push((ptr_offset & 0xFF) as u8);
        pkt.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        pkt.extend_from_slice(&ip.octets()); // RDATA
        pkt
    }

    fn build_aaaa_response(domain: &str, ip: Ipv6Addr) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        let qname_start = pkt.len();
        encode_name(&mut pkt, domain);
        pkt.extend_from_slice(&[0x00, 0x1C]); // QTYPE = AAAA
        pkt.extend_from_slice(&[0x00, 0x01]);
        let ptr_offset = qname_start as u16;
        pkt.push(0xC0 | ((ptr_offset >> 8) as u8));
        pkt.push((ptr_offset & 0xFF) as u8);
        pkt.extend_from_slice(&[0x00, 0x1C]); // TYPE = AAAA
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
        pkt.extend_from_slice(&[0x00, 0x10]); // RDLENGTH = 16
        pkt.extend_from_slice(&ip.octets());
        pkt
    }

    fn encode_name(buf: &mut Vec<u8>, domain: &str) {
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0x00); // root
    }

    #[test]
    fn parses_a_record() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let pkt = build_a_response("api.example.com", ip);
        let results = parse_dns_packet(&pkt);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, IpAddr::V4(ip));
        assert_eq!(results[0].1, "api.example.com");
    }

    #[test]
    fn parses_aaaa_record() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let pkt = build_aaaa_response("ipv6.example.com", ip);
        let results = parse_dns_packet(&pkt);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, IpAddr::V6(ip));
        assert_eq!(results[0].1, "ipv6.example.com");
    }

    #[test]
    fn query_packet_returns_empty() {
        // QR bit = 0 → query, not response
        let mut pkt = build_a_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        pkt[2] &= !0x80; // clear QR bit
        assert!(parse_dns_packet(&pkt).is_empty());
    }

    #[test]
    fn nxdomain_rcode_returns_empty() {
        let mut pkt = build_a_response("doesnotexist.example.com", Ipv4Addr::new(0, 0, 0, 0));
        pkt[3] = (pkt[3] & 0xF0) | 0x03; // RCODE = 3 (NXDOMAIN)
        assert!(parse_dns_packet(&pkt).is_empty());
    }

    #[test]
    fn truncated_packet_returns_empty() {
        assert!(parse_dns_packet(&[]).is_empty());
        assert!(parse_dns_packet(&[0x00; 5]).is_empty());
    }

    #[test]
    fn no_answer_records_returns_empty() {
        let mut pkt = build_a_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        // Set ANCOUNT = 0
        pkt[6] = 0;
        pkt[7] = 0;
        assert!(parse_dns_packet(&pkt).is_empty());
    }

    #[test]
    fn domain_is_lowercased() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        let qname_start = pkt.len();
        // Encode "Example.COM" with mixed case
        for label in ["Example", "COM"] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        let ptr = qname_start as u16;
        pkt.push(0xC0 | ((ptr >> 8) as u8));
        pkt.push((ptr & 0xFF) as u8);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
        pkt.extend_from_slice(&[9, 9, 9, 9]);
        let results = parse_dns_packet(&pkt);
        assert_eq!(results[0].1, "example.com");
    }

    #[test]
    fn multiple_a_records_all_captured() {
        // Build a response with ANCOUNT=2 (two A records for round-robin DNS).
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, // QDCOUNT=1
            0x00, 0x02, // ANCOUNT=2
            0x00, 0x00, 0x00, 0x00,
        ]);
        let qname_start = pkt.len();
        for label in ["google", "com"] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
                                                          // Answer 1
        let ptr = qname_start as u16;
        pkt.push(0xC0 | ((ptr >> 8) as u8));
        pkt.push((ptr & 0xFF) as u8);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
        pkt.extend_from_slice(&[142, 250, 185, 46]);
        // Answer 2
        pkt.push(0xC0 | ((ptr >> 8) as u8));
        pkt.push((ptr & 0xFF) as u8);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
        pkt.extend_from_slice(&[142, 250, 185, 78]);

        let results = parse_dns_packet(&pkt);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, "google.com");
        assert_eq!(results[1].1, "google.com");
    }
}
