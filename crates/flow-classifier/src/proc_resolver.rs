use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use core_types::TransportProtocol;

use crate::ProcessResolver;

/// Real ProcessResolver that maps (src_ip, src_port, protocol) → process name
/// by reading /proc/net/{tcp,tcp6,udp,udp6} and /proc/<pid>/fd.
pub struct ProcProcessResolver;

impl ProcessResolver for ProcProcessResolver {
    fn resolve(&self, src_ip: &str, src_port: u16, protocol: TransportProtocol) -> Option<String> {
        let ip: IpAddr = src_ip.parse().ok()?;
        let inode = find_socket_inode(ip, src_port, protocol)?;
        let pid = find_pid_for_inode(inode)?;
        read_comm(pid)
    }
}

/// Find the socket inode from /proc/net/{tcp,tcp6,udp,udp6} for a local address.
fn find_socket_inode(src_ip: IpAddr, src_port: u16, protocol: TransportProtocol) -> Option<u64> {
    let files: &[&str] = match (protocol, src_ip) {
        (TransportProtocol::Udp | TransportProtocol::Quic, IpAddr::V4(_)) => {
            &["/proc/net/udp"]
        }
        (TransportProtocol::Udp | TransportProtocol::Quic, IpAddr::V6(_)) => {
            &["/proc/net/udp6", "/proc/net/udp"]
        }
        (_, IpAddr::V4(_)) => &["/proc/net/tcp"],
        (_, IpAddr::V6(_)) => &["/proc/net/tcp6", "/proc/net/tcp"],
    };

    for path in files {
        if let Ok(content) = fs::read_to_string(path) {
            if let Some(inode) = parse_proc_net(&content, src_ip, src_port) {
                return Some(inode);
            }
        }
    }
    None
}

/// Parse a /proc/net/tcp or /proc/net/tcp6 file and return the inode for a
/// matching local address (src_ip:src_port). Skips the header line.
///
/// Each data line has the format:
///   sl  local_address rem_address st tx_queue rx_queue tr tm uid timeout inode ...
/// local_address for IPv4: HHHHHHHH:PPPP  (hex IP little-endian, hex port big-endian)
/// local_address for IPv6: HHHH...HHHH:PPPP  (32 hex chars, 4-byte groups little-endian)
pub fn parse_proc_net(content: &str, src_ip: IpAddr, src_port: u16) -> Option<u64> {
    let port_hex = format!("{:04X}", src_port);

    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let local = cols[1]; // "ADDR:PORT"
        let Some(colon) = local.rfind(':') else { continue };
        let addr_hex = &local[..colon];
        let port_part = &local[colon + 1..];

        if port_part != port_hex {
            continue;
        }

        let matches = match src_ip {
            IpAddr::V4(v4) => parse_ipv4_hex(addr_hex) == Some(v4),
            IpAddr::V6(v6) => {
                // Try exact IPv6 match first, then IPv4-mapped fallback.
                parse_ipv6_hex(addr_hex) == Some(v6)
                    || v6
                        .to_ipv4_mapped()
                        .and_then(|v4| parse_ipv4_hex(addr_hex).map(|a| a == v4))
                        .unwrap_or(false)
            }
        };

        if matches {
            // inode is column index 9
            if let Ok(inode) = cols[9].parse::<u64>() {
                return Some(inode);
            }
        }
    }
    None
}

/// Decode a /proc/net/tcp IPv4 hex address (little-endian u32 → Ipv4Addr).
fn parse_ipv4_hex(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(n.to_be()))
}

/// Decode a /proc/net/tcp6 IPv6 hex address (four little-endian u32 words).
fn parse_ipv6_hex(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&hex[i * 8..(i + 1) * 8], 16).ok()?;
        // Each 32-bit word is stored little-endian in /proc/net/tcp6.
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

/// Scan /proc/*/fd/* for a symlink pointing to socket:[inode].
/// Returns the first matching pid.
fn find_pid_for_inode(inode: u64) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    let proc = fs::read_dir("/proc").ok()?;

    for entry in proc.flatten() {
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else { continue };

        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else { continue };

        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path()) {
                if link.to_string_lossy() == target {
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// Read /proc/<pid>/comm (process name, newline-trimmed).
fn read_comm(pid: u32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(comm.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP_SAMPLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0F02000A:1F90 0101010101:0000 01 00000000:00000000 00:00000000 00000000  1000        0 99001 1 0 100 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0 100 0";

    const TCP6_SAMPLE: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 99002 1 0 100 0";

    #[test]
    fn parses_ipv4_local_address() {
        // 0F02000A in little-endian = 10.0.2.15, port 0x1F90 = 8080
        let ip: IpAddr = "10.0.2.15".parse().unwrap();
        let inode = parse_proc_net(TCP_SAMPLE, ip, 8080);
        assert_eq!(inode, Some(99001));
    }

    #[test]
    fn returns_none_for_wrong_port() {
        let ip: IpAddr = "10.0.2.15".parse().unwrap();
        assert_eq!(parse_proc_net(TCP_SAMPLE, ip, 9999), None);
    }

    #[test]
    fn returns_none_for_wrong_ip() {
        let ip: IpAddr = "10.0.2.99".parse().unwrap();
        assert_eq!(parse_proc_net(TCP_SAMPLE, ip, 8080), None);
    }

    #[test]
    fn parses_ipv6_local_address() {
        // 00000000000000000000000001000000 → ::1 (loopback), port 0x1F90 = 8080
        let ip: IpAddr = "::1".parse().unwrap();
        let inode = parse_proc_net(TCP6_SAMPLE, ip, 8080);
        assert_eq!(inode, Some(99002));
    }

    #[test]
    fn parse_ipv4_hex_roundtrip() {
        // 10.0.2.15 → little-endian u32 → hex "0F02000A"
        let addr = parse_ipv4_hex("0F02000A").unwrap();
        assert_eq!(addr, Ipv4Addr::new(10, 0, 2, 15));
    }

    #[test]
    fn parse_ipv6_hex_loopback() {
        let addr = parse_ipv6_hex("00000000000000000000000001000000").unwrap();
        assert_eq!(addr, Ipv6Addr::LOCALHOST);
    }
}
