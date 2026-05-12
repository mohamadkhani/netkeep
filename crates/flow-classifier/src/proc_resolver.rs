use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use core_types::TransportProtocol;

use crate::ProcessResolver;

/// Real ProcessResolver: (src_ip, src_port, protocol) → process name.
///
/// Lookup pipeline:
///   1. Read /proc/net/{tcp,tcp6,udp,udp6} — exact (ip, port) match → inode + uid
///   2. UDP fallback: port-only match for wildcard-bound sockets (0.0.0.0:port)
///   3. Retry up to 3× with short delays — socket may not be in /proc/net yet (TOCTOU)
///   4. UID-filtered /proc/*/fd/ scan — skip processes owned by wrong UID (fast path)
///   5. Prefer exe basename over comm (comm is truncated to 15 chars by the kernel)
///   6. Parent process exe basename — handles Electron/subprocess models where the
///      network child has a short or generic name
pub struct ProcProcessResolver;

impl ProcessResolver for ProcProcessResolver {
    fn resolve(&self, src_ip: &str, src_port: u16, protocol: TransportProtocol) -> Option<String> {
        let ip: IpAddr = src_ip.parse().ok()?;

        // Retry loop: TOCTOU — the socket entry may lag behind the packet by a few ms.
        let (inode, uid) = retry_find_socket(ip, src_port, protocol)?;

        let pid = find_pid_for_inode(inode, uid)?;

        let name = read_exe_basename(pid).or_else(|| read_comm(pid))?;

        // Walk to parent when the direct name is very short (likely a generic helper).
        if name.len() <= 3 {
            if let Some(parent_name) = read_ppid(pid).and_then(read_exe_basename) {
                return Some(parent_name);
            }
        }

        Some(name)
    }
}

/// Try to find the socket (inode, uid) with up to 3 attempts and increasing delays.
fn retry_find_socket(ip: IpAddr, port: u16, protocol: TransportProtocol) -> Option<(u64, u32)> {
    const DELAYS_MS: [u64; 3] = [0, 3, 8];
    for (attempt, &delay) in DELAYS_MS.iter().enumerate() {
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
        if let Some(result) = find_socket_inode(ip, port, protocol) {
            if attempt > 0 {
                eprintln!("proc_resolver: found socket after {} retries", attempt);
            }
            return Some(result);
        }
    }
    None
}

/// Find (inode, uid) from /proc/net/{tcp,tcp6,udp,udp6}.
///
/// For UDP, also tries a port-only match as a fallback because UDP sockets
/// not explicitly bound to a specific interface appear as `0.0.0.0:PORT`
/// in /proc/net/udp even though the outgoing packet carries a real source IP.
fn find_socket_inode(src_ip: IpAddr, src_port: u16, protocol: TransportProtocol) -> Option<(u64, u32)> {
    let is_udp = matches!(protocol, TransportProtocol::Udp | TransportProtocol::Quic);

    let files: &[&str] = match (is_udp, src_ip) {
        (true, IpAddr::V4(_))  => &["/proc/net/udp"],
        (true, IpAddr::V6(_))  => &["/proc/net/udp6", "/proc/net/udp"],
        (false, IpAddr::V4(_)) => &["/proc/net/tcp"],
        (false, IpAddr::V6(_)) => &["/proc/net/tcp6", "/proc/net/tcp"],
    };

    // Pass 1: exact (ip, port) match.
    for path in files {
        if let Ok(content) = fs::read_to_string(path) {
            if let Some(r) = parse_proc_net(&content, src_ip, src_port) {
                return Some(r);
            }
        }
    }

    // Pass 2 (UDP only): port-only match for wildcard-bound (0.0.0.0) sockets.
    if is_udp {
        for path in files {
            if let Ok(content) = fs::read_to_string(path) {
                if let Some(r) = parse_proc_net_port_only(&content, src_port) {
                    return Some(r);
                }
            }
        }
    }

    None
}

/// Parse /proc/net/tcp[6] or /proc/net/udp[6].
/// Returns (inode, uid) for the first row whose local address matches (src_ip, src_port).
///
/// Row format (whitespace-separated):
///   sl  local_addr  rem_addr  st  tx:rx  tr:tm  retrnsmt  uid  timeout  inode  ...
///   0   1           2         3   4      5      6         7    8        9
pub fn parse_proc_net(content: &str, src_ip: IpAddr, src_port: u16) -> Option<(u64, u32)> {
    let port_hex = format!("{:04X}", src_port);

    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let local = cols[1];
        let Some(colon) = local.rfind(':') else { continue };
        if &local[colon + 1..] != port_hex {
            continue;
        }
        let addr_hex = &local[..colon];
        let matches = match src_ip {
            IpAddr::V4(v4) => parse_ipv4_hex(addr_hex) == Some(v4),
            IpAddr::V6(v6) => {
                parse_ipv6_hex(addr_hex) == Some(v6)
                    || v6.to_ipv4_mapped()
                        .and_then(|v4| parse_ipv4_hex(addr_hex).map(|a| a == v4))
                        .unwrap_or(false)
            }
        };
        if matches {
            let inode: u64 = cols[9].parse().ok()?;
            let uid: u32 = cols[7].parse().unwrap_or(u32::MAX);
            return Some((inode, uid));
        }
    }
    None
}

/// Port-only match: find the first row whose local port equals src_port,
/// regardless of the bound address (handles 0.0.0.0 wildcard UDP sockets).
fn parse_proc_net_port_only(content: &str, src_port: u16) -> Option<(u64, u32)> {
    let port_hex = format!("{:04X}", src_port);

    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let local = cols[1];
        let Some(colon) = local.rfind(':') else { continue };
        if &local[colon + 1..] != port_hex {
            continue;
        }
        let inode: u64 = cols[9].parse().ok()?;
        let uid: u32 = cols[7].parse().unwrap_or(u32::MAX);
        return Some((inode, uid));
    }
    None
}

/// Decode a /proc/net/tcp IPv4 hex address (little-endian u32 → Ipv4Addr).
fn parse_ipv4_hex(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 { return None; }
    let n = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(n.to_be()))
}

/// Decode a /proc/net/tcp6 IPv6 hex address (four little-endian u32 words).
fn parse_ipv6_hex(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 { return None; }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&hex[i * 8..(i + 1) * 8], 16).ok()?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

/// Scan /proc/*/fd/* for a symlink pointing to socket:[inode].
///
/// Uses `uid` from /proc/net to skip processes owned by a different user,
/// cutting the scan from O(all_processes × fds) to O(user_processes × fds).
/// Falls back to a full scan if the UID-filtered pass finds nothing
/// (edge case: socket passed between processes or setuid binaries).
fn find_pid_for_inode(inode: u64, uid: u32) -> Option<u32> {
    let target = format!("socket:[{inode}]");

    // First pass: only look at processes matching the socket's UID.
    if let Some(pid) = scan_proc_for_inode(&target, Some(uid)) {
        return Some(pid);
    }
    // Second pass: full scan — catches setuid, capability-elevated, or socket-passed processes.
    scan_proc_for_inode(&target, None)
}

fn scan_proc_for_inode(target: &str, only_uid: Option<u32>) -> Option<u32> {
    let proc = fs::read_dir("/proc").ok()?;

    for entry in proc.flatten() {
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else { continue };

        // UID filter: read /proc/<pid>/status and skip wrong-owner processes.
        if let Some(uid) = only_uid {
            if !process_uid_matches(pid, uid) {
                continue;
            }
        }

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

/// Check whether /proc/<pid>/status reports the given UID (Uid field, real uid).
fn process_uid_matches(pid: u32, uid: u32) -> bool {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else { return false };
    for line in status.lines() {
        if let Some(val) = line.strip_prefix("Uid:\t") {
            // Uid line: "real  effective  saved  filesystem"
            if let Some(real) = val.split_whitespace().next() {
                return real.parse::<u32>().ok() == Some(uid);
            }
        }
    }
    false
}

/// Read /proc/<pid>/comm (process name, truncated to 15 chars by the kernel).
fn read_comm(pid: u32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(comm.trim().to_string())
}

/// Read the basename of /proc/<pid>/exe (full path, not truncated).
fn read_exe_basename(pid: u32) -> Option<String> {
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let name = exe.file_name()?.to_string_lossy().to_string();
    Some(name.trim_end_matches(" (deleted)").to_string())
}

/// Read the parent PID from /proc/<pid>/status.
fn read_ppid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(val) = line.strip_prefix("PPid:\t") {
            return val.trim().parse().ok();
        }
    }
    None
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

    // UDP sample: socket bound to 0.0.0.0 (wildcard)
    const UDP_WILDCARD_SAMPLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:D431 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 55555 1 0 100 0";

    #[test]
    fn parses_ipv4_local_address() {
        let ip: IpAddr = "10.0.2.15".parse().unwrap();
        let result = parse_proc_net(TCP_SAMPLE, ip, 8080);
        assert_eq!(result, Some((99001, 1000)));
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
        let ip: IpAddr = "::1".parse().unwrap();
        let result = parse_proc_net(TCP6_SAMPLE, ip, 8080);
        assert_eq!(result, Some((99002, 1000)));
    }

    #[test]
    fn parse_ipv4_hex_roundtrip() {
        let addr = parse_ipv4_hex("0F02000A").unwrap();
        assert_eq!(addr, Ipv4Addr::new(10, 0, 2, 15));
    }

    #[test]
    fn parse_ipv6_hex_loopback() {
        let addr = parse_ipv6_hex("00000000000000000000000001000000").unwrap();
        assert_eq!(addr, Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn port_only_match_finds_wildcard_udp_socket() {
        // 0xD431 = 54321
        let result = parse_proc_net_port_only(UDP_WILDCARD_SAMPLE, 54321);
        assert_eq!(result, Some((55555, 1000)));
    }

    #[test]
    fn port_only_returns_none_for_wrong_port() {
        assert_eq!(parse_proc_net_port_only(UDP_WILDCARD_SAMPLE, 9999), None);
    }

    #[test]
    fn exact_match_misses_wildcard_udp_but_port_only_finds_it() {
        // Exact IP match fails (packet has real IP, socket is 0.0.0.0).
        let real_ip: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(parse_proc_net(UDP_WILDCARD_SAMPLE, real_ip, 54321), None);
        // Port-only fallback succeeds.
        assert_eq!(parse_proc_net_port_only(UDP_WILDCARD_SAMPLE, 54321), Some((55555, 1000)));
    }
}
