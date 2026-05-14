use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use core_types::TransportProtocol;

use crate::ProcessResolver;

/// Real ProcessResolver: (src_ip, src_port, protocol) → process name.
///
/// Lookup pipeline:
///   1. Per-socket cache hit — successful resolutions are cached for a short
///      TTL so retransmits / follow-up segments of the same connection do not
///      re-race `/proc/net/tcp`.
///   2. Read /proc/net/{tcp,tcp6,udp,udp6} — exact (ip, port) match → inode + uid
///   3. UDP fallback: port-only match for wildcard-bound sockets (0.0.0.0:port)
///   4. Retry with short delays — socket may not be in /proc/net yet (TOCTOU)
///   5. UID-filtered /proc/*/fd/ scan — skip processes owned by wrong UID (fast path)
///   6. Prefer exe basename over comm (comm is truncated to 15 chars by the kernel)
///   7. Parent process exe basename — handles Electron/subprocess models where the
///      network child has a short or generic name
pub struct ProcProcessResolver {
    /// (src_ip, src_port, protocol) → (name, inserted_at). Avoids re-reading
    /// /proc/net on every retransmit of the same socket, which otherwise
    /// re-triggers the TOCTOU race and yields inconsistent process names
    /// across packets of the same logical connection.
    cache: Mutex<HashMap<SocketKey, CachedName>>,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct SocketKey {
    ip: IpAddr,
    port: u16,
    protocol: TransportProtocol,
}

#[derive(Clone)]
struct CachedName {
    name: String,
    inserted_at: Instant,
}

/// How long a resolved `(src_ip, src_port, protocol) → name` mapping stays
/// in the cache. Long enough to cover typical TCP connection lifetimes and
/// HTTP keep-alive idle periods, short enough that an OS port reuse for a
/// different process gets a fresh lookup.
const CACHE_TTL: Duration = Duration::from_secs(60);
/// Cap on cache size. When exceeded we evict expired entries on the next
/// insert; the cap is a defense against pathological resolver-failure storms.
const CACHE_MAX: usize = 4096;

impl ProcProcessResolver {
    pub fn new() -> Self {
        Self { cache: Mutex::new(HashMap::new()) }
    }
}

impl Default for ProcProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessResolver for ProcProcessResolver {
    fn resolve(&self, src_ip: &str, src_port: u16, protocol: TransportProtocol) -> Option<String> {
        let ip: IpAddr = src_ip.parse().ok()?;
        let key = SocketKey { ip, port: src_port, protocol };

        // Cache fast path — a successful resolution within the TTL is reused
        // verbatim. This is what stops a retransmit whose /proc/net entry
        // briefly vanished (or hasn't been written this poll) from yielding
        // process_name=None when we already learned it a moment ago.
        let now = Instant::now();
        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.get(&key) {
                if now.duration_since(entry.inserted_at) < CACHE_TTL {
                    return Some(entry.name.clone());
                }
            }
        }

        // Retry loop: TOCTOU — the socket entry may lag behind the packet by a few ms.
        let (inode, uid) = retry_find_socket(ip, src_port, protocol)?;

        let pid = find_pid_for_inode(inode, uid)?;

        let name = read_exe_basename(pid).or_else(|| read_comm(pid))?;

        // Walk to parent only for single-character names or known generic shell
        // wrappers. Length <= 3 was too broad: `ssh`, `git`, `bun` all have
        // 3 chars and should NOT be replaced by their parent (the terminal).
        let name = if name.len() <= 1 || matches!(name.as_str(), "sh" | "bash" | "dash" | "zsh" | "fish") {
            read_ppid(pid).and_then(read_exe_basename).unwrap_or(name)
        } else {
            name
        };

        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() >= CACHE_MAX {
                cache.retain(|_, v| now.duration_since(v.inserted_at) < CACHE_TTL);
            }
            cache.insert(key, CachedName { name: name.clone(), inserted_at: now });
        }

        Some(name)
    }
}

/// Try to find the socket (inode, uid) with up to 4 attempts and increasing delays.
///
/// Only the first SYN of each new connection reaches NFQUEUE (subsequent packets
/// are fast-pathed by `ct state established,related accept`), so blocking the
/// NFQUEUE thread here is acceptable — 60 ms worst-case latency on one new
/// connection is far better than showing "unknown" in the dialog.
/// Delays chosen to cover:
///   - 0 ms  : socket already in /proc/net (most apps)
///   - 5 ms  : slight kernel lag (typical for busy desktops)
///   - 15 ms : slower app startup (Electron, .NET, throne relay)
///   - 40 ms : worst-case race (JVM, sandbox wrappers)
fn retry_find_socket(ip: IpAddr, port: u16, protocol: TransportProtocol) -> Option<(u64, u32)> {
    const DELAYS_MS: [u64; 4] = [0, 5, 15, 40];
    for (attempt, &delay) in DELAYS_MS.iter().enumerate() {
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
        if let Some(result) = find_socket_inode(ip, port, protocol) {
            if attempt > 0 {
                eprintln!("proc_resolver: found socket after {} retries (delay={}ms)", attempt, delay);
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
///
/// Both the IPv4 and the IPv6 tables are checked for any source IP because
/// modern applications frequently use `AF_INET6` sockets with `IPV6_V6ONLY=0`.
/// When such a socket connects to an IPv4 address the kernel records the entry
/// in `/proc/net/tcp6` as `::ffff:a.b.c.d`, so an IPv4-only or IPv6-only
/// lookup would miss it.
fn find_socket_inode(src_ip: IpAddr, src_port: u16, protocol: TransportProtocol) -> Option<(u64, u32)> {
    let is_udp = matches!(protocol, TransportProtocol::Udp | TransportProtocol::Quic);

    // Always check both address families: many applications use AF_INET6
    // sockets even for IPv4 destinations (::ffff: mapped form in tcp6/udp6).
    let files: &[&str] = if is_udp {
        match src_ip {
            IpAddr::V4(_) => &["/proc/net/udp", "/proc/net/udp6"],
            IpAddr::V6(_) => &["/proc/net/udp6", "/proc/net/udp"],
        }
    } else {
        match src_ip {
            IpAddr::V4(_) => &["/proc/net/tcp", "/proc/net/tcp6"],
            IpAddr::V6(_) => &["/proc/net/tcp6", "/proc/net/tcp"],
        }
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
        // Normalize the hex address to an IpAddr. A 32-char value comes from
        // a tcp6/udp6 entry; `to_ipv4_mapped()` collapses `::ffff:a.b.c.d`
        // back to an Ipv4Addr so cross-file lookups work (e.g. IPv4 src_ip
        // found in /proc/net/tcp6 as an IPv4-mapped address).
        let parsed_addr = parse_hex_addr(addr_hex);
        let matches = match (src_ip, parsed_addr) {
            (IpAddr::V4(a), Some(IpAddr::V4(b))) => a == b,
            (IpAddr::V6(a), Some(IpAddr::V6(b))) => a == b,
            // IPv6 src matched against an IPv4-mapped entry in tcp6 (or vice-versa).
            (IpAddr::V6(a), Some(IpAddr::V4(b))) => a.to_ipv4_mapped() == Some(b),
            (IpAddr::V4(a), Some(IpAddr::V6(b))) => b.to_ipv4_mapped() == Some(a),
            _ => false,
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

/// Decode a /proc/net hex address — either 8-char IPv4 or 32-char IPv6 —
/// and normalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to `IpAddr::V4`.
fn parse_hex_addr(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8  => parse_ipv4_hex(hex).map(IpAddr::V4),
        32 => parse_ipv6_hex(hex).map(|v6| {
            v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
        }),
        _ => None,
    }
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
///
/// A short retry loop covers multi-process applications (e.g. Electron) where
/// the network-service subprocess can have a brief window after fork/exec during
/// which its file descriptors are not yet visible under /proc/<pid>/fd/.
fn find_pid_for_inode(inode: u64, uid: u32) -> Option<u32> {
    let target = format!("socket:[{inode}]");

    // Retry delays: 0 ms covers the common case (fd already visible);
    // 3 ms and 8 ms cover the fork/exec visibility gap in multi-process apps
    // like Electron where the network-service subprocess can briefly not have
    // its file descriptors visible under /proc/<pid>/fd/.
    const DELAYS_MS: [u64; 3] = [0, 3, 8];
    for &delay in &DELAYS_MS {
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
        // UID-filtered pass first (fast path).
        if let Some(pid) = scan_proc_for_inode(&target, Some(uid)) {
            return Some(pid);
        }
        // Full scan — catches setuid, capability-elevated, or socket-passed processes.
        if let Some(pid) = scan_proc_for_inode(&target, None) {
            return Some(pid);
        }
    }
    None
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
    fn cache_hit_returns_name_without_touching_proc() {
        // Pre-populate the cache; if resolve() reads /proc/net, it would
        // fail (no real socket on this port). A correct cache short-circuit
        // returns the cached name regardless.
        let resolver = ProcProcessResolver::new();
        let key = SocketKey {
            ip: "10.20.30.40".parse().unwrap(),
            port: 65000,
            protocol: TransportProtocol::Tcp,
        };
        resolver.cache.lock().unwrap().insert(
            key,
            CachedName { name: "curl".to_string(), inserted_at: Instant::now() },
        );
        assert_eq!(
            resolver.resolve("10.20.30.40", 65000, TransportProtocol::Tcp).as_deref(),
            Some("curl"),
        );
    }

    #[test]
    fn cache_misses_for_different_port_or_protocol() {
        let resolver = ProcProcessResolver::new();
        let key = SocketKey {
            ip: "10.20.30.40".parse().unwrap(),
            port: 65000,
            protocol: TransportProtocol::Tcp,
        };
        resolver.cache.lock().unwrap().insert(
            key,
            CachedName { name: "curl".to_string(), inserted_at: Instant::now() },
        );
        // Different port → no hit (returns None because /proc has no entry).
        assert_eq!(
            resolver.resolve("10.20.30.40", 65001, TransportProtocol::Tcp),
            None,
        );
        // Different protocol → no hit.
        assert_eq!(
            resolver.resolve("10.20.30.40", 65000, TransportProtocol::Udp),
            None,
        );
    }

    #[test]
    fn cache_entry_expires_after_ttl() {
        let resolver = ProcProcessResolver::new();
        let key = SocketKey {
            ip: "10.20.30.40".parse().unwrap(),
            port: 65000,
            protocol: TransportProtocol::Tcp,
        };
        let stale = Instant::now()
            .checked_sub(CACHE_TTL + Duration::from_secs(1))
            .expect("clock is too young for this test");
        resolver
            .cache
            .lock()
            .unwrap()
            .insert(key, CachedName { name: "curl".to_string(), inserted_at: stale });
        // Stale entry must not be served; fallback to /proc fails → None.
        assert_eq!(
            resolver.resolve("10.20.30.40", 65000, TransportProtocol::Tcp),
            None,
        );
    }

    #[test]
    fn ipv4_address_matches_ipv4_mapped_entry_in_tcp6() {
        // An AF_INET6 socket connecting to an IPv4 address appears in
        // /proc/net/tcp6 as ::ffff:a.b.c.d (32-char hex, IPv4-mapped).
        // 10.0.2.15 in IPv4-mapped form = 0000…0000ffff0f02000a
        // Little-endian words: 00000000 00000000 0000ffff 0f02000a
        let tcp6_ipv4_mapped = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000F02000A:1F90 00000000000000000000000000000000:0000 01 00000000:00000000 00:00000000 00000000  2000        0 77777 1 0 100 0";
        let ipv4: IpAddr = "10.0.2.15".parse().unwrap();
        let result = parse_proc_net(tcp6_ipv4_mapped, ipv4, 8080);
        assert_eq!(result, Some((77777, 2000)));
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
