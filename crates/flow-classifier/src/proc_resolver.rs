use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use core_types::TransportProtocol;
use metrics::{counter, histogram};

use crate::sock_diag;
use crate::{ProcessInfo, ProcessResolver, SocketTracker};

/// Real ProcessResolver: (src_ip, src_port, protocol) → ProcessInfo.
///
/// Lookup pipeline:
///   0. eBPF socket tracker → PID + UID (instant, no /proc race at all).
///   1. Per-socket cache hit — successful resolutions are cached for 60 s.
///   2. SOCK_DIAG netlink → inode + uid (kernel socket table, no /proc race).
///   3. /proc/net/{tcp,tcp6,udp,udp6} → inode + uid (with retry delays).
///   4. /proc/*/fd/ scan → pid (UID-filtered first pass, full fallback).
///   5. `ss` fallback if inode lookup or fd scan fails.
///   6. /proc/<pid>/exe → full path + basename name.
///   7. Name fixup: shell wrappers → parent, electron/AppRun → cmdline/env.
///   8. `pacman -Qo <exe>` → app_name (Arch Linux, cached per exe path).
pub struct ProcProcessResolver {
    /// Per-socket ProcessInfo cache keyed by (src_ip, src_port, protocol).
    cache: Mutex<HashMap<SocketKey, CachedEntry>>,
    /// Pacman owner cache keyed by exe path. Stores `None` for paths not
    /// owned by any package to avoid repeated subprocess invocations.
    pacman_cache: Mutex<HashMap<String, Option<String>>>,
    /// Optional eBPF socket tracker for instant PID resolution.
    /// When available, checked before SOCK_DIAG — eliminates TOCTOU races.
    sock_tracker: Option<Arc<dyn SocketTracker>>,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct SocketKey {
    ip: IpAddr,
    port: u16,
    protocol: TransportProtocol,
}

#[derive(Clone)]
struct CachedEntry {
    name: String,
    exe: Option<String>,
    app_name: Option<String>,
    /// PID the entry was resolved for. Used to detect port reuse: when the
    /// eBPF tracker reports a different PID than the cached entry's, the
    /// entry is stale (the kernel recycled the ephemeral port to another
    /// process) and must not be served.
    pid: Option<u32>,
    inserted_at: Instant,
}

/// How long a resolved `(src_ip, src_port, protocol)` mapping stays in cache.
const CACHE_TTL: Duration = Duration::from_secs(60);
/// Cap on socket cache size.
const CACHE_MAX: usize = 4096;
/// Cap on pacman cache size (one entry per unique binary on the system).
const PACMAN_CACHE_MAX: usize = 1024;

impl ProcProcessResolver {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            pacman_cache: Mutex::new(HashMap::new()),
            sock_tracker: None,
        }
    }

    /// Create a resolver with an eBPF socket tracker for instant PID lookup.
    pub fn with_sock_tracker(tracker: Arc<dyn SocketTracker>) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            pacman_cache: Mutex::new(HashMap::new()),
            sock_tracker: Some(tracker),
        }
    }

    /// Find the PID that owns the socket:
    ///   0. eBPF socket tracker (instant, no /proc race at all).
    ///   1. SOCK_DIAG netlink (kernel socket table, no /proc race).
    ///   2. /proc/net + /proc/*/fd scan with retries.
    ///   3. `ss` command fallback if both paths miss the inode or fd scan.
    fn find_pid(&self, ip: IpAddr, port: u16, protocol: TransportProtocol) -> Option<u32> {
        // Step 0: eBPF socket tracker — instant PID lookup from BPF map.
        // The eBPF program captures the PID at socket creation time (TCP SYN_SENT)
        // or at send time (udp_sendmsg), BEFORE the packet reaches NFQUEUE.
        // This eliminates all TOCTOU races.
        if let Some(ref tracker) = self.sock_tracker {
            if let Some(tracked) = tracker.lookup_pid(ip, port, protocol) {
                counter!("logiguard.proc.resolver.ebpf.hits").increment(1);
                eprintln!("proc: key={ip}:{port} pid={} source=ebpf", tracked.pid);
                return Some(tracked.pid);
            }
            counter!("logiguard.proc.resolver.ebpf.misses").increment(1);
        }

        let inode_uid = sock_diag::query_socket_inode(ip, port, protocol)
            .or_else(|| retry_find_socket(ip, port, protocol));
        if let Some((inode, uid)) = inode_uid {
            if let Some(pid) = find_pid_for_inode(inode, uid) {
                eprintln!("proc: key={ip}:{port} pid={pid} inode={inode} source=sockdiag+procfds");
                return Some(pid);
            }
            eprintln!(
                "proc: key={ip}:{port} inode={inode} uid={uid} found but no /proc/*/fd owner \
                 (fork/exec gap?) — trying ss fallback"
            );
            // Inode found but /proc/*/fd scan came up empty (fork/exec gap).
        } else {
            eprintln!("proc: key={ip}:{port} no inode via sock-diag — trying ss fallback");
        }
        let ss_pid = try_ss_fallback(ip, port, protocol);
        if ss_pid.is_none() {
            eprintln!("proc: key={ip}:{port} UNRESOLVED — all sources missed");
        }
        ss_pid
    }

    /// Look up the Arch Linux package that owns `exe_path` via `pacman -Qo`.
    /// Result is cached — including `None` for unowned paths.
    fn lookup_pacman(&self, exe_path: &str) -> Option<String> {
        if let Ok(c) = self.pacman_cache.lock() {
            if let Some(cached) = c.get(exe_path) {
                return cached.clone();
            }
        }
        let result = pacman_query_owner(exe_path);
        if let Ok(mut c) = self.pacman_cache.lock() {
            if c.len() >= PACMAN_CACHE_MAX {
                c.clear();
            }
            c.insert(exe_path.to_string(), result.clone());
        }
        result
    }
}

impl Default for ProcProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessResolver for ProcProcessResolver {
    fn resolve(
        &self,
        src_ip: &str,
        src_port: u16,
        protocol: TransportProtocol,
    ) -> Option<ProcessInfo> {
        let resolve_start = Instant::now();
        let ip: IpAddr = src_ip.parse().ok()?;
        let key = SocketKey {
            ip,
            port: src_port,
            protocol,
        };
        let now = Instant::now();

        // eBPF tracker first (when available): it is authoritative — it
        // captured the PID at socket-creation time. Consulting the cache
        // before it would hide port reuse (kernel recycling an ephemeral
        // port to a different process within the cache TTL).
        let tracked_pid = if let Some(ref tracker) = self.sock_tracker {
            tracker.lookup_pid(ip, src_port, protocol)
        } else {
            None
        };

        // Cache fast path. When the tracker reported a PID, the cached entry
        // is only valid if it was resolved for that same PID.
        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.get(&key) {
                let pid_matches = match (tracked_pid.clone(), entry.pid) {
                    (Some(tracked), Some(cached)) => tracked.pid == cached,
                    // No tracker (or tracker has no entry for this socket):
                    // fall back to the old TTL-only behaviour.
                    _ => true,
                };
                if pid_matches && now.duration_since(entry.inserted_at) < CACHE_TTL {
                    counter!("logiguard.proc.resolver.cache.hits").increment(1);
                    histogram!("logiguard.proc.resolver.resolve.duration")
                        .record(resolve_start.elapsed().as_secs_f64());
                    return Some(ProcessInfo {
                        name: entry.name.clone(),
                        exe: entry.exe.clone(),
                        app_name: entry.app_name.clone(),
                    });
                }
                counter!("logiguard.proc.resolver.cache.stale_pid").increment(1);
            }
        }

        counter!("logiguard.proc.resolver.cache.misses").increment(1);

        let pid = match tracked_pid {
            Some(ref tracked) => {
                counter!("logiguard.proc.resolver.ebpf.hits").increment(1);
                tracked.pid
            }
            None => self.find_pid(ip, src_port, protocol)?,
        };

        // Read exe: full path first, fall back to comm.
        let exe_path = read_exe_path(pid);
        let raw_name = exe_path
            .as_deref()
            .and_then(|p| std::path::Path::new(p).file_name())
            .map(|n| n.to_string_lossy().to_string())
            .or_else(|| read_comm(pid))?;

        // Name fixup: shell wrappers → parent, electron → cmdline / env.
        let name = if raw_name.len() <= 1
            || matches!(raw_name.as_str(), "sh" | "bash" | "dash" | "zsh" | "fish")
        {
            read_ppid(pid)
                .and_then(read_exe_basename)
                .unwrap_or(raw_name)
        } else if matches!(raw_name.as_str(), "electron" | "AppRun") {
            // Resolution order for generic Electron/AppImage names:
            //   1. Own cmdline — path before "resources/" gives the app dir name.
            //   2. Parent cmdline — utility subprocesses inherit parent's app path.
            //   3. APPIMAGE env var — set by AppImage runtime for all child procs.
            //   4. Parent exe basename — last resort, filtered for generic names.
            app_name_from_electron_cmdline(pid)
                .or_else(|| read_ppid(pid).and_then(app_name_from_electron_cmdline))
                .or_else(|| app_name_from_environ(pid))
                .or_else(|| {
                    read_ppid(pid).and_then(read_exe_basename).filter(|n| {
                        !matches!(
                            n.as_str(),
                            "electron" | "AppRun" | "sh" | "bash" | "dash" | "zsh" | "fish"
                        )
                    })
                })
                .unwrap_or(raw_name)
        } else {
            raw_name
        };

        // Pacman lookup (Arch Linux only; graceful no-op otherwise).
        let app_name = exe_path.as_deref().and_then(|p| self.lookup_pacman(p));
        // Suppress app_name when it equals name — no value in duplicating it.
        let app_name = app_name.filter(|a| a != &name);

        let info = ProcessInfo {
            name,
            exe: exe_path,
            app_name,
        };

        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() >= CACHE_MAX {
                cache.retain(|_, v| now.duration_since(v.inserted_at) < CACHE_TTL);
            }
            cache.insert(
                key,
                CachedEntry {
                    name: info.name.clone(),
                    exe: info.exe.clone(),
                    app_name: info.app_name.clone(),
                    pid: Some(pid),
                    inserted_at: now,
                },
            );
        }

        histogram!("logiguard.proc.resolver.resolve.duration")
            .record(resolve_start.elapsed().as_secs_f64());
        Some(info)
    }
}

// ---------------------------------------------------------------------------
// `ss` fallback (SOCK_DIAG via iproute2)
// ---------------------------------------------------------------------------

/// Try `ss -Hnp -{t|u} src :<port>` to find the pid owning the socket.
///
/// `ss` uses the kernel's SOCK_DIAG netlink interface internally, which can
/// produce results in cases where reading `/proc/net/tcp` races.  This is a
/// last-resort call only made after all `/proc/net` retries have failed, so
/// its ~1 ms subprocess latency is acceptable.  Returns `None` immediately if
/// `ss` is not installed or reports an error.
fn try_ss_fallback(ip: IpAddr, port: u16, protocol: TransportProtocol) -> Option<u32> {
    let proto_flag = if matches!(protocol, TransportProtocol::Udp | TransportProtocol::Quic) {
        "-u"
    } else {
        "-t"
    };
    let output = std::process::Command::new("ss")
        .args(["-Hnp", proto_flag, &format!("src :{port}")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // ss -H columns: State Recv-Q Send-Q Local Peer [Process]
        if fields.len() < 6 {
            continue;
        }
        if !ss_local_matches(fields[3], ip, port) {
            continue;
        }
        if let Some(pid) = extract_pid_from_ss_line(line) {
            return Some(pid);
        }
    }
    None
}

/// Return true if `addr` (as printed by `ss`) matches the given IP and port.
/// Handles IPv4 (`1.2.3.4:port`), IPv6 (`[::1]:port`), and IPv4-mapped forms.
fn ss_local_matches(addr: &str, ip: IpAddr, port: u16) -> bool {
    let Some(colon) = addr.rfind(':') else {
        return false;
    };
    let port_str = port.to_string();
    if addr[colon + 1..] != port_str {
        return false;
    }
    let addr_part = addr[..colon].trim_matches('[').trim_matches(']');
    match (ip, addr_part.parse::<IpAddr>().ok()) {
        (IpAddr::V4(a), Some(IpAddr::V4(b))) => a == b,
        (IpAddr::V6(a), Some(IpAddr::V6(b))) => a == b,
        (IpAddr::V4(a), Some(IpAddr::V6(b))) => b.to_ipv4_mapped() == Some(a),
        (IpAddr::V6(a), Some(IpAddr::V4(b))) => a.to_ipv4_mapped() == Some(b),
        _ => addr_part == ip.to_string(),
    }
}

/// Extract `pid=N` from an `ss -p` users field like `users:(("curl",pid=1234,fd=3))`.
fn extract_pid_from_ss_line(line: &str) -> Option<u32> {
    let start = line.find("pid=")? + 4;
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

// ---------------------------------------------------------------------------
// Pacman lookup (Arch Linux)
// ---------------------------------------------------------------------------

/// Ask pacman which package owns `exe_path`.
/// Returns `None` if pacman is not available, the path is unowned, or the
/// command fails for any reason.
fn pacman_query_owner(exe_path: &str) -> Option<String> {
    let output = std::process::Command::new("pacman")
        .args(["-Qo", "--", exe_path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    // e.g. "/usr/bin/curl is owned by curl 8.7.1-1\n"
    let s = String::from_utf8_lossy(&output.stdout);
    let after_by = s.split(" owned by ").nth(1)?;
    Some(after_by.split_whitespace().next()?.to_string())
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
                eprintln!(
                    "proc_resolver: found socket after {} retries (delay={}ms)",
                    attempt, delay
                );
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
fn find_socket_inode(
    src_ip: IpAddr,
    src_port: u16,
    protocol: TransportProtocol,
) -> Option<(u64, u32)> {
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
        let Some(colon) = local.rfind(':') else {
            continue;
        };
        if local[colon + 1..] != port_hex {
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
            // inode=0 means a TIME_WAIT or kernel-internal socket — no process
            // owns it, so find_pid_for_inode would always fail. Skip it so we
            // continue searching for the real socket entry.
            if inode == 0 {
                continue;
            }
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
        let Some(colon) = local.rfind(':') else {
            continue;
        };
        if local[colon + 1..] != port_hex {
            continue;
        }
        let inode: u64 = cols[9].parse().ok()?;
        if inode == 0 {
            continue;
        }
        let uid: u32 = cols[7].parse().unwrap_or(u32::MAX);
        return Some((inode, uid));
    }
    None
}

/// Decode a /proc/net hex address — either 8-char IPv4 or 32-char IPv6 —
/// and normalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to `IpAddr::V4`.
fn parse_hex_addr(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => parse_ipv4_hex(hex).map(IpAddr::V4),
        32 => parse_ipv6_hex(hex).map(|v6| {
            v6.to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6))
        }),
        _ => None,
    }
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
    // 3/8/20 ms cover the fork/exec visibility gap in multi-process apps
    // like Electron/Cursor where the network-service subprocess can briefly
    // not have its file descriptors visible under /proc/<pid>/fd/.
    // 20 ms is the extra slot for heavier runtimes (e.g. Cursor AppImage).
    const DELAYS_MS: [u64; 4] = [0, 3, 8, 20];
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
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        // UID filter: read /proc/<pid>/status and skip wrong-owner processes.
        if let Some(uid) = only_uid {
            if !process_uid_matches(pid, uid) {
                continue;
            }
        }

        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

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
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
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

/// Extract a user-visible app name from a process's environment.
///
/// Checks two env vars in order:
/// - `APPIMAGE=/path/to/Cursor-0.45.5.AppImage` — set by the AppImage runtime
///   for every process in the tree (including utility subprocesses). File stem
///   is lowercased; a trailing `-<version>` suffix (first component starting
///   with a digit) is stripped so "Cursor-0.45.5" → "cursor".
/// - `ELECTRON_APP_NAME=cursor` — some Electron apps set this explicitly.
///
/// Returns `None` if neither var is present or the extracted name is too short
/// to be meaningful (≤ 2 chars).
pub(crate) fn parse_environ_for_app_name(environ: &str) -> Option<String> {
    for var in environ.split('\0') {
        if let Some(val) = var.strip_prefix("APPIMAGE=") {
            let stem = std::path::Path::new(val)
                .file_stem()?
                .to_string_lossy()
                .to_lowercase();
            // Strip trailing version: "cursor-0.45.5" → "cursor"
            let name: String = stem
                .split('-')
                .take_while(|part| !part.starts_with(|c: char| c.is_ascii_digit()))
                .collect::<Vec<_>>()
                .join("-");
            let name = if name.is_empty() { stem } else { name };
            if name.len() > 2 {
                return Some(name.to_string());
            }
        }
        if let Some(val) = var.strip_prefix("ELECTRON_APP_NAME=") {
            if val.len() > 2 {
                return Some(val.to_lowercase());
            }
        }
    }
    None
}

fn app_name_from_environ(pid: u32) -> Option<String> {
    let environ = fs::read_to_string(format!("/proc/{pid}/environ")).ok()?;
    parse_environ_for_app_name(&environ)
}

/// Extract an app name from an Electron process's command-line arguments.
///
/// Electron apps (including Cursor, VSCode, and others packaged as system
/// Arch/Debian packages with a shared `electronN` binary) are launched as:
///
///   /usr/lib/electron42/electron /usr/share/<app>/resources/app/<entry>.mjs
///
/// The directory component immediately before `"resources"` is the canonical
/// app name. Returns `None` when the process is a subprocess (its cmdline
/// starts directly with flags like `--type=utility`) — in that case the
/// caller should try the parent process's cmdline instead.
pub(crate) fn parse_cmdline_for_app_name(cmdline: &str) -> Option<String> {
    // Args are NUL-separated. Skip arg[0] (the electron binary path).
    let app_arg = cmdline
        .split('\0')
        .skip(1)
        .find(|a| !a.is_empty() && !a.starts_with('-'))?;

    let path = std::path::Path::new(app_arg);
    let components: Vec<_> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
        .collect();

    let resources_idx = components.iter().position(|c| c == "resources")?;
    if resources_idx == 0 {
        return None;
    }
    let app_dir = &components[resources_idx - 1];
    if app_dir.len() > 2 {
        Some(app_dir.to_string())
    } else {
        None
    }
}

fn app_name_from_electron_cmdline(pid: u32) -> Option<String> {
    let cmdline = fs::read_to_string(format!("/proc/{pid}/cmdline")).ok()?;
    parse_cmdline_for_app_name(&cmdline)
}

/// Read /proc/<pid>/comm (process name, truncated to 15 chars by the kernel).
fn read_comm(pid: u32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(comm.trim().to_string())
}

/// Read the full path of /proc/<pid>/exe.
fn read_exe_path(pid: u32) -> Option<String> {
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(
        exe.to_string_lossy()
            .trim_end_matches(" (deleted)")
            .to_string(),
    )
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
            CachedEntry {
                pid: None,
                name: "curl".to_string(),
                exe: None,
                app_name: None,
                inserted_at: Instant::now(),
            },
        );
        assert_eq!(
            resolver
                .resolve("10.20.30.40", 65000, TransportProtocol::Tcp)
                .map(|p| p.name)
                .as_deref(),
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
            CachedEntry {
                name: "curl".to_string(),
                pid: None,
                exe: None,
                app_name: None,
                inserted_at: Instant::now(),
            },
        );
        // Different port → no hit (returns None because /proc has no entry).
        assert!(resolver
            .resolve("10.20.30.40", 65001, TransportProtocol::Tcp)
            .is_none());
        // Different protocol → no hit.
        assert!(resolver
            .resolve("10.20.30.40", 65000, TransportProtocol::Udp)
            .is_none());
    }

    /// Fake tracker simulating eBPF map contents: the caller mutates the
    /// reported PID between lookups to simulate port reuse by another process.
    struct PortReuseTracker {
        pid: std::sync::atomic::AtomicU32,
    }

    impl crate::SocketTracker for PortReuseTracker {
        fn lookup_pid(
            &self,
            _src_ip: IpAddr,
            _src_port: u16,
            _protocol: TransportProtocol,
        ) -> Option<crate::TrackedProcess> {
            Some(crate::TrackedProcess {
                pid: self.pid.load(std::sync::atomic::Ordering::SeqCst),
                uid: 0,
            })
        }
    }

    /// Reproduces the misattribution bug: the kernel recycles an ephemeral
    /// port across processes (old socket closed → new socket from another
    /// process binds the same port). The eBPF map correctly reports the NEW
    /// pid, but the userspace cache still holds the OLD process's name and is
    /// consulted first — so a YouTube request from chromium gets attributed
    /// to whatever process owned the port 60 s ago.
    #[test]
    fn port_reuse_does_not_serve_stale_cached_process() {
        use std::process::{Command, Stdio};

        // Two long-lived children with distinct exe basenames.
        let mut first = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let mut second = Command::new("tail")
            .args(["-f", "/dev/null"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn tail");

        let tracker = PortReuseTracker {
            pid: std::sync::atomic::AtomicU32::new(first.id()),
        };
        let tracker: Arc<PortReuseTracker> = Arc::new(tracker);
        let resolver = ProcProcessResolver::with_sock_tracker(
            Arc::clone(&tracker) as Arc<dyn crate::SocketTracker>
        );

        let ip = "10.20.30.40";
        let first_name = resolver
            .resolve(ip, 54321, TransportProtocol::Tcp)
            .map(|p| p.name);
        assert_eq!(first_name.as_deref(), Some("sleep"));

        // Same (ip, port, protocol): the eBPF map now points at `tail`.
        tracker
            .pid
            .store(second.id(), std::sync::atomic::Ordering::SeqCst);
        let second_name = resolver
            .resolve(ip, 54321, TransportProtocol::Tcp)
            .map(|p| p.name);
        assert_eq!(
            second_name.as_deref(),
            Some("tail"),
            "port reused by another process must not be served from the stale cache"
        );

        let _ = first.kill();
        let _ = second.kill();
        let _ = first.wait();
        let _ = second.wait();
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
        resolver.cache.lock().unwrap().insert(
            key,
            CachedEntry {
                name: "curl".to_string(),
                exe: None,
                pid: None,
                app_name: None,
                inserted_at: stale,
            },
        );
        // Stale entry must not be served; fallback to /proc fails → None.
        assert!(resolver
            .resolve("10.20.30.40", 65000, TransportProtocol::Tcp)
            .is_none());
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
        assert_eq!(
            parse_proc_net_port_only(UDP_WILDCARD_SAMPLE, 54321),
            Some((55555, 1000))
        );
    }

    // TIME_WAIT sockets have inode=0 in /proc/net/tcp. A matching (ip, port)
    // row with inode=0 must be skipped so the retry loop can find the real entry.
    const TCP_WITH_ZERO_INODE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0F02000A:1F90 01020304:0050 06 00000000:00000000 00:00000000 00000000  1000        0 0 1 0 100 0
   1: 0F02000A:1F90 05060708:0050 01 00000000:00000000 00:00000000 00000000  1000        0 99001 1 0 100 0";

    #[test]
    fn inode_zero_row_is_skipped_and_real_entry_returned() {
        let ip: IpAddr = "10.0.2.15".parse().unwrap();
        // Must skip the inode=0 TIME_WAIT row and return the real ESTABLISHED entry.
        assert_eq!(
            parse_proc_net(TCP_WITH_ZERO_INODE, ip, 8080),
            Some((99001, 1000))
        );
    }

    #[test]
    fn inode_zero_only_row_returns_none() {
        // Only a TIME_WAIT (inode=0) row exists — should return None so the
        // caller's retry loop tries again rather than returning a useless inode.
        const ONLY_ZERO: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0F02000A:1F90 01020304:0050 06 00000000:00000000 00:00000000 00000000  1000        0 0 1 0 100 0";
        let ip: IpAddr = "10.0.2.15".parse().unwrap();
        assert_eq!(parse_proc_net(ONLY_ZERO, ip, 8080), None);
    }

    #[test]
    fn parse_environ_extracts_appimage_cursor() {
        let environ = "HOME=/home/user\0APPIMAGE=/home/user/Cursor-0.45.5.AppImage\0TERM=xterm\0";
        assert_eq!(
            parse_environ_for_app_name(environ).as_deref(),
            Some("cursor")
        );
    }

    #[test]
    fn parse_environ_extracts_appimage_no_version_suffix() {
        let environ = "APPIMAGE=/opt/myapp.AppImage\0";
        assert_eq!(
            parse_environ_for_app_name(environ).as_deref(),
            Some("myapp")
        );
    }

    #[test]
    fn parse_environ_extracts_hyphenated_app_name() {
        let environ = "APPIMAGE=/downloads/my-editor-1.2.3.AppImage\0";
        assert_eq!(
            parse_environ_for_app_name(environ).as_deref(),
            Some("my-editor")
        );
    }

    #[test]
    fn parse_environ_uses_electron_app_name_var() {
        let environ = "ELECTRON_APP_NAME=cursor\0OTHER=val\0";
        assert_eq!(
            parse_environ_for_app_name(environ).as_deref(),
            Some("cursor")
        );
    }

    #[test]
    fn parse_environ_returns_none_when_no_relevant_vars() {
        let environ = "HOME=/home/user\0PATH=/usr/bin\0TERM=xterm\0";
        assert_eq!(parse_environ_for_app_name(environ), None);
    }

    #[test]
    fn parse_environ_rejects_short_names() {
        let environ = "APPIMAGE=/tmp/ok.AppImage\0";
        assert_eq!(parse_environ_for_app_name(environ), None);
    }

    // Cursor on Arch Linux: /usr/bin/cursor → /usr/share/cursor/cursor (script)
    // → exec /usr/lib/electron42/electron /usr/share/cursor/resources/app/cursor.mjs
    // The network subprocess inherits the same electron binary but has --type=utility
    // in its own cmdline. The parent (main process) has the real app path.
    #[test]
    fn parse_cmdline_cursor_main_process() {
        let cmdline = "/usr/lib/electron42/electron\0/usr/share/cursor/resources/app/cursor.mjs\0";
        assert_eq!(
            parse_cmdline_for_app_name(cmdline).as_deref(),
            Some("cursor")
        );
    }

    #[test]
    fn parse_cmdline_cursor_network_subprocess_returns_none() {
        // Subprocess cmdline has only flags — no app path. Caller must try parent.
        let cmdline = "/usr/lib/electron42/electron\0--type=utility\0--utility-sub-type=network.mojom.NetworkService\0";
        assert_eq!(parse_cmdline_for_app_name(cmdline), None);
    }

    #[test]
    fn parse_cmdline_vscode_arch_package() {
        // VSCode on Arch also uses a shared electron binary.
        let cmdline = "/usr/lib/electron32/electron\0/usr/share/code/resources/app/bootstrap/bootstrap-fork.js\0";
        assert_eq!(parse_cmdline_for_app_name(cmdline).as_deref(), Some("code"));
    }

    #[test]
    fn parse_cmdline_returns_none_when_no_resources_component() {
        // cmdline with an app path that doesn't follow the electron pattern.
        let cmdline = "/usr/bin/node\0/usr/share/myapp/index.js\0";
        assert_eq!(parse_cmdline_for_app_name(cmdline), None);
    }

    #[test]
    fn parse_cmdline_returns_none_for_bare_electron() {
        // electron called with no arguments — nothing to extract.
        let cmdline = "/usr/lib/electron42/electron\0";
        assert_eq!(parse_cmdline_for_app_name(cmdline), None);
    }
}
