//! eBPF-based socket tracker for near-instantaneous PID resolution.
//!
//! Hooks into the `tcp_connect` kprobe (TCP) and the `udp_sendmsg` /
//! `udp_lib_unhash` kprobes (UDP) to capture the PID at the exact moment a
//! connection is initiated or a packet is sent — before NFQUEUE delivers the
//! packet to userspace. This eliminates the TOCTOU race that plagues
//! `/proc/net` lookups and the fork/exec fd-visibility gap that causes
//! `find_pid_for_inode` to return `None`.
//!
//! TCP uses `tcp_connect` rather than the `inet_sock_set_state` tracepoint
//! because on kernels ≥ ~6.15 the SYN_SENT tracepoint fires BEFORE the
//! ephemeral port and source address are assigned, so its record carries
//! sport=0/saddr=0.0.0.0 for auto-bound sockets (verified on 6.18). The
//! kprobe reads the live `struct sock` after connect() has populated it.

use std::net::IpAddr;
use std::sync::Mutex;

use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData};
use aya::programs::KProbe;
use aya::Ebpf;

use core_types::TransportProtocol;
use flow_classifier::{
    SocketTracker as SocketTrackerTrait, TrackedProcess as FcTrackedProcess, TrackerSource,
};

/// Key: identifies a socket by source address + port + protocol.
/// IPv4 addresses are stored as IPv4-mapped IPv6 (::ffff:a.b.c.d).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct SockKey {
    /// Source IP as 16 bytes. IPv4 stored as ::ffff:a.b.c.d.
    pub src_ip: [u8; 16],
    /// Source port, host byte order.
    pub src_port: u16,
    /// IP protocol number: 6 = TCP, 17 = UDP.
    pub protocol: u8,
    pub _pad: u8,
}

// SAFETY: SockKey is a POD type — all bit patterns are valid, no padding issues.
unsafe impl aya::Pod for SockKey {}

/// Value: process info captured at socket creation/send time.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SockInfo {
    /// PID of the process that owns the socket.
    pub pid: u32,
    /// UID of the process that owns the socket.
    pub uid: u32,
    /// Timestamp (nanoseconds since boot) when the entry was created.
    pub timestamp_ns: u64,
    /// Process comm (exe basename, kernel-truncated to 16 bytes) captured at
    /// hook time — survives the exit race that empties /proc/<pid>/exe for
    /// short-lived processes. NUL-padded.
    pub comm: [u8; 16],
}

// SAFETY: SockInfo is a POD type — all bit patterns are valid.
unsafe impl aya::Pod for SockInfo {}

/// Result of a successful eBPF socket tracker lookup.
#[derive(Debug, Clone)]
pub struct TrackedProcess {
    pub pid: u32,
    pub uid: u32,
    /// Process comm captured at hook time, as a Rust string (empty when the
    /// BPF helper failed). The comm is the exe basename truncated to 15
    /// chars by the kernel — usable as the process name when /proc is gone.
    pub comm: String,
    /// Which map satisfied the lookup.
    pub source: TrackerSource,
}

impl TrackedProcess {
    fn from_info(info: &SockInfo) -> Self {
        let nul = info
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(info.comm.len());
        Self {
            pid: info.pid,
            uid: info.uid,
            comm: String::from_utf8_lossy(&info.comm[..nul]).into_owned(),
            source: TrackerSource::Unknown,
        }
    }
}

/// Manages the eBPF socket tracker: loads the BPF programs, attaches them,
/// and provides lookups into the socket events map.
pub struct SockTracker {
    /// The BPF object — must stay alive for the maps to remain accessible.
    _ebpf: Ebpf,
    /// Handle to the SOCK_EVENTS BPF map. Protected by Mutex for thread safety
    /// (NFQUEUE processor calls lookup_pid from its run loop thread).
    sock_map: Mutex<HashMap<MapData, SockKey, SockInfo>>,
    /// Fallback map keyed by (port, protocol) only — covers unconnected UDP
    /// sockets whose source address is unknown at udp_sendmsg time.
    port_map: Mutex<HashMap<MapData, PortKey, SockInfo>>,
}

impl SockTracker {
    /// Load and attach the eBPF socket tracker programs.
    ///
    /// Attaches:
    /// - `sock_tcp_connect` kprobe on `tcp_connect`
    /// - `sock_udp_sendmsg` kprobe on `udp_sendmsg`
    /// - `sock_udp_unhash` kprobe on `udp_lib_unhash`
    ///
    /// Requires root / `CAP_BPF` + `CAP_NET_ADMIN`.
    pub fn load() -> Result<Self> {
        let ebpf_bytes = include_bytes_aligned!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dns-tracker-ebpf/target/bpfel-unknown-none/release/sock-tracker-ebpf"
        ));

        let mut ebpf = Ebpf::load(ebpf_bytes).context("failed to load sock-tracker BPF object")?;

        // Attach kprobe: tcp_connect
        let kp_tcp: &mut KProbe = ebpf
            .program_mut("sock_tcp_connect")
            .context("BPF program 'sock_tcp_connect' not found")?
            .try_into()
            .context("expected KProbe program type")?;
        kp_tcp
            .load()
            .context("failed to load sock_tcp_connect into kernel")?;
        kp_tcp
            .attach("tcp_connect", 0)
            .context("failed to attach kprobe to tcp_connect")?;

        // Attach kprobe: udp_sendmsg
        let kp_send: &mut KProbe = ebpf
            .program_mut("sock_udp_sendmsg")
            .context("BPF program 'sock_udp_sendmsg' not found")?
            .try_into()
            .context("expected KProbe program type")?;
        kp_send
            .load()
            .context("failed to load sock_udp_sendmsg into kernel")?;
        kp_send
            .attach("udp_sendmsg", 0)
            .context("failed to attach kprobe to udp_sendmsg")?;

        // Attach kprobe: udp_lib_unhash (UDP socket close/cleanup)
        let kp_unhash: &mut KProbe = ebpf
            .program_mut("sock_udp_unhash")
            .context("BPF program 'sock_udp_unhash' not found")?
            .try_into()
            .context("expected KProbe program type")?;
        kp_unhash
            .load()
            .context("failed to load sock_udp_unhash into kernel")?;
        kp_unhash
            .attach("udp_lib_unhash", 0)
            .context("failed to attach kprobe to udp_lib_unhash")?;

        eprintln!(
            "sock-tracker: eBPF programs attached \
             (kprobe:tcp_connect, kprobe:udp_sendmsg, kprobe:udp_lib_unhash)"
        );

        // Take ownership of the maps so we can store them without borrowing Ebpf.
        let sock_map: HashMap<MapData, SockKey, SockInfo> = HashMap::try_from(
            ebpf.take_map("SOCK_EVENTS")
                .context("BPF map 'SOCK_EVENTS' not found")?,
        )
        .context("failed to create HashMap from SOCK_EVENTS")?;
        let port_map: HashMap<MapData, PortKey, SockInfo> = HashMap::try_from(
            ebpf.take_map("PORT_PIDS")
                .context("BPF map 'PORT_PIDS' not found")?,
        )
        .context("failed to create HashMap from PORT_PIDS")?;

        Ok(Self {
            _ebpf: ebpf,
            sock_map: Mutex::new(sock_map),
            port_map: Mutex::new(port_map),
        })
    }

    /// Look up the process that owns a socket by source IP, port, and protocol.
    ///
    /// Consults BOTH maps (full `(ip, port, protocol)` key and the port-only
    /// fallback) and returns whichever entry is NEWER. This matters after
    /// ephemeral port reuse: a stale full-key entry (whose socket has since
    /// closed — entries deliberately outlive their sockets for the
    /// short-lived-process case) must never shadow the fresh port-only entry
    /// written by the current socket's send.
    ///
    /// Age gates bound staleness for both entries (the port-only gate is
    /// much tighter: the entry only needs to survive until the in-flight
    /// datagram is classified, and a long-lived port-only entry can be
    /// overwritten by a *different* process's socket reusing the port).
    ///
    /// Returns `None` if neither map has a fresh entry for the socket.
    pub fn lookup_pid(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        protocol: TransportProtocol,
    ) -> Option<TrackedProcess> {
        const MAX_ENTRY_AGE_S: u64 = 60;
        const MAX_PORT_ENTRY_AGE_S: u64 = 10;

        let full_hit = {
            let key = build_sock_key(src_ip, src_port, protocol);
            let map = self.sock_map.lock().ok()?;
            map.get(&key, 0).ok()
        };
        let port_hit = {
            let port_key = build_port_key(src_port, protocol);
            let map = self.port_map.lock().ok()?;
            map.get(&port_key, 0).ok()
        };

        let boot_now_ns = boot_time_now_ns()?;
        let fresh = |info: &SockInfo, max_age_s: u64| {
            boot_now_ns.saturating_sub(info.timestamp_ns) <= max_age_s * 1_000_000_000
        };

        // Prefer the NEWER entry; on equal timestamps prefer the full key
        // (it proves the source address, not just the port).
        let (info, source) = match (&full_hit, &port_hit) {
            (Some(f), Some(p)) => {
                if p.timestamp_ns > f.timestamp_ns {
                    (p, TrackerSource::PortKey)
                } else {
                    (f, TrackerSource::FullKey)
                }
            }
            (Some(f), None) => (f, TrackerSource::FullKey),
            (None, Some(p)) => (p, TrackerSource::PortKey),
            (None, None) => return None,
        };

        let max_age = match source {
            TrackerSource::PortKey => MAX_PORT_ENTRY_AGE_S,
            TrackerSource::FullKey => MAX_ENTRY_AGE_S,
            TrackerSource::Unknown => MAX_ENTRY_AGE_S,
        };
        if !fresh(info, max_age) {
            return None;
        }

        let mut tracked = TrackedProcess::from_info(info);
        tracked.source = source;
        Some(tracked)
    }
}

/// Key for the port-only fallback map (must match the eBPF-side PortKey).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct PortKey {
    /// Source port, host byte order.
    pub src_port: u16,
    /// IP protocol number: 6 = TCP, 17 = UDP.
    pub protocol: u8,
    pub _pad: u8,
}

// SAFETY: PortKey is a POD type — all bit patterns are valid.
unsafe impl aya::Pod for PortKey {}

fn build_port_key(src_port: u16, protocol: TransportProtocol) -> PortKey {
    let proto_num = match protocol {
        TransportProtocol::Tcp => 6u8,
        TransportProtocol::Udp | TransportProtocol::Quic => 17u8,
        TransportProtocol::Other => 0u8,
    };
    PortKey {
        src_port,
        protocol: proto_num,
        _pad: 0,
    }
}

/// Nanoseconds since boot (same clock as `bpf_ktime_get_ns`), via
/// `clock_gettime(CLOCK_MONOTONIC)` — on Linux this is the same basis the
/// BPF helper uses.
fn boot_time_now_ns() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid out-pointer for clock_gettime.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return None;
    }
    Some(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

/// Implement the `flow_classifier::SocketTracker` trait so the eBPF tracker
/// can be passed to `ProcProcessResolver::with_sock_tracker()`.
impl SocketTrackerTrait for SockTracker {
    fn lookup_pid(
        &self,
        src_ip: std::net::IpAddr,
        src_port: u16,
        protocol: TransportProtocol,
    ) -> Option<FcTrackedProcess> {
        self.lookup_pid(src_ip, src_port, protocol)
            .map(|tp| FcTrackedProcess {
                pid: tp.pid,
                uid: tp.uid,
                comm: tp.comm,
                source: tp.source,
            })
    }
}

/// Build a BPF map key from an IP address, port, and transport protocol.
///
/// IPv4 addresses are normalized to IPv4-mapped IPv6 (::ffff:a.b.c.d) to
/// match the format used by the eBPF program.
fn build_sock_key(src_ip: IpAddr, src_port: u16, protocol: TransportProtocol) -> SockKey {
    let proto_num = match protocol {
        TransportProtocol::Tcp => 6u8,
        TransportProtocol::Udp | TransportProtocol::Quic => 17u8,
        TransportProtocol::Other => 0u8,
    };

    let mut key = SockKey {
        src_ip: [0u8; 16],
        src_port,
        protocol: proto_num,
        _pad: 0,
    };

    match src_ip {
        IpAddr::V4(v4) => {
            // IPv4-mapped IPv6: ::ffff:a.b.c.d
            key.src_ip[10] = 0xff;
            key.src_ip[11] = 0xff;
            key.src_ip[12..16].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            key.src_ip.copy_from_slice(&v6.octets());
        }
    }

    key
}

/// Align an `include_bytes!` slice to the required BPF ELF alignment.
macro_rules! include_bytes_aligned {
    ($path:expr) => {{
        #[repr(C)]
        struct Aligned<T: ?Sized> {
            _align: [u32; 0],
            bytes: T,
        }
        static ALIGNED: &Aligned<[u8]> = &Aligned {
            _align: [],
            bytes: *include_bytes!($path),
        };
        &ALIGNED.bytes
    }};
}

use include_bytes_aligned;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn build_key_ipv4_normalized_to_mapped_ipv6() {
        let key = build_sock_key(
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
            8080,
            TransportProtocol::Tcp,
        );
        // ::ffff:10.0.2.15
        assert_eq!(key.src_ip[0..10], [0u8; 10]);
        assert_eq!(key.src_ip[10], 0xff);
        assert_eq!(key.src_ip[11], 0xff);
        assert_eq!(&key.src_ip[12..16], &[10, 0, 2, 15]);
        assert_eq!(key.src_port, 8080);
        assert_eq!(key.protocol, 6); // TCP
    }

    #[test]
    fn build_key_ipv6_raw() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let key = build_sock_key(IpAddr::V6(ip), 443, TransportProtocol::Udp);
        assert_eq!(key.src_ip[0..2], [0x20, 0x01]);
        assert_eq!(key.src_port, 443);
        assert_eq!(key.protocol, 17); // UDP
    }

    #[test]
    fn build_key_quic_uses_udp_protocol() {
        let key = build_sock_key(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            443,
            TransportProtocol::Quic,
        );
        assert_eq!(key.protocol, 17); // QUIC uses UDP protocol number
    }

    #[test]
    fn build_key_other_protocol_is_zero() {
        let key = build_sock_key(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            0,
            TransportProtocol::Other,
        );
        assert_eq!(key.protocol, 0);
    }

    // -------------------------------------------------------------------
    // Live-map integration tests (root + CAP_BPF required).
    //
    // These exercise the REAL eBPF programs and BPF maps against REAL
    // sockets created by this test process — verifying the tracepoint
    // offsets, byte orders, and map content on the running kernel.
    // They must run serially (they share the global BPF maps), so the
    // whole module is single-threaded and each test waits for map
    // convergence with bounded retries instead of sleeps.
    //
    // Run:  sudo cargo test -p dns-tracker sock_tracker -- --ignored --test-threads 1
    // -------------------------------------------------------------------

    fn my_pid() -> u32 {
        std::process::id()
    }

    fn default_gateway_v4() -> Option<std::net::Ipv4Addr> {
        let out = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.split_whitespace()
            .skip_while(|t| *t != "via")
            .nth(1)
            .and_then(|s| s.parse().ok())
    }

    fn default_gateway_v6() -> Option<std::net::Ipv6Addr> {
        let out = std::process::Command::new("ip")
            .args(["-6", "route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.split_whitespace()
            .skip_while(|t| *t != "via")
            .nth(1)
            .and_then(|s| s.parse().ok())
    }

    /// IPv6 default gateway plus its scope id (link-local gateways need
    /// `scope_id = ifindex` for connect() to be valid).
    fn default_gateway_v6_scoped() -> Option<(std::net::Ipv6Addr, u32)> {
        let gw = default_gateway_v6()?;
        let out = std::process::Command::new("ip")
            .args(["-6", "route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let dev = text
            .split_whitespace()
            .skip_while(|t| *t != "dev")
            .nth(1)?
            .to_string();
        let scope = ifindex_of(&dev)?;
        Some((gw, scope))
    }

    fn ifindex_of(dev: &str) -> Option<u32> {
        let out = std::process::Command::new("cat")
            .arg(format!("/sys/class/net/{dev}/ifindex"))
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }

    /// The default egress interface's primary IPv4 address — the source IP a
    /// connected socket to the gateway will use.
    fn local_v4_for_gateway() -> Option<std::net::Ipv4Addr> {
        let out = std::process::Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        // "default via GW dev IFACE proto dhcp src 192.168.x.y metric N"
        text.split_whitespace()
            .skip_while(|t| *t != "src")
            .nth(1)
            .and_then(|s| s.parse().ok())
    }

    /// Load the real eBPF tracker. These tests are root-only by declaration,
    /// so a load failure is a BROKEN BUILD (silently skipping would turn the
    /// tests into vacuous passes) — panic instead.
    fn load_tracker_or_panic_skip() -> Option<SockTracker> {
        match SockTracker::load() {
            Ok(t) => Some(t),
            Err(e) => panic!("sock tracker failed to load under root test: {e:#}"),
        }
    }

    /// Poll `f` until it returns `Some`, up to ~2s. Map updates are visible
    /// immediately after the triggering syscall returns; the tight retry
    /// covers scheduling jitter only.
    fn poll_map<T>(f: impl Fn() -> Option<T>) -> Option<T> {
        for _ in 0..200 {
            if let Some(v) = f() {
                return Some(v);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        None
    }

    /// Non-blocking TCP connect via socket2 → socket sits in SYN_SENT with
    /// the SYN on the wire (gateway port 9 is filtered → no RST race).
    fn syn_sent_socket(dst: std::net::SocketAddr) -> socket2::Socket {
        let domain = match dst {
            std::net::SocketAddr::V4(_) => socket2::Domain::IPV4,
            std::net::SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        let sock = socket2::Socket::new(domain, socket2::Type::STREAM, None).unwrap();
        sock.set_nonblocking(true).unwrap();
        match sock.connect(&dst.into()) {
            Ok(()) => eprintln!("note: gateway:9 accepted a connection?!"),
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => panic!("connect({dst}) failed unexpectedly: {e}"),
        }
        sock
    }

    fn kill_socket(sock: socket2::Socket) {
        let _ = sock.set_linger(Some(std::time::Duration::from_secs(0)));
        let _ = sock.shutdown(std::net::Shutdown::Both);
    }

    /// TCP over IPv4: a non-blocking connect to the gateway sends a SYN; the
    /// tracepoint must record OUR pid under the full (ip, port) key.
    /// This also verifies the tracepoint field offsets and the sport byte
    /// order on the running kernel — a byte-order bug makes this miss.
    #[test]
    #[ignore = "root + real eBPF; sudo cargo test -p dns-tracker -- --ignored --test-threads 1"]
    fn live_tcp_ipv4_full_key_hits_own_pid() {
        let Some(gw) = default_gateway_v4() else {
            eprintln!("skipping: no IPv4 default gateway");
            return;
        };
        let Some(tracker) = load_tracker_or_panic_skip() else {
            return;
        };
        let Some(local_ip) = local_v4_for_gateway() else {
            eprintln!("skipping: could not determine local source IPv4");
            return;
        };

        let sock = syn_sent_socket(format!("{gw}:9").parse().unwrap());
        let local_port = sock.local_addr().unwrap().as_socket().unwrap().port();

        let tracked = poll_map(|| {
            tracker.lookup_pid(IpAddr::V4(local_ip), local_port, TransportProtocol::Tcp)
        });
        let Some(t) = tracked else {
            panic!(
                "eBPF map has no full-key entry for TCP {local_ip}:{local_port} — \
                 tracepoint offsets or byte order are wrong on this kernel"
            );
        };
        assert_eq!(t.pid, my_pid(), "TCP v4 entry must point at this process");
        kill_socket(sock);
    }

    /// TCP over IPv6 — same verification for the AF_INET6 path of the
    /// tracepoint (saddr_v6 offset). Link-local gateways need the scope id.
    #[test]
    #[ignore = "root + real eBPF; sudo cargo test -p dns-tracker -- --ignored --test-threads 1"]
    fn live_tcp_ipv6_full_key_hits_own_pid() {
        let Some((gw, scope)) = default_gateway_v6_scoped() else {
            eprintln!("skipping: no IPv6 default gateway");
            return;
        };
        let Some(tracker) = load_tracker_or_panic_skip() else {
            return;
        };

        let dst = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(gw, 9, 0, scope));
        let sock = syn_sent_socket(dst);
        let local = sock.local_addr().unwrap().as_socket().unwrap();

        let tracked =
            poll_map(|| tracker.lookup_pid(local.ip(), local.port(), TransportProtocol::Tcp));
        let Some(t) = tracked else {
            panic!("eBPF map has no full-key entry for TCP6 {local} — v6 offset bug?");
        };
        assert_eq!(t.pid, my_pid());
        kill_socket(sock);
    }

    /// Connected UDP: full key must be present with our pid (skc_rcv_saddr is
    /// set by connect()).
    #[test]
    #[ignore = "root + real eBPF; sudo cargo test -p dns-tracker -- --ignored --test-threads 1"]
    fn live_udp_connected_full_key_hits_own_pid() {
        let Some(gw) = default_gateway_v4() else {
            eprintln!("skipping: no IPv4 default gateway");
            return;
        };
        let Some(tracker) = load_tracker_or_panic_skip() else {
            return;
        };

        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.connect(format!("{gw}:9")).unwrap();
        sock.send(b"x").unwrap();
        let local = sock.local_addr().unwrap();

        let tracked =
            poll_map(|| tracker.lookup_pid(local.ip(), local.port(), TransportProtocol::Udp));
        let Some(t) = tracked else {
            panic!("no full-key entry for connected UDP {local}");
        };
        assert_eq!(t.pid, my_pid());
        assert_eq!(t.uid, users_uid(), "captured UID must match this process");
    }

    /// Unconnected UDP sendto: only the port-only entry exists (rcv_saddr is
    /// 0.0.0.0 at udp_sendmsg time). Lookup must still find our pid via the
    /// port map.
    #[test]
    #[ignore = "root + real eBPF; sudo cargo test -p dns-tracker -- --ignored --test-threads 1"]
    fn live_udp_unconnected_port_key_hits_own_pid() {
        let Some(gw) = default_gateway_v4() else {
            eprintln!("skipping: no IPv4 default gateway");
            return;
        };
        let Some(tracker) = load_tracker_or_panic_skip() else {
            return;
        };

        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.send_to(b"x", format!("{gw}:9")).unwrap();
        let local = sock.local_addr().unwrap();

        let tracked =
            poll_map(|| tracker.lookup_pid(local.ip(), local.port(), TransportProtocol::Udp));
        let Some(t) = tracked else {
            panic!("no port-key entry for unconnected UDP {local}");
        };
        assert_eq!(t.pid, my_pid());
    }

    /// REGRESSION (misattribution at the eBPF layer): a stale full-key entry
    /// (from a connected socket that has since closed) must not shadow the
    /// fresh port-only entry written by a NEW unconnected socket that re-used
    /// the same ephemeral port. The full-key map is consulted first and its
    /// entries deliberately outlive their sockets — without comparing entry
    /// timestamps the resolver confidently returns the OLD process.
    ///
    /// The old socket is driven by an external `nc` child so the two owners
    /// have different pids; otherwise the bug would be invisible.
    #[test]
    #[ignore = "root + real eBPF; sudo cargo test -p dns-tracker -- --ignored --test-threads 1"]
    fn live_port_reuse_stale_full_key_must_not_shadow_fresh_port_entry() {
        let Some(gw) = default_gateway_v4() else {
            eprintln!("skipping: no IPv4 default gateway");
            return;
        };
        let Some(tracker) = load_tracker_or_panic_skip() else {
            return;
        };
        if which("nc").is_none() {
            eprintln!("skipping: nc not installed");
            return;
        }
        let Some(src_ip) = local_v4_for_gateway() else {
            eprintln!("skipping: could not determine local source IPv4");
            return;
        };

        // Pick a port for the old (nc) socket; retry on collisions.
        for attempt in 0..8u16 {
            let port: u16 =
                40000 + (((std::process::id() % 997) * 7 + attempt as u32 * 13) % 20000) as u16;
            // Phase A: external `nc` child connects (full key), sends, exits.
            let mut nc = std::process::Command::new("nc")
                .args([
                    "-u",
                    "-w",
                    "1",
                    "-p",
                    &port.to_string(),
                    &gw.to_string(),
                    "9",
                ])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn nc");
            let nc_pid = nc.id();
            if let Some(stdin) = nc.stdin.as_mut() {
                use std::io::Write;
                let _ = stdin.write_all(b"x");
            }
            let _ = nc.wait();

            // Phase B: this process rebinds the same port unconnected and
            // sends — writing a FRESH port-only entry.
            let Ok(sock_b) = std::net::UdpSocket::bind(("0.0.0.0", port)) else {
                continue; // port still held; try another
            };
            if sock_b.send_to(b"y", format!("{gw}:9")).is_err() {
                continue;
            }

            // A wildcard-bound socket reports 0.0.0.0 from local_addr(); the
            // actual packet (and therefore the NFQUEUE lookup) carries the
            // route-selected source address — use that, like the daemon does.
            let tracked =
                poll_map(|| tracker.lookup_pid(IpAddr::V4(src_ip), port, TransportProtocol::Udp));
            let Some(t) = tracked else {
                panic!("no entry at all for ({src_ip}:{port})");
            };
            assert_ne!(nc_pid, my_pid());
            assert_eq!(
                t.pid,
                my_pid(),
                "stale full-key entry from nc (pid {nc_pid}) shadowed the fresh \
                 port-only entry for the CURRENT socket — port reuse is \
                 misattributed to the previous process"
            );
            return;
        }
        panic!("could not find a reusable port in 8 attempts");
    }

    // -- helpers ------------------------------------------------------------

    fn which(bin: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var("PATH").ok()?;
        path.split(':')
            .map(|p| std::path::Path::new(p).join(bin))
            .find(|p| p.exists())
    }

    fn users_uid() -> u32 {
        // SAFETY: getuid is async-signal-safe and takes no pointers.
        unsafe { libc::getuid() }
    }
}
