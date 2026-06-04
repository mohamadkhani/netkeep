//! eBPF-based socket tracker for near-instantaneous PID resolution.
//!
//! Hooks into the kernel's `inet_sock_set_state` tracepoint (TCP) and
//! `udp_sendmsg` / `udp_lib_unhash` kprobes (UDP) to capture the PID at the
//! exact moment a socket is created or a packet is sent — before NFQUEUE
//! delivers the packet to userspace. This eliminates the TOCTOU race that
//! plagues `/proc/net` lookups and the fork/exec fd-visibility gap that causes
//! `find_pid_for_inode` to return `None`.

use std::net::IpAddr;
use std::sync::Mutex;

use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData};
use aya::programs::{KProbe, TracePoint};
use aya::Ebpf;

use core_types::TransportProtocol;
use flow_classifier::{SocketTracker as SocketTrackerTrait, TrackedProcess as FcTrackedProcess};

// ---------------------------------------------------------------------------
// Shared BPF types (must match crates/dns-tracker-ebpf/src/sock_tracker.rs)
// ---------------------------------------------------------------------------

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
}

// SAFETY: SockInfo is a POD type — all bit patterns are valid.
unsafe impl aya::Pod for SockInfo {}

/// Result of a successful eBPF socket tracker lookup.
#[derive(Debug, Clone)]
pub struct TrackedProcess {
    pub pid: u32,
    pub uid: u32,
}

/// Manages the eBPF socket tracker: loads the BPF programs, attaches them,
/// and provides lookups into the socket events map.
pub struct SockTracker {
    /// The BPF object — must stay alive for the maps to remain accessible.
    _ebpf: Ebpf,
    /// Handle to the SOCK_EVENTS BPF map. Protected by Mutex for thread safety
    /// (NFQUEUE processor calls lookup_pid from its run loop thread).
    sock_map: Mutex<HashMap<MapData, SockKey, SockInfo>>,
}

impl SockTracker {
    /// Load and attach the eBPF socket tracker programs.
    ///
    /// Attaches:
    /// - `trace_tcp_state` tracepoint on `sock:inet_sock_set_state`
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

        // Attach tracepoint: sock:inet_sock_set_state
        let tp: &mut TracePoint = ebpf
            .program_mut("trace_tcp_state")
            .context("BPF program 'trace_tcp_state' not found")?
            .try_into()
            .context("expected TracePoint program type")?;
        tp.load()
            .context("failed to load trace_tcp_state into kernel")?;
        tp.attach("sock", "inet_sock_set_state")
            .context("failed to attach trace_tcp_state to sock:inet_sock_set_state")?;

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
             (tracepoint:sock:inet_sock_set_state, kprobe:udp_sendmsg, kprobe:udp_lib_unhash)"
        );

        // Take ownership of the map so we can store it without borrowing Ebpf.
        let sock_map: HashMap<MapData, SockKey, SockInfo> = HashMap::try_from(
            ebpf.take_map("SOCK_EVENTS")
                .context("BPF map 'SOCK_EVENTS' not found")?,
        )
        .context("failed to create HashMap from SOCK_EVENTS")?;

        Ok(Self {
            _ebpf: ebpf,
            sock_map: Mutex::new(sock_map),
        })
    }

    /// Look up the process that owns a socket by source IP, port, and protocol.
    ///
    /// Returns `None` if the BPF map has no entry for this key (e.g., the
    /// socket was created before the tracker was loaded, or the entry was
    /// evicted).
    pub fn lookup_pid(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        protocol: TransportProtocol,
    ) -> Option<TrackedProcess> {
        let key = build_sock_key(src_ip, src_port, protocol);

        let map = self.sock_map.lock().ok()?;
        let info = map.get(&key, 0).ok()?;

        Some(TrackedProcess {
            pid: info.pid,
            uid: info.uid,
        })
    }
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
}
