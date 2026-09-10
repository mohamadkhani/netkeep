// `cfg` mirrors the panic handler below: for the real eBPF target the crate is
// fully no_std, but host-target `cargo check --all-targets` (rust-analyzer)
// also builds each bin in test mode, where std provides `panic_impl` and ours
// would be a hard "duplicate lang item" error.
#![cfg_attr(target_os = "none", no_std)]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, map, tracepoint},
    maps::LruHashMap,
    programs::{ProbeContext, TracePointContext},
};

// ---------------------------------------------------------------------------
// Shared types (must match userspace in dns-tracker/src/sock_tracker.rs)
// ---------------------------------------------------------------------------

/// Key: identifies a socket by source address + port + protocol.
/// IPv4 addresses are stored as IPv4-mapped IPv6 (::ffff:a.b.c.d).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockKey {
    /// Source IP as 16 bytes. IPv4 stored as ::ffff:a.b.c.d.
    /// Network byte order within each 32-bit word (same as kernel storage).
    pub src_ip: [u8; 16],
    /// Source port, host byte order.
    pub src_port: u16,
    /// IP protocol number: 6 = TCP, 17 = UDP.
    pub protocol: u8,
    pub _pad: u8,
}

/// Value: process info captured at socket creation/send time.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockInfo {
    /// PID of the process that owns the socket.
    pub pid: u32,
    /// UID of the process that owns the socket.
    pub uid: u32,
    /// Timestamp (nanoseconds since boot) when the entry was created.
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

/// Socket → process mapping. Populated by both TCP and UDP hooks.
/// LRU: entries self-evict under capacity pressure. We deliberately do NOT
/// delete on socket close — the resolver must still find the PID AFTER a
/// short-lived process exits (its /proc entry is already gone by then; the
/// BPF map is the only surviving record). Port reuse overwrites the key at
/// the new socket's first send; the userspace lookup age-gates entries.
#[map]
static SOCK_EVENTS: LruHashMap<SockKey, SockInfo> =
    LruHashMap::with_max_entries(16384, 0);

/// Secondary map keyed by (source port, protocol) ONLY. Unconnected UDP
/// sockets (the common case: nc, DNS stubs, most one-shot clients) have
/// skc_rcv_saddr == 0.0.0.0 at udp_sendmsg time — the address is only chosen
/// later, during route lookup. Those sends can't build a full SockKey, so we
/// record them here by port alone; an in-flight ephemeral port uniquely
/// identifies the socket, and the userspace resolver falls back to this map
/// on a full-key miss.
#[map]
static PORT_PIDS: LruHashMap<PortKey, SockInfo> = LruHashMap::with_max_entries(16384, 0);

/// Key for the port-only secondary map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PortKey {
    /// Source port, host byte order.
    pub src_port: u16,
    /// IP protocol number: 6 = TCP, 17 = UDP.
    pub protocol: u8,
    pub _pad: u8,
}

// ---------------------------------------------------------------------------
// TCP: tracepoint on inet_sock_set_state
// ---------------------------------------------------------------------------

/// TCP state constants (from include/net/tcp_states.h).
const TCP_SYN_SENT: u32 = 2;
const TCP_TIME_WAIT: u32 = 6;
const TCP_CLOSE: u32 = 7;

/// Protocol constants.
const IPPROTO_TCP: u16 = 6;
const IPPROTO_UDP: u16 = 17;

/// AF_INET / AF_INET6.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Tracepoint offsets for inet_sock_set_state (x86_64, Linux 6.x).
/// These are the byte offsets from the start of the raw tracepoint record
/// (including the 8-byte common header).
///
/// Format (from /sys/kernel/tracing/events/sock/inet_sock_set_state/format):
///   offset 8:  const void *skaddr      (8 bytes, pointer)
///   offset 16: int oldstate            (4 bytes)
///   offset 20: int newstate            (4 bytes)
///   offset 24: __u16 family            (2 bytes)
///   offset 26: __u16 protocol          (2 bytes)
///   offset 28: __u16 sport             (2 bytes)
///   offset 30: __u16 dport             (2 bytes)
///   offset 32: __be32 saddr            (4 bytes, IPv4 src)
///   offset 36: __be32 daddr            (4 bytes, IPv4 dst)
///   offset 40: __u32 saddr_v6[4]       (16 bytes, IPv6 src)
///   offset 56: __u32 daddr_v6[4]       (16 bytes, IPv6 dst)
const TP_OFF_NEWSTATE: usize = 20;
const TP_OFF_FAMILY: usize = 24;
const TP_OFF_PROTOCOL: usize = 26;
const TP_OFF_SPORT: usize = 28;
const TP_OFF_SADDR: usize = 32;
const TP_OFF_SADDR_V6: usize = 40;

/// Hook: tracepoint/sock/inet_sock_set_state
///
/// Captures PID when a TCP socket enters SYN_SENT (outgoing connection).
/// Cleans up the entry when the socket enters TIME_WAIT or CLOSE.
#[tracepoint(category = "sock", name = "inet_sock_set_state")]
pub fn trace_tcp_state(ctx: TracePointContext) -> u32 {
    match unsafe { try_trace_tcp_state(&ctx) } {
        Ok(()) | Err(()) => 0,
    }
}

#[inline(always)]
unsafe fn try_trace_tcp_state(ctx: &TracePointContext) -> Result<(), ()> {
    let newstate: u32 = ctx.read_at(TP_OFF_NEWSTATE).map_err(|_| ())?;
    let protocol: u16 = ctx.read_at(TP_OFF_PROTOCOL).map_err(|_| ())?;

    // Only handle TCP.
    if protocol != IPPROTO_TCP {
        return Ok(());
    }

    // On SYN_SENT: insert into map.
    if newstate == TCP_SYN_SENT {
        let family: u16 = ctx.read_at(TP_OFF_FAMILY).map_err(|_| ())?;
        let sport: u16 = ctx.read_at(TP_OFF_SPORT).map_err(|_| ())?;

        let mut key = SockKey {
            src_ip: zeroed_ip16(),
            src_port: sport,
            protocol: IPPROTO_TCP as u8,
            _pad: 0,
        };

        // Fill source IP, normalizing IPv4 to IPv4-mapped IPv6.
        if family == AF_INET {
            // IPv4: read 4-byte saddr, store as ::ffff:a.b.c.d
            let saddr: u32 = ctx.read_at(TP_OFF_SADDR).map_err(|_| ())?;
            // ::ffff: prefix: 0000:0000:0000:0000:0000:ffff
            key.src_ip[10] = 0xff;
            key.src_ip[11] = 0xff;
            // saddr is network byte order from the kernel — copy directly.
            key.src_ip[12..16].copy_from_slice(&saddr.to_ne_bytes());
        } else if family == AF_INET6 {
            // IPv6: read 16-byte saddr_v6.
            let saddr_v6: [u8; 16] = ctx.read_at(TP_OFF_SADDR_V6).map_err(|_| ())?;
            key.src_ip.copy_from_slice(&saddr_v6);
        } else {
            return Ok(());
        }

        let pid_tgid = bpf_get_current_pid_tgid();
        let uid_gid = bpf_get_current_uid_gid();

        let info = SockInfo {
            pid: (pid_tgid >> 32) as u32,
            uid: uid_gid as u32,
            timestamp_ns: bpf_ktime_get_ns(),
        };

        let _ = SOCK_EVENTS.insert(&key, &info, 0);
        return Ok(());
    }

    // On TIME_WAIT or CLOSE: do nothing. The entry deliberately survives the
    // socket (see the SOCK_EVENTS map doc) — the userspace resolver needs it
    // after short-lived processes exit, and LRU eviction bounds its lifetime.
    let _ = (newstate, TP_OFF_FAMILY, TP_OFF_SPORT, TP_OFF_SADDR, TP_OFF_SADDR_V6);

    Ok(())
}

// ---------------------------------------------------------------------------
// UDP: kprobe on udp_sendmsg
// ---------------------------------------------------------------------------

/// Field offsets inside `struct sock` → `struct sock_common` (x86_64).
/// struct sock starts with sock_common, so these are offsets from `sk`.
/// Verified against kernel BTF (`pahole -C sock_common /sys/kernel/btf/vmlinux`,
/// Linux 6.18): family=16, num=14, rcv_saddr=4, v6_rcv_saddr=72.
/// NOTE: the layout is BTF-derived, not compile-time CO-RE — re-verify after
/// major kernel upgrades.
const SKC_FAMILY_OFF: usize = 16; // __u16 skc_family
const SKC_NUM_OFF: usize = 14; // __u16 skc_num (source port, host-endian)
const SKC_RCV_SADDR_OFF: usize = 4; // __be32 skc_rcv_saddr (IPv4 src)
/// Offset of skc_v6_rcv_saddr inside struct sock_common (x86_64).
/// This is the IPv6 source address for AF_INET6 sockets.
const SKC_V6_RCV_SADDR_OFF: usize = 72; // struct in6_addr skc_v6_rcv_saddr

/// kprobe on udp_sendmsg.
/// Kernel: int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
///
/// Captures PID for every outgoing UDP send. This covers both connected and
/// unconnected UDP sockets, including QUIC.
#[kprobe]
pub fn sock_udp_sendmsg(ctx: ProbeContext) -> u32 {
    match unsafe { try_sock_udp_sendmsg(&ctx) } {
        Ok(()) | Err(()) => 0,
    }
}

#[inline(always)]
unsafe fn try_sock_udp_sendmsg(ctx: &ProbeContext) -> Result<(), ()> {
    // arg0 = struct sock *sk
    let sk_ptr: *const u8 = ctx.arg::<*const u8>(0).ok_or(())?;

    // Read family.
    let family: u16 =
        bpf_probe_read_kernel(sk_ptr.add(SKC_FAMILY_OFF) as *const u16).map_err(|_| ())?;

    // Source port (host byte order).
    let src_port: u16 =
        bpf_probe_read_kernel(sk_ptr.add(SKC_NUM_OFF) as *const u16).map_err(|_| ())?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let info = SockInfo {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        timestamp_ns: bpf_ktime_get_ns(),
    };

    // Always record the port-only key — an in-flight ephemeral port uniquely
    // identifies the socket even when the source address is not yet known.
    let port_key = PortKey {
        src_port,
        protocol: IPPROTO_UDP as u8,
        _pad: 0,
    };
    let _ = PORT_PIDS.insert(&port_key, &info, 0);

    // Full key only when the socket actually has a source address. Unconnected
    // UDP sockets have rcv_saddr == 0.0.0.0 here (address chosen later, during
    // route lookup) — writing that as a full key would only pollute the map.
    let mut key = SockKey {
        src_ip: zeroed_ip16(),
        src_port,
        protocol: IPPROTO_UDP as u8,
        _pad: 0,
    };

    if family == AF_INET as u16 {
        // IPv4: read 4-byte source address.
        let src_ip4: u32 = bpf_probe_read_kernel(sk_ptr.add(SKC_RCV_SADDR_OFF) as *const u32)
            .map_err(|_| ())?;
        if src_ip4 == 0 {
            // Unconnected socket — the port-only entry above covers it.
            return Ok(());
        }
        // Normalize to IPv4-mapped IPv6.
        key.src_ip[10] = 0xff;
        key.src_ip[11] = 0xff;
        // src_ip4 is network byte order from the kernel.
        key.src_ip[12..16].copy_from_slice(&src_ip4.to_ne_bytes());
    } else if family == AF_INET6 as u16 {
        // IPv6: read 16-byte source address.
        let src_ip6: [u8; 16] = core::mem::transmute(
            bpf_probe_read_kernel::<[u32; 4]>(sk_ptr.add(SKC_V6_RCV_SADDR_OFF) as *const [u32; 4])
                .map_err(|_| ())?,
        );
        key.src_ip.copy_from_slice(&src_ip6);
    } else {
        return Ok(());
    }

    let _ = SOCK_EVENTS.insert(&key, &info, 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Cleanup: kprobe on udp_lib_unhash (UDP socket close)
// ---------------------------------------------------------------------------

/// kprobe on udp_lib_unhash — fires when a UDP socket is closed/unhashed.
/// Deliberately a NO-OP: entries survive socket close so the resolver can
/// still find the PID after a short-lived process exits (see the
/// SOCK_EVENTS map doc). Staleness is bounded by LRU eviction on the map and
/// the userspace age gate in `lookup_pid`. Keeping the probe attached (doing
/// nothing) preserves the program set across restarts.
#[kprobe]
pub fn sock_udp_unhash(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

/// Build a zeroed 16-byte IP array via volatile writes: a plain `[0u8; 16]`
/// literal lowers to llvm.memset, which bpf-linker >= 0.11 rejects on the
/// no_std eBPF target.
#[inline(always)]
fn zeroed_ip16() -> [u8; 16] {
    let mut buf = core::mem::MaybeUninit::<[u8; 16]>::uninit();
    // SAFETY: we initialize every byte below before reading.
    let p = buf.as_mut_ptr() as *mut u8;
    for i in 0..16 {
        unsafe { core::ptr::write_volatile(p.add(i), 0) };
    }
    // SAFETY: [u8; 16] has no invalid bit patterns and all bytes are set.
    unsafe { buf.assume_init() }
}

// Host-target test-mode builds (rust-analyzer) link std's panic_impl; only
// define ours for the actual eBPF target, where it is required.
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
