// `cfg` mirrors the panic handler below: for the real eBPF target the crate is
// fully no_std, but host-target `cargo check --all-targets` (rust-analyzer)
// also builds each bin in test mode, where std provides `panic_impl` and ours
// would be a hard "duplicate lang item" error.
#![cfg_attr(target_os = "none", no_std)]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{kprobe, map},
    maps::LruHashMap,
    programs::ProbeContext,
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
    /// Process comm (exe basename, kernel-truncated to 16 bytes) captured at
    /// hook time. The process is guaranteed alive mid-syscall, so this
    /// survives the exit race that makes /proc/<pid>/exe unreadable for
    /// short-lived processes. NUL-padded.
    pub comm: [u8; 16],
}

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

/// Socket → process mapping. Populated by both TCP and UDP hooks.
/// LRU: entries self-evict under capacity pressure. We deliberately do NOT
/// delete on socket close — the resolver must still find the PID AFTER a
/// short-lived process exits (its /proc entry is already gone by then; the
/// BPF map is the only surviving record). Port reuse overwrites the key at
/// the new socket's first send; the userspace lookup age-gates entries and
/// picks the NEWEST entry across both maps.
///
/// Capacity 65536 covers the full ephemeral port range (~28k sockets) with
/// headroom, so a busy desktop's churn cannot LRU-evict entries for sockets
/// that are still being classified (which would fall back to the racy
/// /proc path and misattribute under load).
#[map]
static SOCK_EVENTS: LruHashMap<SockKey, SockInfo> =
    LruHashMap::with_max_entries(65536, 0);

/// Secondary map keyed by (source port, protocol) ONLY. Unconnected UDP
/// sockets (the common case: nc, DNS stubs, most one-shot clients) have
/// skc_rcv_saddr == 0.0.0.0 at udp_sendmsg time — the address is only chosen
/// later, during route lookup. Those sends can't build a full SockKey, so we
/// record them here by port alone; an in-flight ephemeral port uniquely
/// identifies the socket, and the userspace resolver falls back to this map
/// on a full-key miss (preferring whichever of the two entries is newer).
#[map]
static PORT_PIDS: LruHashMap<PortKey, SockInfo> = LruHashMap::with_max_entries(65536, 0);

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
// TCP: kprobe on tcp_connect
// ---------------------------------------------------------------------------

/// Protocol constants.
const IPPROTO_TCP: u16 = 6;
const IPPROTO_UDP: u16 = 17;

/// AF_INET / AF_INET6.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// kprobe on `tcp_connect`.
/// Uses the shared SKC_* field offsets defined in the UDP section below.
/// Kernel: int tcp_connect(struct sock *sk)
///
/// Captures PID for every outgoing TCP connection attempt. `tcp_connect`
/// runs at the END of tcp_v4_connect/tcp_v6_connect — AFTER the ephemeral
/// port (skc_num) and source address (skc_rcv_saddr) have been assigned by
/// connect() — so the key fields are guaranteed populated even for
/// auto-bound sockets.
///
/// HISTORY: this hook used to be the `inet_sock_set_state` tracepoint
/// filtered on TCP_SYN_SENT. That broke twice, and is now known to be
/// structurally unusable for this purpose on modern kernels:
///   1. The tracepoint record layout is not stable (6.18 moved sport/dport
///      ahead of family/protocol) — fixable by parsing the format file.
///   2. Since the tcp_set_state(SYN_SENT) call was moved BEFORE the port
///      hash assignment (kernel ~6.15+), the record itself carries
///      sport=0 / saddr=0.0.0.0 for auto-bound sockets — the information we
///      need is not in the record at all. Verified empirically on 6.18:
///      the raw record for a fresh connect shows daddr set but sport/saddr
///      zeroed; only pre-bound sockets (explicit bind()) carry values.
/// Reading the socket fields via the `sk` pointer — like the UDP hook — is
/// immune to both problems.
#[kprobe]
pub fn sock_tcp_connect(ctx: ProbeContext) -> u32 {
    match unsafe { try_sock_tcp_connect(&ctx) } {
        Ok(()) | Err(()) => 0,
    }
}

#[inline(always)]
unsafe fn try_sock_tcp_connect(ctx: &ProbeContext) -> Result<(), ()> {
    // arg0 = struct sock *sk
    let sk_ptr: *const u8 = ctx.arg::<*const u8>(0).ok_or(())?;

    // Read family.
    let family: u16 =
        bpf_probe_read_kernel(sk_ptr.add(SKC_FAMILY_OFF) as *const u16).map_err(|_| ())?;

    // Source port (host byte order) — assigned by tcp_v4_connect before
    // tcp_connect runs. Zero means it was not assigned (should not happen
    // on this path); skip to avoid polluting the map with useless keys.
    let src_port: u16 =
        bpf_probe_read_kernel(sk_ptr.add(SKC_NUM_OFF) as *const u16).map_err(|_| ())?;
    if src_port == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let info = SockInfo {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        timestamp_ns: bpf_ktime_get_ns(),
        comm: current_comm(),
    };

    let mut key = SockKey {
        src_ip: zeroed_ip16(),
        src_port,
        protocol: IPPROTO_TCP as u8,
        _pad: 0,
    };

    if family == AF_INET as u16 {
        // IPv4: read 4-byte source address (network byte order).
        let src_ip4: u32 = bpf_probe_read_kernel(sk_ptr.add(SKC_RCV_SADDR_OFF) as *const u32)
            .map_err(|_| ())?;
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
        comm: current_comm(),
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

/// Capture the current process comm (16 bytes, NUL-padded) at hook time.
/// Guaranteed to be the connecting/sending process — the hook fires inside
/// its syscall. On helper failure, returns NULs (the resolver then relies on
/// /proc for the name, as before).
#[inline(always)]
fn current_comm() -> [u8; 16] {
    match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => [0u8; 16],
    }
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
