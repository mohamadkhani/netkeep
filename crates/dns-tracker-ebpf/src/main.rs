#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{kprobe, map},
    maps::{HashMap, PerCpuArray},
    programs::ProbeContext,
};

/// Key for the DNS events map: source IPv4 address + source port.
/// Must match crates/dns-tracker/src/lib.rs.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsKey {
    /// Source IPv4 address, network byte order.
    pub src_ip4: u32,
    /// Source port, host byte order.
    pub src_port: u16,
    pub _pad: u16,
}

/// Value stored in the DNS events map.
/// Must match crates/dns-tracker/src/lib.rs.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub pid: u32,
    pub comm: [u8; 16],
    pub domain: [u8; 256],
}

/// Per-CPU scratch space for DnsEvent (avoids 512-byte BPF stack limit).
#[map]
static SCRATCH: PerCpuArray<DnsEvent> = PerCpuArray::with_max_entries(1, 0);

/// Published events: DnsKey → DnsEvent.
#[map]
static DNS_EVENTS: HashMap<DnsKey, DnsEvent> = HashMap::with_max_entries(8192, 0);

/// Field offsets inside `struct sock` → `struct sock_common` (x86_64, Linux 6.x).
/// Verify with: `pahole -C sock_common vmlinux` or BTF dump.
const SKC_FAMILY_OFF: usize = 0;      // __u16 skc_family
const SKC_DPORT_OFF: usize = 2;       // __be16 skc_dport  (destination port, big-endian)
const SKC_NUM_OFF: usize = 4;         // __u16  skc_num    (source port, host-endian)
const SKC_RCV_SADDR_OFF: usize = 20;  // __be32 skc_rcv_saddr (IPv4 src, big-endian)

/// msghdr layout (x86_64, Linux 6.x).
/// The __iov pointer (pointer to first iovec) lives at offset 32 inside msghdr.
const MSGHDR_IOV_OFF: usize = 32;

/// kprobe on udp_sendmsg.
/// Kernel: int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
#[kprobe]
pub fn dns_sendmsg(ctx: ProbeContext) -> u32 {
    match unsafe { try_dns_sendmsg(&ctx) } {
        Ok(()) | Err(()) => 0,
    }
}

#[inline(always)]
unsafe fn try_dns_sendmsg(ctx: &ProbeContext) -> Result<(), ()> {
    // arg0 = struct sock *sk
    let sk_ptr: *const u8 = ctx.arg::<*const u8>(0).ok_or(())?;

    // Filter AF_INET (2).
    let family: u16 =
        bpf_probe_read_kernel(sk_ptr.add(SKC_FAMILY_OFF) as *const u16).map_err(|_| ())?;
    if family != 2 {
        return Ok(());
    }

    // Destination port (big-endian → host).
    let dport_be: u16 =
        bpf_probe_read_kernel(sk_ptr.add(SKC_DPORT_OFF) as *const u16).map_err(|_| ())?;
    if u16::from_be(dport_be) != 53 {
        return Ok(());
    }

    // Source port (already host byte order).
    let src_port: u16 =
        bpf_probe_read_kernel(sk_ptr.add(SKC_NUM_OFF) as *const u16).map_err(|_| ())?;

    // Source IPv4 address (network byte order).
    let src_ip4: u32 =
        bpf_probe_read_kernel(sk_ptr.add(SKC_RCV_SADDR_OFF) as *const u32).map_err(|_| ())?;

    let key = DnsKey { src_ip4, src_port, _pad: 0 };

    // Obtain a per-CPU scratch DnsEvent to avoid stack overflow.
    let event = SCRATCH.get_ptr_mut(0).ok_or(())?;
    // SAFETY: This is per-CPU storage; no concurrent access from this CPU.
    let event = &mut *event;

    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.comm = bpf_get_current_comm().map_err(|_| ())?;

    // arg1 = struct msghdr *msg
    let msg_ptr: *const u8 = ctx.arg::<*const u8>(1).ok_or(())?;

    // Clear domain buffer.
    for b in event.domain.iter_mut() {
        *b = 0;
    }

    // Parse DNS QNAME from first iovec's payload.
    let _ = parse_qname_from_msg(msg_ptr, &mut event.domain);

    let _ = DNS_EVENTS.insert(&key, event, 0);
    Ok(())
}

/// Read the first iovec from msghdr, then parse DNS QNAME (starts at byte 12).
#[inline(always)]
unsafe fn parse_qname_from_msg(msg_ptr: *const u8, out: &mut [u8; 256]) -> Result<(), ()> {
    // Read the iovec pointer stored at MSGHDR_IOV_OFF inside msghdr.
    let iov_ptr: *const u8 =
        bpf_probe_read_kernel((msg_ptr.add(MSGHDR_IOV_OFF)) as *const *const u8)
            .map_err(|_| ())?;
    if iov_ptr.is_null() {
        return Err(());
    }

    // Read iov_base from the first iovec (offset 0 inside struct iovec).
    let data_ptr: *const u8 =
        bpf_probe_read_kernel(iov_ptr as *const *const u8).map_err(|_| ())?;
    if data_ptr.is_null() {
        return Err(());
    }

    // DNS header = 12 bytes; QNAME follows.
    parse_qname(data_ptr.add(12), out)
}

/// Decode a DNS wire-format QNAME into dot-separated ASCII (null-terminated).
/// BPF verifier requires bounded loops; we limit iterations to satisfy it.
#[inline(always)]
unsafe fn parse_qname(ptr: *const u8, out: &mut [u8; 256]) -> Result<(), ()> {
    let mut src = 0usize;
    let mut dst = 0usize;
    let mut first = true;

    // Outer loop: at most 16 labels (sufficient for any real domain name).
    for _ in 0..16usize {
        if dst >= 253 {
            break;
        }
        let len: u8 = bpf_probe_read_kernel(ptr.add(src)).map_err(|_| ())?;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            break; // compression pointer or illegal — stop
        }
        let label_len = len as usize;
        if label_len > 63 || src + 1 + label_len > 253 {
            break;
        }
        src += 1;

        if !first && dst < 254 {
            out[dst] = b'.';
            dst += 1;
        }
        first = false;

        // Inner loop: copy label bytes. Bounded at 64 to satisfy verifier.
        for i in 0..64usize {
            if i >= label_len || dst >= 254 {
                break;
            }
            let ch: u8 = bpf_probe_read_kernel(ptr.add(src + i)).map_err(|_| ())?;
            out[dst] = if ch.is_ascii_uppercase() { ch + 32 } else { ch };
            dst += 1;
        }
        src += label_len;
    }

    if dst < 256 {
        out[dst] = 0;
    }
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
