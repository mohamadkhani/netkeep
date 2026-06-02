use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use aya::{maps::HashMap, programs::KProbe, Ebpf};

use crate::{DnsEvent, DnsKey};

/// Information captured for a single DNS query by the eBPF probe.
#[derive(Clone, Debug)]
pub struct DnsQueryInfo {
    pub pid: u32,
    /// Process base name (from `bpf_get_current_comm()`).
    pub comm: String,
    /// DNS query domain (QNAME decoded from wire format).
    pub domain: String,
}

/// Manages the eBPF DNS tracker: loads the BPF program, attaches the kprobe,
/// and provides lookups into the DNS events map.
pub struct DnsTracker {
    ebpf: Ebpf,
}

impl DnsTracker {
    /// Load and attach the eBPF kprobe on `udp_sendmsg`.
    ///
    /// The BPF object is embedded at compile time via `include_bytes_aligned!`.
    /// Requires root / `CAP_BPF` + `CAP_NET_ADMIN`.
    pub fn load() -> Result<Self> {
        // The BPF ELF object is embedded at compile time by xtask.
        let ebpf_bytes = include_bytes_aligned!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dns-tracker-ebpf/target/bpfel-unknown-none/release/dns-tracker-ebpf"
        ));

        let mut ebpf = Ebpf::load(ebpf_bytes).context("failed to load BPF object")?;

        // Attach the kprobe to udp_sendmsg.
        let prog: &mut KProbe = ebpf
            .program_mut("dns_sendmsg")
            .context("BPF program 'dns_sendmsg' not found")?
            .try_into()
            .context("expected KProbe program type")?;
        prog.load().context("failed to load kprobe into kernel")?;
        prog.attach("udp_sendmsg", 0)
            .context("failed to attach kprobe to udp_sendmsg")?;

        eprintln!("dns-tracker: eBPF kprobe attached to udp_sendmsg");
        Ok(Self { ebpf })
    }

    /// Look up a DNS query event by source IP and port.
    ///
    /// Returns `None` if the BPF map has no entry for this key (i.e. the
    /// socket was not a DNS query, or the entry was evicted).
    pub fn lookup(&self, src_ip: Ipv4Addr, src_port: u16) -> Option<DnsQueryInfo> {
        let map: HashMap<_, DnsKey, DnsEvent> =
            HashMap::try_from(self.ebpf.map("DNS_EVENTS")?).ok()?;

        let key = DnsKey {
            src_ip4: u32::from(src_ip).to_be(),
            src_port,
            _pad: 0,
        };

        let event = map.get(&key, 0).ok()?;
        let comm = null_terminated_str(&event.comm).to_string();
        let domain = null_terminated_str(&event.domain).to_string();

        Some(DnsQueryInfo {
            pid: event.pid,
            comm,
            domain,
        })
    }
}

/// Convert a null-terminated byte slice to a &str (UTF-8 best-effort).
fn null_terminated_str(bytes: &[u8]) -> &str {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..len]).unwrap_or("")
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
