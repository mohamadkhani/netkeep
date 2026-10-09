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

/// A tracked DNS query found by domain scan, with its source socket so the
/// caller can validate the socket's current owner via SOCK_DIAG / /proc.
#[derive(Clone, Debug)]
pub struct DnsQueryCandidate {
    /// Source IPv4 from the map key (may be `0.0.0.0` for auto-bound sockets).
    pub src_ip: Ipv4Addr,
    /// Source port from the map key.
    pub src_port: u16,
    /// Captured query info (pid, comm, domain).
    pub info: DnsQueryInfo,
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
    /// Tries the specific source IP first, then falls back to `0.0.0.0`
    /// (INADDR_ANY). Auto-bound UDP sockets have `skc_rcv_saddr = 0.0.0.0`
    /// even when the actual packet source IP is `127.0.0.1` or a real IP.
    ///
    /// Returns `None` if the BPF map has no entry for either key.
    pub fn lookup(&self, src_ip: Ipv4Addr, src_port: u16) -> Option<DnsQueryInfo> {
        let map: HashMap<_, DnsKey, DnsEvent> =
            HashMap::try_from(self.ebpf.map("DNS_EVENTS")?).ok()?;

        // Try 1: specific source IP.
        let key = DnsKey {
            src_ip4: u32::from(src_ip).to_be(),
            src_port,
            _pad: 0,
        };
        if let Ok(event) = map.get(&key, 0) {
            return Some(DnsQueryInfo {
                pid: event.pid,
                comm: null_terminated_str(&event.comm).to_string(),
                domain: null_terminated_str(&event.domain).to_string(),
            });
        }

        // Try 2: wildcard (0.0.0.0) — auto-bound UDP sockets.
        let wildcard_key = DnsKey {
            src_ip4: 0u32.to_be(),
            src_port,
            _pad: 0,
        };
        let event = map.get(&wildcard_key, 0).ok()?;
        Some(DnsQueryInfo {
            pid: event.pid,
            comm: null_terminated_str(&event.comm).to_string(),
            domain: null_terminated_str(&event.domain).to_string(),
        })
    }

    /// Find every tracked query for `domain` by scanning the whole map.
    ///
    /// Used for stub-resolver attribution: when a local caching resolver
    /// (systemd-resolved, dnsmasq, …) re-queries the forwarder, the
    /// socket-level lookup names the resolver — not the app that asked for
    /// the name. The app's own query to the stub (e.g. dst `127.0.0.53:53`)
    /// has dport 53 too, so the map also holds `(app socket → domain)`
    /// entries that this scan recovers.
    ///
    /// Returns candidates in arbitrary map order; the caller filters out
    /// resolver/daemon comms and validates the socket's current owner.
    pub fn lookup_all_by_domain(&self, domain: &str) -> Vec<DnsQueryCandidate> {
        let Some(map_data) = self.ebpf.map("DNS_EVENTS") else {
            return Vec::new();
        };
        let Ok(map) = HashMap::<_, DnsKey, DnsEvent>::try_from(map_data) else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for key in map.keys() {
            let Ok(key) = key else { continue };
            let Ok(event) = map.get(&key, 0) else {
                continue;
            };
            if null_terminated_str(&event.domain) == domain {
                out.push(DnsQueryCandidate {
                    src_ip: Ipv4Addr::from(u32::from_be(key.src_ip4)),
                    src_port: key.src_port,
                    info: DnsQueryInfo {
                        pid: event.pid,
                        comm: null_terminated_str(&event.comm).to_string(),
                        domain: null_terminated_str(&event.domain).to_string(),
                    },
                });
            }
        }
        out
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
