pub mod forwarder;
pub mod sock_tracker;
mod tracker;

pub use forwarder::DnsForwarder;
pub use sock_tracker::{SockTracker, TrackedProcess};
pub use tracker::{DnsQueryInfo, DnsTracker};

/// Shared key layout mirroring crates/dns-tracker-ebpf/src/main.rs DnsKey.
/// Must stay ABI-compatible with the BPF program.
/// `unsafe impl Pod` is required by aya's BPF map API.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct DnsKey {
    pub src_ip4: u32,
    pub src_port: u16,
    pub _pad: u16,
}

// SAFETY: DnsKey is a POD type — all bit patterns are valid, no padding issues.
unsafe impl aya::Pod for DnsKey {}

/// Shared event layout mirroring crates/dns-tracker-ebpf/src/main.rs DnsEvent.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub pid: u32,
    pub comm: [u8; 16],
    pub domain: [u8; 256],
}

impl Default for DnsEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            comm: [0u8; 16],
            domain: [0u8; 256],
        }
    }
}

// SAFETY: DnsEvent is a POD type — all bit patterns are valid.
unsafe impl aya::Pod for DnsEvent {}
