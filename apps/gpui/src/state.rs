use core_types::{Egress, PendingDecision};

#[derive(Clone, Debug, PartialEq)]
pub enum ProcessScope {
    /// Rule applies to the specific process from the flow.
    Specific,
    /// Rule applies to all processes (process_name: None in rule).
    All,
}

/// How the destination field of the rule is scoped.
#[derive(Clone, Debug, PartialEq)]
pub enum DestScope {
    /// Exact subdomain match (domain flows only).
    DomainExact,
    /// Wildcard subdomain match — `*.apex` (domain flows only).
    DomainWildcard,
    /// No destination constraint — matches any destination.
    Any,
    /// CIDR prefix — active_octets (1..=4) determines the prefix length.
    /// 4 = /32 exact IP, 3 = /24, 2 = /16, 1 = /8.
    IpCidr(u8),
}

pub struct AppState {
    pub item: PendingDecision,
    pub now_secs: u64,
    pub make_permanent: bool,
    pub pending_count: usize,
    pub egresses: Vec<Egress>,
    pub selected_egress_index: usize,
    pub process_scope: ProcessScope,
    pub dest_scope: DestScope,
}
