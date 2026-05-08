use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
    Ask,
    Route { target: RouteTarget },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RouteTarget {
    Tun(String),
    Device(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDuration {
    UntilRestart,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestinationMatcher {
    IpExact(String),
    Cidr(String),
    DomainExact(String),
    DomainWildcard(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub action: RuleAction,
    pub duration: RuleDuration,
    pub process_name: Option<String>,
    pub destination: DestinationMatcher,
    pub route_target: Option<RouteTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowContext {
    pub process_name: Option<String>,
    pub destination_ip: String,
    pub destination_port: u16,
    pub destination_domain: Option<String>,
    pub protocol: TransportProtocol,
    pub direction: FlowDirection,
    pub device_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDecision {
    pub id: String,
    pub flow: FlowContext,
    pub created_at_secs: u64,
    pub deadline_at_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Quic,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    Pending,
    Allowed,
    Denied,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowEvent {
    pub id: String,
    pub process_name: Option<String>,
    pub device_label: Option<String>,
    pub destination_ip: String,
    pub destination_domain: Option<String>,
    pub protocol: TransportProtocol,
    pub state: FlowState,
    pub timestamp_secs: u64,
}

// ---------------------------------------------------------------------------
// Egress — a named, color-coded exit point for routed traffic
// ---------------------------------------------------------------------------

/// An egress represents a named routing destination that traffic can be
/// sent through. Each egress binds to one or more network interfaces
/// (TUN devices, physical NICs, etc.). The special "default" egress
/// (empty targets) means "use the system routing table" (no special routing).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Egress {
    pub id: String,
    pub name: String,
    pub color: String,
    pub targets: Vec<RouteTarget>,
    /// Resolver IPs to use for this egress (e.g. ["1.1.1.1", "8.8.8.8"]).
    /// Empty means use system-default DNS behavior.
    pub dns_servers: Vec<String>,
    pub is_system_default: bool,
    /// Whether the underlying interface is currently up and usable.
    /// Unavailable egresses should still be shown (greyed out) so the user
    /// knows they exist, but traffic must not be routed through them.
    pub is_available: bool,
}

