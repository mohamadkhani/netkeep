use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
    Ask,
    /// Route traffic via the egress named by `Rule::egress_id`.
    /// The concrete `RouteTarget` is resolved at enforcement time from the
    /// egress's ordered target list — first available target wins.
    Route,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RouteTarget {
    Tun(String),
    Device(String),
    /// Route traffic through a managed proxy (references `ProxyConfig.id`).
    Proxy(String),
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
    /// Matches any destination — only valid when a process constraint is present.
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub action: RuleAction,
    pub duration: RuleDuration,
    pub process_name: Option<String>,
    /// Full path to the process executable (e.g. `/usr/bin/curl`). Used as
    /// the primary match key when present — more unique than basename alone
    /// and immune to comm-name truncation.
    #[serde(default)]
    pub process_exe: Option<String>,
    pub destination: DestinationMatcher,
    /// Set when `action == Route`. References an `Egress.id` stored in the
    /// daemon's state-store. The first available target of that egress is
    /// used at enforcement time; if the egress or all its targets are
    /// unavailable the packet is denied (fail-close).
    pub egress_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowContext {
    pub process_name: Option<String>,
    /// Full executable path from `/proc/<pid>/exe` — the unique identity of
    /// the process binary, used for rule matching and stored in the DB.
    #[serde(default)]
    pub process_exe: Option<String>,
    /// User-facing app label resolved from the Arch Linux package database
    /// (`pacman -Qo <exe>`). Displayed alongside `process_name` in the dialog.
    #[serde(default)]
    pub app_name: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

// ---------------------------------------------------------------------------
// Proxy — a remote proxy server that can be used as an egress target
// ---------------------------------------------------------------------------

/// Supported proxy protocols.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProxyProtocol {
    Socks5,
    Http,
    Shadowsocks,
}

/// Authentication configuration for a proxy connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProxyAuth {
    None,
    Basic { username: String, password: String },
    Shadowsocks { method: String, password: String },
}

/// A managed proxy server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub id: String,
    pub name: String,
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    pub auth: ProxyAuth,
    pub enabled: bool,
}

