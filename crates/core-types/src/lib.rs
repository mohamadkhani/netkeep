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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Ordinal precedence; higher = evaluated first when multiple rules match.
    /// Seeded at creation from the built-in restriction ladder
    /// (`policy_engine::seed_priority`) and refined by user reordering via
    /// midpoint insertion. Never shown or entered as a number in the UI.
    /// See the priority ladder (fractional rule priority).
    #[serde(default = "default_priority")]
    pub priority: f64,
}

fn default_priority() -> f64 {
    1.0
}

/// Creation-time choice for process-only rules (destination = `Any`).
///
/// A `process + Any` rule has no destination restriction, so the ladder
/// can't rank it by destination specificity. Instead the creator picks one
/// of two slots: `High` (base 7, the common case — "this process matters")
/// or `Low` (base 2, "background/telemetry process"). Rules created via the
/// plain `AddRule` request default to `High`. See the priority ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProcessPriority {
    /// Ladder base 7 — "this process matters" (default for plain `AddRule`).
    #[default]
    High,
    /// Ladder base 2 — "background/telemetry process".
    Low,
}

/// Provenance of `FlowContext::destination_domain`.
///
/// Only `Sni` and `Host` are *in-band* observations for this connection: the
/// name was read from the packet being classified. Everything else is a prior
/// or a hint, so it must never decide a TLS connection before the ClientHello
/// arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum DomainSource {
    /// No domain is known.
    #[default]
    None,
    /// TLS `server_name` extension in this packet's ClientHello.
    Sni,
    /// `Host:` header in this packet's plaintext HTTP request.
    Host,
    /// Learned from DNS or from a shared cache hit — a prior for the IP, not
    /// an observation for this connection.
    Dns,
    /// User-declared intent, e.g. `ssh user@host` from `/proc/<pid>/cmdline`.
    Cmdline,
}

impl DomainSource {
    /// Whether the name came from the packet being classified. In-band names
    /// may resolve a flow immediately; every other source is deferred until
    /// the ClientHello supplies the authoritative SNI.
    pub fn is_in_band(self) -> bool {
        matches!(self, DomainSource::Sni | DomainSource::Host)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProcessOrigin {
    /// No process could be proven for this socket. The flow may be anyone's.
    #[default]
    Unresolved,
    /// The resolver read the owning process from `/proc`.
    Proved,
    /// The socket has no user-space owner, and the scan that established this
    /// was complete (no permission errors): a kernel service owns it, such as
    /// the `nfsd` threads behind an NFS mount.
    Kernel,
}

/// A failure in the data path that the user has to see.
///
/// These used to exist only as `eprintln!` lines in the journal: a proxy that
/// could not be reached, an egress whose DNS servers failed, or a rule that
/// routed a lookup to an egress with no resolvers. The connection simply broke
/// and nothing said why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressAlert {
    pub kind: EgressAlertKind,
    /// Proxy or egress id the failure belongs to, when known.
    pub target_id: Option<String>,
    /// Human-readable detail: the error text, the domain, or the destination.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EgressAlertKind {
    /// The proxy could not be reached, or refused the connection.
    Unreachable,
    /// The proxy answered, but its DNS servers failed.
    DnsFailed,
    /// A rule sent this lookup to an egress with no DNS servers configured.
    NoResolver,
}

impl EgressAlertKind {
    /// Short label for the UI.
    pub fn label(self) -> &'static str {
        match self {
            EgressAlertKind::Unreachable => "proxy unreachable",
            EgressAlertKind::DnsFailed => "egress DNS failed",
            EgressAlertKind::NoResolver => "egress has no resolver",
        }
    }
}

/// Callback handed to the subsystems that can fail (transparent proxy, DNS
/// forwarder). Kept as a plain closure so those crates stay independent of the
/// control service.
pub type EgressAlertSink = std::sync::Arc<dyn Fn(EgressAlert) + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowContext {
    pub process_name: Option<String>,
    /// What the process lookup actually established. `process_name: None`
    /// alone cannot tell "the kernel owns this socket" from "the lookup
    /// failed", and those two need different handling: a kernel service has
    /// no app to ask about, while a failed lookup must never be allowed on a
    /// guess.
    #[serde(default)]
    pub process_origin: ProcessOrigin,
    /// Full executable path from `/proc/<pid>/exe` — the unique identity of
    /// the process binary, used for rule matching and stored in the DB.
    #[serde(default)]
    pub process_exe: Option<String>,
    /// User-facing app label resolved from the Arch Linux package database
    /// (`pacman -Qo <exe>`). Displayed alongside `process_name` in the dialog.
    #[serde(default)]
    pub app_name: Option<String>,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub destination_domain: Option<String>,
    /// Reverse-DNS name for `destination_ip`, when the packet gave no name of
    /// its own. A display hint only: it never takes part in rule matching,
    /// because the owner of the reverse zone can claim any name.
    #[serde(default)]
    pub reverse_dns: Option<String>,
    /// Where `destination_domain` came from. Defaults to `None` for rows and
    /// pending decisions written before provenance existed.
    #[serde(default)]
    pub domain_source: DomainSource,
    pub protocol: TransportProtocol,
    pub direction: FlowDirection,
    pub device_label: Option<String>,
    /// True when the classified packet was the TCP SYN (connection
    /// initiation). A SYN never carries a TLS ClientHello, so a flow
    /// classified on its SYN cannot know the destination hostname yet —
    /// used to defer pending decisions until SNI is available.
    #[serde(default)]
    pub tcp_syn: bool,
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
    /// Ephemeral source port of the flow's first classified packet.
    /// Identifies the exact local socket — the primary key for verifying
    /// process attribution in tests and diagnostics. Older rows (and any
    /// FlowContext-based producers without a socket) default to 0.
    #[serde(default)]
    pub source_port: u16,
    /// Destination port of the flow. Defaults to 0 for legacy rows.
    #[serde(default)]
    pub destination_port: u16,
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
