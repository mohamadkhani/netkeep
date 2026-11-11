use clap::{Parser, Subcommand};

/// Parse destination matcher from a bare string.
///
/// * `any`           -> Any
/// * `*.domain`      -> DomainWildcard("domain")
/// * `10.0.0.0/8`    -> Cidr
/// * `1.1.1.1`       -> IpExact
/// * `example.com`   -> DomainExact
pub fn parse_destination(value: &str) -> Result<core_types::DestinationMatcher, String> {
    parse_destination_with_target(value, None)
}

/// Parse the `--target` option. Accepts either:
/// * `TYPE,VALUE` (e.g. `domain,example.com`)
/// * `TYPE=VALUE` (e.g. `domain=example.com`)
/// * `TYPE` alone as a flag when a positional DESTINATION is supplied
///
/// `--target any` needs no value.
fn parse_target_flag(s: &str) -> Result<(TargetType, Option<String>), String> {
    let (ty, val) = if let Some((t, v)) = s.split_once('=') {
        (t, Some(v.to_string()))
    } else if let Some((t, v)) = s.split_once(',') {
        (t, Some(v.to_string()))
    } else {
        (s, None)
    };
    let target_type = ty.parse::<TargetType>().map_err(|_| {
        format!("unknown target type '{ty}'; use ip, domain, cidr, wildcard, or any")
    })?;
    Ok((target_type, val))
}

/// Parse destination matcher with an explicit type override.
pub fn parse_destination_with_target(
    value: &str,
    target: Option<TargetType>,
) -> Result<core_types::DestinationMatcher, String> {
    match target {
        Some(TargetType::Any) => Ok(core_types::DestinationMatcher::Any),
        Some(TargetType::Ip) => Ok(core_types::DestinationMatcher::IpExact(value.to_string())),
        Some(TargetType::Domain) => Ok(core_types::DestinationMatcher::DomainExact(
            value.to_string(),
        )),
        Some(TargetType::Cidr) => Ok(core_types::DestinationMatcher::Cidr(value.to_string())),
        Some(TargetType::Wildcard) => {
            let rest = value.strip_prefix("*.").ok_or_else(|| {
                format!(
                    "--target wildcard requires value prefixed with `*.`: {}",
                    value
                )
            })?;
            Ok(core_types::DestinationMatcher::DomainWildcard(
                rest.to_string(),
            ))
        }
        None => {
            if value.eq_ignore_ascii_case("any") {
                return Ok(core_types::DestinationMatcher::Any);
            }
            if let Some(rest) = value.strip_prefix("*.") {
                return Ok(core_types::DestinationMatcher::DomainWildcard(
                    rest.to_string(),
                ));
            }
            if value.contains('/') {
                return Ok(core_types::DestinationMatcher::Cidr(value.to_string()));
            }
            if value.chars().all(|c| c.is_ascii_digit() || c == '.') && value.contains('.') {
                return Ok(core_types::DestinationMatcher::IpExact(value.to_string()));
            }
            Ok(core_types::DestinationMatcher::DomainExact(
                value.to_string(),
            ))
        }
    }
}

/// Resolve a destination matcher from an optional positional value plus an
/// optional `--target` override. With neither, the matcher is `Any`.
pub fn resolve_destination(
    value: Option<&str>,
    target: Option<&(TargetType, Option<String>)>,
) -> Result<core_types::DestinationMatcher, String> {
    if let Some((target_type, explicit_value)) = target {
        let value = explicit_value.as_deref().or(value);
        if matches!(target_type, TargetType::Any) {
            parse_destination_with_target(value.unwrap_or_default(), Some(*target_type))
        } else {
            let value = value.ok_or_else(|| {
                "missing destination value: provide a DESTINATION or --target TYPE,VALUE"
                    .to_string()
            })?;
            parse_destination_with_target(value, Some(*target_type))
        }
    } else if let Some(value) = value {
        parse_destination(value)
    } else {
        Ok(core_types::DestinationMatcher::Any)
    }
}

/// Top-level subcommands of the netkeep CLI.
#[derive(Subcommand)]
pub enum Command {
    /// Rule management
    Rule {
        #[command(subcommand)]
        action: RuleAction,
    },

    /// Shortcut: allow traffic to a destination and/or from a process.
    #[command(after_help = "\
Examples:
  netkeep-cli allow example.com
  netkeep-cli allow 10.0.0.0/8 --process docker
  netkeep-cli allow --process firefox --duration until-restart")]
    Allow(ShortcutArgs),

    /// Shortcut: deny traffic to a destination and/or from a process.
    #[command(after_help = "\
Examples:
  netkeep-cli deny ads.example.com
  netkeep-cli deny any --process tracker")]
    Deny(ShortcutArgs),

    /// Shortcut: route a destination and/or process through an egress.
    ///
    /// The egress may be given by id or by name.
    #[command(after_help = "\
Examples:
  netkeep-cli route example.com --via VPN
  netkeep-cli route --process qbittorrent --via eg-lan")]
    Route(RouteShortcutArgs),

    /// Pending (unresolved flows) management
    Pending {
        #[command(subcommand)]
        action: PendingAction,
    },

    /// Flow event inspection
    Flow {
        #[command(subcommand)]
        action: FlowAction,
    },

    /// Egress (network target / route target) management
    Egress {
        #[command(subcommand)]
        action: EgressAction,
    },

    /// Proxy management
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },

    /// NFQUEUE (packet interception) management
    Nfqueue {
        #[command(subcommand)]
        action: NfqueueAction,
    },

    /// Configuration / status
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Register an unknown flow from the command line.
    ///
    /// Used by the flow classifier / eBPF components to submit a flow for
    /// policy evaluation. Signature mirrors the legacy `register-flow`:
    /// `register-flow <process> <ip> <domain|-> <tcp|udp|quic|other> <now-secs>`.
    RegisterFlow {
        /// Process name or executable path.
        process: String,
        /// Destination IP address.
        ip: String,
        /// Destination domain, or `-` for none.
        domain: Option<String>,
        /// Transport protocol.
        protocol: Protocol,
        /// Flow start timestamp (seconds since epoch).
        now_secs: u64,
    },

    /// Open a routed TCP relay through an available egress target.
    OpenRoutedTcp {
        /// Host to connect to.
        host: String,
        /// Port to connect to.
        port: u16,
        /// Egress id or target name to route through.
        #[arg(long, short)]
        target: String,
    },
}

// ---------- Rule ----------

#[derive(Subcommand)]
pub enum RuleAction {
    /// Create a new firewall rule.
    Add(RuleAddArgs),

    /// Reorder a rule: move it so it is evaluated right before `before-id`
    /// (or at the bottom if `--before` is omitted) and after `after-id`
    /// (or at the top if `--after` is omitted). The daemon inserts the rule's
    /// priority as the midpoint between the surrounding rules.
    Move {
        /// ID of the rule to move.
        #[arg(short, long, help = "ID of the rule to move")]
        id: String,
        /// Move before this rule's ID (rule that follows in evaluation order).
        #[arg(long)]
        before: Option<String>,
        /// Move after this rule's ID (rule that precedes in evaluation order).
        #[arg(long)]
        after: Option<String>,
    },

    /// List all rules.
    List {
        /// Show only rules matching this process name.
        #[arg(long)]
        process: Option<String>,

        /// Filter rules by an exact rule id.
        #[arg(long, short = 'i')]
        id: Option<String>,

        /// Search text matched case-insensitively against all rule fields
        /// (id, process, destination, action, duration).
        #[arg(long)]
        search: Option<String>,

        /// Filter rules by action (allow | deny | ask | route).
        #[arg(long)]
        action: Option<String>,

        /// Filter rules by duration (until-restart | permanent).
        #[arg(long)]
        duration: Option<String>,
    },

    /// Delete a rule by ID.
    Delete {
        #[arg(short, long, help = "Unique rule identifier")]
        id: String,
        /// Confirm deletion (required to avoid accidents).
        #[arg(long, short = 'F', help = "Confirm the deletion")]
        force: bool,
    },
}

#[derive(Parser)]
pub struct RuleAddArgs {
    /// Unique rule identifier. Auto-generated if omitted.
    #[arg(short, long)]
    pub id: Option<String>,
    /// Destination matcher. Auto-detected from the value:
    /// `any` -> any destination, `*.domain` -> wildcard domain, `10.0.0.0/8` -> CIDR,
    /// `1.1.1.1` -> exact IP, anything else -> exact domain.
    pub destination: Option<String>,

    /// Destination type override: ip | domain | cidr | wildcard | any.
    /// Can be combined with the value: `--target domain,example.com` or
    /// `--target ip=192.168.1.1`. Leave unset to auto-detect the matcher type
    /// from the `--destination` / positional value.
    #[arg(long, value_parser = parse_target_flag)]
    pub target: Option<(TargetType, Option<String>)>,

    /// Action to take on matching traffic. One of: `allow`, `deny`, `ask`
    /// (prompt on the dashboard), or `route` (send traffic via --egress).
    #[arg(long, default_value = "allow")]
    pub action: String,

    /// How long the rule stays installed. One of: `until-restart` (session)
    /// or `permanent`. Defaults to `permanent`.
    #[arg(long, default_value = "permanent")]
    pub duration: String,

    /// Restrict this rule to a process name.
    #[arg(long)]
    pub process: Option<String>,

    /// Restrict this rule to a process executable path.
    #[arg(long, short = 'e')]
    pub process_exe: Option<String>,

    /// Restrict this rule to an egress (route target / proxy). Used with `--action route`.
    #[arg(long)]
    pub egress: Option<String>,
}

/// Arguments shared by the `allow` and `deny` shortcuts.
#[derive(Parser)]
pub struct ShortcutArgs {
    /// Destination to match. Auto-detected:
    /// `any` -> any destination, `*.domain` -> wildcard domain,
    /// `10.0.0.0/8` -> CIDR, `1.1.1.1` -> exact IP, anything else -> exact domain.
    /// Omit to match any destination (requires --process or --process-exe).
    pub destination: Option<String>,

    /// Destination type override: ip | domain | cidr | wildcard | any.
    #[arg(long, value_parser = parse_target_flag)]
    pub target: Option<(TargetType, Option<String>)>,

    /// Restrict the rule to this process name.
    #[arg(short, long)]
    pub process: Option<String>,

    /// Restrict the rule to this process executable path.
    #[arg(short = 'e', long)]
    pub process_exe: Option<String>,

    /// How long the rule stays installed: until-restart | permanent.
    #[arg(short = 'd', long, default_value = "permanent")]
    pub duration: String,

    /// Rule id (auto-generated if omitted).
    #[arg(short, long)]
    pub id: Option<String>,
}

/// Arguments for the `route` shortcut.
#[derive(Parser)]
pub struct RouteShortcutArgs {
    /// Destination to match. Auto-detected like `allow` / `deny`.
    /// Omit to match any destination (requires --process or --process-exe).
    pub destination: Option<String>,

    /// Destination type override: ip | domain | cidr | wildcard | any.
    #[arg(long, value_parser = parse_target_flag)]
    pub target: Option<(TargetType, Option<String>)>,

    /// Egress id or name to route traffic through.
    #[arg(short, long)]
    pub via: String,

    /// Restrict the rule to this process name.
    #[arg(short, long)]
    pub process: Option<String>,

    /// Restrict the rule to this process executable path.
    #[arg(short = 'e', long)]
    pub process_exe: Option<String>,

    /// How long the rule stays installed: until-restart | permanent.
    #[arg(short = 'd', long, default_value = "permanent")]
    pub duration: String,

    /// Rule id (auto-generated if omitted).
    #[arg(short, long)]
    pub id: Option<String>,
}

#[derive(Parser)]
pub struct RuleMoveArgs {
    #[arg(short, long, help = "Unique rule identifier")]
    id: String,
    #[arg(long)]
    before: Option<String>,
    #[arg(long)]
    after: Option<String>,
}

// ---------- Pending ----------

#[derive(Subcommand)]
pub enum PendingAction {
    /// List pending (waiting) decisions.
    List,

    /// Wait for a pending decision to be made. Blocks until the pending entry
    /// resolves or expires.
    Await {
        /// ID of the pending decision to wait for (defaults to the most recent).
        #[arg(short, long)]
        id: Option<String>,
        /// How many pending decisions to wait for (1 or more).
        #[arg(long, default_value = "1")]
        count: usize,
    },

    /// Resolve a pending decision with an immediate action.
    Resolve {
        /// ID of the pending decision.
        #[arg(short, long, help = "ID of the pending decision")]
        id: String,
        /// Action to apply.
        action: PendingActionValue,
    },

    /// Resolve a pending decision and install a rule in one request.
    ResolveWithRule {
        /// ID of the pending decision.
        #[arg(short, long, help = "ID of the pending decision")]
        id: String,
        /// Action to apply.
        action: PendingActionValue,
        /// Unique rule identifier.
        #[arg(long)]
        rule_id: String,
        /// Destination matcher for the rule.
        #[arg(long)]
        destination: String,
        /// Action for the rule (defaults to the resolve action).
        #[arg(long)]
        rule_action: Option<String>,
        /// How long the rule stays installed.
        #[arg(long, default_value = "permanent")]
        rule_duration: String,
        /// Restrict the rule to a process name.
        #[arg(long)]
        rule_process: Option<String>,
        /// Restrict the rule to an egress.
        #[arg(long)]
        rule_egress: Option<String>,
    },
}

#[derive(clap::ValueEnum, Clone)]
pub enum PendingActionValue {
    Allow,
    Deny,
    Ask,
}

// ---------- Flow ----------

#[derive(Subcommand)]
pub enum FlowAction {
    /// List recent flow events.
    List {
        /// Maximum number of events to show.
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Show events matching this process name.
        #[arg(long)]
        process: Option<String>,
    },
}

// ---------- Egress ----------

#[derive(Subcommand)]
pub enum EgressAction {
    /// List available egresses (route targets / proxies).
    List,

    /// Create or update an egress.
    Upsert {
        /// Egress ID.
        #[arg(short, long, help = "Egress ID")]
        id: String,
        /// Human-readable name.
        name: String,
        /// Whether this is the default egress.
        #[arg(long)]
        default: bool,
        /// Target addresses (comma-separated), e.g. `10.0.0.1:53,8.8.8.8:53`.
        #[arg(long, default_value = "")]
        targets: String,
        /// DNS servers to use for this egress (comma-separated), or `system`.
        #[arg(long, default_value = "system")]
        dns: String,
    },

    /// Delete an egress by ID.
    Delete {
        #[arg(short, long, help = "Egress ID to delete")]
        id: String,
        #[arg(long, short = 'F', help = "Confirm the deletion")]
        force: bool,
    },
}

// ---------- Proxy ----------
#[derive(Subcommand)]
pub enum ProxyAction {
    /// List configured proxies.
    List,

    /// Create or update a proxy.
    Upsert {
        /// Proxy ID.
        #[arg(short, long, help = "Proxy ID")]
        id: String,
        /// Human-readable name.
        name: String,
        /// Protocol: http, socks5, shadowsocks.
        #[arg(value_enum)]
        protocol: LocalProxyProtocol,
        /// Host and port, e.g. `127.0.0.1:1080`.
        host_port: String,
        /// Whether the proxy is enabled.
        #[arg(long, default_value = "true")]
        enabled: bool,
        /// Proxy authentication (none | basic <user>:<pass>).
        #[arg(long, default_value = "none")]
        auth: LocalProxyAuth,
    },

    /// Delete a proxy by ID.
    Delete {
        #[arg(short, long, help = "Proxy ID to delete")]
        id: String,
        #[arg(long, short = 'F', help = "Confirm the deletion")]
        force: bool,
    },

    /// Test HTTP connectivity through a proxy.
    TestHttp {
        /// Proxy ID.
        #[arg(short, long, help = "Proxy ID to test")]
        id: String,
        /// URL to test against.
        url: String,
    },

    /// Test DNS resolution through a proxy.
    TestDns {
        /// Proxy ID.
        #[arg(short, long, help = "Proxy ID to test")]
        id: String,
        /// Domain to resolve.
        domain: String,
    },
}

// ---------- NFQUEUE ----------

#[derive(Subcommand)]
pub enum NfqueueAction {
    /// Enable NFQUEUE packet interception.
    Enable {
        /// NFQUEUE number.
        #[arg(long, default_value = "1")]
        queue_num: u16,
    },

    /// Disable NFQUEUE packet interception.
    Disable,

    /// Show NFQUEUE status.
    Status,
}

// ---------- Config ----------

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show daemon configuration / health.
    Show,

    /// Unlock: remove any installed nftables rules (emergency recovery).
    Unlock,
}

// ---------- Protocol helpers ----------

#[derive(clap::ValueEnum, Clone)]
pub enum Protocol {
    Tcp,
    Udp,
    Quic,
    Other,
}

impl Protocol {
    pub fn into_transport(self) -> core_types::TransportProtocol {
        match self {
            Protocol::Tcp => core_types::TransportProtocol::Tcp,
            Protocol::Udp => core_types::TransportProtocol::Udp,
            Protocol::Quic => core_types::TransportProtocol::Quic,
            Protocol::Other => core_types::TransportProtocol::Other,
        }
    }
}

// ---------- clap value enums ----------

/// Destination matcher type for explicit rule targets.
#[derive(clap::ValueEnum, Clone, Copy)]
pub enum TargetType {
    /// Any destination (requires a process constraint).
    Any,
    /// Exact IP address match (e.g. `192.168.1.1`).
    Ip,
    /// Domain name match (e.g. `example.com`).
    Domain,
    /// CIDR network match (e.g. `10.0.0.0/8`).
    Cidr,
    /// Wildcard domain match (e.g. `*.example.com`).
    Wildcard,
}

impl std::str::FromStr for TargetType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "any" | "all" => Ok(TargetType::Any),
            "ip" => Ok(TargetType::Ip),
            "domain" => Ok(TargetType::Domain),
            "cidr" => Ok(TargetType::Cidr),
            "wildcard" => Ok(TargetType::Wildcard),
            other => Err(format!(
                "unknown target type '{other}'; use ip, domain, cidr, wildcard, or any"
            )),
        }
    }
}

/// Clap value enum for proxy protocol.
#[derive(clap::ValueEnum, Clone)]
pub enum LocalProxyProtocol {
    Http,
    Socks5,
    Shadowsocks,
}

/// Clap value enum for proxy auth.
#[derive(clap::ValueEnum, Clone, Copy)]
pub enum LocalProxyAuth {
    None,
    Basic,
}

#[derive(clap::ValueEnum, Clone, Copy)]
pub enum Duration {
    UntilRestart,
    Permanent,
}

impl std::str::FromStr for Duration {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "until-restart" | "session" => Ok(Duration::UntilRestart),
            "permanent" => Ok(Duration::Permanent),
            other => Err(format!(
                "unknown duration {other:?}; use until-restart or permanent"
            )),
        }
    }
}

impl From<Duration> for core_types::RuleDuration {
    fn from(d: Duration) -> Self {
        match d {
            Duration::UntilRestart => core_types::RuleDuration::UntilRestart,
            Duration::Permanent => core_types::RuleDuration::Permanent,
        }
    }
}
