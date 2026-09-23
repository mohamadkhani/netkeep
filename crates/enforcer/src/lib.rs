pub mod dns_snoop;
pub mod nfqueue;

use std::collections::HashMap;
use std::io::Write;
use std::process::Stdio;

use core_types::{FlowContext, RouteTarget, RuleAction};
use flow_classifier::{Classifier, RawPacket};

// ---------------------------------------------------------------------------
// Packet event — raw input from the network layer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PacketEvent {
    pub flow_id: String,
    pub raw: RawPacket,
}

// ---------------------------------------------------------------------------
// Verdict types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementVerdict {
    Allow,
    Deny,
    Route { target: RouteTarget },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedVerdict {
    pub flow_id: String,
    pub verdict: EnforcementVerdict,
    pub fwmark: Option<u32>,
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

pub trait VerdictSink {
    fn apply(&mut self, verdict: AppliedVerdict) -> Result<(), String>;
}

pub trait PacketSource {
    fn next_packet(&mut self) -> Option<PacketEvent>;
}

/// Decision returned by `FlowRegistrar` for a classified flow.
///
/// For `Immediate(Route, Some(target))` the NFQUEUE processor calls
/// `route_mark(&target)` and sets the fwmark before accepting the packet.
/// `route_target` is `None` for all non-Route actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowDecision {
    Immediate(RuleAction, Option<RouteTarget>),
    Pending {
        id: String,
        deadline_at_secs: u64,
    },
    /// Defer the decision to the next packet of the connection: the flow is
    /// an unknown TLS (TCP:443) connection classified on its SYN. A SYN
    /// carries no ClientHello, so the hostname is unknowable at this point —
    /// and a Pending verdict would DROP the SYN, blocking the handshake and
    /// making SNI forever unavailable. Accepting the bare handshake lets the
    /// ClientHello arrive; it is re-classified (pending verdicts are never
    /// cached) and either matches a rule by domain — no dialog at all — or
    /// opens the pending WITH the real hostname instead of a bare IP.
    /// No application payload flows before a real verdict: the ClientHello
    /// itself is the first gated packet.
    DeferSni,
}

/// Registers a classified flow and returns an immediate or pending decision.
/// Implemented by `ControlService` in the daemon.
pub trait FlowRegistrar {
    fn register(&mut self, flow: FlowContext, now_secs: u64) -> FlowDecision;
    /// Return (and lazily install) the fwmark for a route target.
    /// Used by the NFQUEUE processor to set the packet mark on routed verdicts
    /// so the kernel's policy routing tables steer the traffic correctly.
    fn route_mark(&mut self, target: &RouteTarget) -> Option<u32>;
}

// ---------------------------------------------------------------------------
// PacketProcessor — wires source → classifier → registrar → sink
// ---------------------------------------------------------------------------

pub struct PacketProcessor<PS, C, VS, FR> {
    source: PS,
    classifier: C,
    sink: VS,
    registrar: FR,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResult {
    pub flow_id: String,
    pub verdict: EnforcementVerdict,
    pub decision: FlowDecision,
}

impl<PS, C, VS, FR> PacketProcessor<PS, C, VS, FR>
where
    PS: PacketSource,
    C: Classifier,
    VS: VerdictSink,
    FR: FlowRegistrar,
{
    pub fn new(source: PS, classifier: C, sink: VS, registrar: FR) -> Self {
        Self {
            source,
            classifier,
            sink,
            registrar,
        }
    }

    /// Process one packet. Returns `None` when the source is exhausted.
    pub fn process_next(&mut self, now_secs: u64) -> Option<ProcessResult> {
        let event = self.source.next_packet()?;
        let flow = self.classifier.classify(&event.raw);
        let decision = self.registrar.register(flow, now_secs);

        let verdict = match &decision {
            FlowDecision::Immediate(RuleAction::Allow, _) => EnforcementVerdict::Allow,
            FlowDecision::Immediate(RuleAction::Route, Some(target)) => EnforcementVerdict::Route {
                target: target.clone(),
            },
            // Deferred-SNI handshake: no payload may flow until the ClientHello
            // is classified, but the bare connection setup passes.
            FlowDecision::DeferSni => EnforcementVerdict::Allow,
            // Route with no resolved target, Deny, Ask, or pending → drop (fail-close).
            FlowDecision::Immediate(RuleAction::Route, None)
            | FlowDecision::Immediate(RuleAction::Deny, _)
            | FlowDecision::Immediate(RuleAction::Ask, _)
            | FlowDecision::Pending { .. } => EnforcementVerdict::Deny,
        };

        let _ = self.sink.apply(AppliedVerdict {
            flow_id: event.flow_id.clone(),
            verdict: verdict.clone(),
            fwmark: None,
        });

        Some(ProcessResult {
            flow_id: event.flow_id,
            verdict,
            decision,
        })
    }
}

// ---------------------------------------------------------------------------
// Mark allocator (for routing verdicts)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MarkAllocator {
    next_mark: u32,
    marks_by_target: HashMap<RouteTarget, u32>,
}

impl MarkAllocator {
    pub fn new() -> Self {
        Self {
            next_mark: 1,
            marks_by_target: HashMap::new(),
        }
    }

    pub fn mark_for_target(&mut self, target: &RouteTarget) -> u32 {
        if let Some(mark) = self.marks_by_target.get(target) {
            *mark
        } else {
            let mark = self.next_mark;
            self.next_mark += 1;
            self.marks_by_target.insert(target.clone(), mark);
            mark
        }
    }
}

// ---------------------------------------------------------------------------
// DryRunEnforcer (used by daemon before nftables is available)
// ---------------------------------------------------------------------------

pub struct DryRunEnforcer<S: VerdictSink> {
    sink: S,
    allocator: MarkAllocator,
}

impl<S: VerdictSink> DryRunEnforcer<S> {
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            allocator: MarkAllocator::new(),
        }
    }

    pub fn apply_verdict(
        &mut self,
        flow_id: &str,
        verdict: EnforcementVerdict,
    ) -> Result<(), String> {
        let fwmark = match &verdict {
            EnforcementVerdict::Route { target } => Some(self.allocator.mark_for_target(target)),
            EnforcementVerdict::Allow | EnforcementVerdict::Deny => None,
        };
        self.sink.apply(AppliedVerdict {
            flow_id: flow_id.to_string(),
            verdict,
            fwmark,
        })
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }
}

// ---------------------------------------------------------------------------
// Nftables bootstrap — sets up/tears down the NFQUEUE interception rules
// ---------------------------------------------------------------------------

/// Base fwmark used by netkeep's policy-routing tables.
/// Packets carrying any mark in this range are daemon-originated relay
/// connections and must NOT be re-queued to NFQUEUE (would cause a deadlock
/// where the relay's own SYN is held pending a user decision).
pub const ROUTE_MARK_BASE: u32 = 20000;

/// Special fwmark for packets that should be redirected to the transparent
/// proxy. When the NFQUEUE verdict resolves a `RouteTarget::Proxy`, this mark
/// is stamped on the packet. A nftables REDIRECT rule in the nat hook then
/// sends the packet to the local transparent proxy port.
/// Must be below ROUTE_MARK_BASE so it's not caught by the relay bypass rules.
pub const PROXY_REDIRECT_MARK: u32 = ROUTE_MARK_BASE - 1;

/// Fwmark stamped on daemon-originated sockets (DNS forwarder, relay connects,
/// proxy connects) so nftables bypasses NFQUEUE for the daemon's own traffic.
/// Without this mark, the daemon's outbound packets are intercepted and
/// attributed to "netkeep-daemon" instead of the real application.
///
/// This mark is intentionally **not** in the `>= ROUTE_MARK_BASE` range so
/// that it does NOT trigger policy routing rules (`ip rule add fwmark N
/// lookup T`). The daemon's own connections should follow the system default
/// route, not be forced through a specific egress interface.
///
/// The nftables `output_early` chain has an explicit accept rule for this
/// exact mark value, placed before the `queue num N` rule.
pub const DAEMON_BYPASS_MARK: u32 = PROXY_REDIRECT_MARK - 1;

pub trait NftablesBootstrap: Send + Sync {
    /// Install the netkeep nftables table.
    ///
    /// * `queue_num` — when `Some(n)`, NFQUEUE rules are added so packets are
    ///   sent to userspace for classification.  When `None`, only the
    ///   route-mark protection chains are installed (no interception).
    /// * `route_mark_base` — marks at or above this value belong to netkeep
    ///   relay sockets and are preserved across other tools' marking chains
    ///   via conntrack mark save/restore.
    /// * `proxy_redirects` — list of `(fwmark, local_port)` pairs, one per
    ///   enabled proxy. Each entry generates a REDIRECT rule that sends packets
    ///   carrying that fwmark to the corresponding local transparent proxy port.
    fn setup(
        &self,
        queue_num: Option<u16>,
        route_mark_base: u32,
        proxy_redirects: &[(u32, u16)],
    ) -> Result<(), String>;
    fn teardown(&self) -> Result<(), String>;
}

pub struct SystemNftablesBootstrap;

impl NftablesBootstrap for SystemNftablesBootstrap {
    fn setup(
        &self,
        queue_num: Option<u16>,
        route_mark_base: u32,
        proxy_redirects: &[(u32, u16)],
    ) -> Result<(), String> {
        // Idempotent: tear down first, ignore errors (table may not exist yet).
        let _ = self.teardown();
        // Two-chain strategy to survive transparent-proxy tools (e.g. throne,
        // sing-box, clash) that mark packets in their filter chain (priority 0):
        //
        //  priority -150  output_early  ← we run first
        //                   • save relay mark into conntrack mark (ct mark)
        //                   • accept relay packets → skip NFQUEUE
        //                   • queue everything else to NFQUEUE
        //  priority -100                ← iptables nat OUTPUT (REDIRECT/DNAT)
        //  priority    0                ← proxy marks packet (e.g. 0x2023)
        //  priority  +10  output_late   ← we run last, AFTER the proxy
        //                   • if ct mark >= route_mark_base → restore it
        //                   • routing decision now sees our mark, not the proxy's
        //
        // accept in output_early does NOT prevent priority-0 chains from running;
        // it only prevents NFQUEUE re-queuing and the drop path.  The ct mark
        // survives across hook priorities (it's per-connection state), so we can
        // restore our SO_MARK after the proxy has overwritten the packet mark.
        //
        // Reroute strategy — three chains:
        //
        //   priority -150  output_early       (type route, has the NFQUEUE rule)
        //   priority -125  output_save_mark   (type filter)
        //   priority -100  output_reroute     (type route)
        //
        // The naive idea "put NFQUEUE in a type-route chain so the kernel does
        // ip_route_me_harder when userspace stamps a mark" does NOT work. The
        // kernel's route-chain hook fn (`nf_route_table_hook4`) only runs its
        // pre/post mark-change check when `nft_do_chain` returns NF_DROP/etc —
        // when the chain returns NF_QUEUE the function exits without comparing,
        // and after nf_reinject() the iteration resumes at the *next* chain, so
        // our route chain never sees the new mark. No reroute → packet exits
        // whichever interface the original (pre-mark) routing decision chose.
        //
        // Workaround: make the actual mark change happen *inside a later route
        // chain's* nft_do_chain. So after NFQUEUE, `output_save_mark` (filter)
        // copies meta mark → ct mark and clears meta mark. Then `output_reroute`
        // (route) restores meta mark from ct mark — its pre-mark is 0 and post-
        // mark is X, the kernel sees the change, and ip_route_me_harder fires.
        let mut script = String::new();
        script.push_str("add table inet netkeep\n");

        // Add a nat/output chain to bypass throne's TCP redirect for our marked traffic.
        // Throne uses "meta nfproto ipv4 meta l4proto tcp redirect to :37805" which
        // would otherwise redirect all our routed connections to its local proxy.
        // Throne's own rule checks: "meta mark 0x00002024 return" (bypass).
        // We set this bypass mark for our traffic going to physical devices (NOT throne-tun),
        // so throne skips the redirect, while also saving our routing mark for later restoration.
        // Use priority -199 to run BEFORE throne's "mangle" priority (-150).
        script.push_str(
            "add chain inet netkeep output_nat { type nat hook output priority -199; policy accept; }\n",
        );
        // Only bypass throne if output device is NOT throne-tun (i.e., physical NIC routing)
        script.push_str(&format!(
            "add rule inet netkeep output_nat meta mark >= {route_mark_base} oifname != \"throne-tun\" ct mark set meta mark meta mark set 0x2024 return\n",
        ));

        script.push_str(
            "add chain inet netkeep output_early { type route hook output priority -150; policy accept; }\n",
        );
        // Accept packets already carrying a routing mark (set by a previous NFQUEUE verdict
        // or by our relay sockets). The mark was saved to ct mark by output_nat the first
        // time the packet traversed that chain; restore it here so policy routing is stable.
        script.push_str(&format!(
            "add rule inet netkeep output_early ct mark >= {route_mark_base} meta mark set ct mark accept\n",
        ));
        // Save fwmark to ct mark when a routed packet first passes through this chain
        // (output_nat already ran and saw meta mark=0 before NFQUEUE set it, so we
        // must save it here on the accept-with-mark path). Subsequent packets then
        // hit the ct mark rule above and bypass NFQUEUE entirely.
        script.push_str(&format!(
            "add rule inet netkeep output_early meta mark >= {route_mark_base} ct mark set meta mark accept\n",
        ));
        if let Some(q) = queue_num {
            // Exclude loopback traffic: skip both the loopback interface and the
            // 127.0.0.0/8 address range (defense-in-depth; the Rust processor also
            // filters loopback as a second layer).
            script.push_str(&format!(
                "add rule inet netkeep output_early oifname \"lo\" accept\n",
            ));
            script.push_str(&format!(
                "add rule inet netkeep output_early ip daddr 127.0.0.0/8 accept\n",
            ));
            script.push_str(&format!(
                "add rule inet netkeep output_early ip6 daddr ::1 accept\n",
            ));
            // IPv4-mapped loopback (::ffff:127.0.0.0/8) — not matched by `ip daddr` or `::1`.
            script.push_str(
                "add rule inet netkeep output_early ip6 daddr ::ffff:7f00:0000/104 accept\n",
            );
            // DNS queries must bypass NFQUEUE. If queued, they appear as flows to the DNS
            // server IP (not the actual destination) and block name resolution entirely,
            // preventing any domain from being reached.
            script.push_str("add rule inet netkeep output_early udp dport 53 accept\n");
            script.push_str("add rule inet netkeep output_early tcp dport 53 accept\n");
            // ICMP and ICMPv6 must bypass NFQUEUE. These are layer-3 control
            // protocols with no TCP/UDP port — the process resolver cannot match
            // them to a user process. ICMPv6 also includes NDP (types 133–137)
            // which the kernel generates autonomously; queuing it would produce
            // spurious "unknown process" dialogs and blocking it would break IPv6
            // neighbor discovery entirely.
            script.push_str("add rule inet netkeep output_early meta l4proto icmp accept\n");
            script.push_str("add rule inet netkeep output_early meta l4proto icmpv6 accept\n");
            // Proxy-routed packets carry a per-proxy fwmark (below route_mark_base).
            // Accept them without re-queuing so follow-on segments are not dropped.
            for (mark, _port) in proxy_redirects {
                script.push_str(&format!(
                    "add rule inet netkeep output_early meta mark {mark} accept\n",
                ));
            }
            // Also accept the legacy single PROXY_REDIRECT_MARK for backwards compat.
            script.push_str(&format!(
                "add rule inet netkeep output_early meta mark {PROXY_REDIRECT_MARK} accept\n",
            ));
            // Daemon bypass mark — stamped on daemon-originated sockets (DNS
            // forwarder, relay connects, proxy connects) so they skip NFQUEUE.
            // Without this, the daemon's own traffic is intercepted and
            // attributed to "netkeep-daemon" instead of the real application.
            // Uses a dedicated mark (not >= route_mark_base) to avoid triggering
            // policy routing rules — the daemon's own connections follow the
            // system default route.
            script.push_str(&format!(
                "add rule inet netkeep output_early meta mark {DAEMON_BYPASS_MARK} accept\n",
            ));
            script.push_str(&format!(
                "add rule inet netkeep output_early queue num {q}\n",
            ));
        }

        // Stage 2 of the reroute dance — see the comment above output_early.
        // Save NFQUEUE-stamped (or relay SO_MARK-stamped) meta mark into ct mark
        // and clear meta mark. With meta mark = 0 at the entry of the next
        // chain, the kernel's mark-change comparison will detect a real change
        // when output_reroute restores it.
        //
        // Why a separate chain (not just a few more rules in output_early): the
        // NFQUEUE rule terminates the chain via NF_QUEUE, and after nf_reinject
        // continues iteration at the *next* hook entry — anything we add below
        // `queue num q` in output_early never executes for queued packets.
        script.push_str(
            "add chain inet netkeep output_save_mark { type filter hook output priority -125; policy accept; }\n",
        );
        script.push_str(&format!(
            "add rule inet netkeep output_save_mark meta mark >= {route_mark_base} ct mark set meta mark meta mark set 0\n",
        ));

        // Stage 3 of the reroute dance — restore meta mark from ct mark inside
        // a route-type chain. The kernel captures `mark = skb->mark` (= 0,
        // freshly cleared) before nft_do_chain and compares it to the post-
        // chain value (= X, just restored). Detecting that change triggers
        // ip_route_me_harder(state->net, sk, skb, RTN_UNSPEC), which re-does
        // the route lookup with the new mark — finally putting the packet on
        // the right egress interface for our fwmark policy rule.
        script.push_str(
            "add chain inet netkeep output_reroute { type route hook output priority -100; policy accept; }\n",
        );
        script.push_str(&format!(
            "add rule inet netkeep output_reroute ct mark >= {route_mark_base} meta mark set ct mark\n",
        ));

        if let Some(q) = queue_num {
            script.push_str(
                "add chain inet netkeep forward { type filter hook forward priority 0; policy accept; }\n",
            );
            // Exclude loopback from forward chain
            script.push_str("add rule inet netkeep forward oifname \"lo\" accept\n");
            script.push_str(&format!(
                "add rule inet netkeep forward ip daddr 127.0.0.0/8 accept\n",
            ));
            script.push_str(&format!(
                "add rule inet netkeep forward ip6 daddr ::1 accept\n",
            ));
            script.push_str(
                "add rule inet netkeep forward ip6 daddr ::ffff:7f00:0000/104 accept\n",
            );
            script.push_str("add rule inet netkeep forward meta l4proto icmp accept\n");
            script.push_str("add rule inet netkeep forward meta l4proto icmpv6 accept\n");
            script.push_str(&format!("add rule inet netkeep forward queue num {q}\n",));

            // INPUT chain: passively snoop DNS responses (UDP src_port 53) on a
            // second NFQUEUE queue (queue_num + 1) with `bypass` so that if the
            // DnsSnoopWorker is not running, DNS responses pass through unaffected.
            if let Some(dns_q) = q.checked_add(1) {
                script.push_str(
                    "add chain inet netkeep input_dns { type filter hook input priority 0; policy accept; }\n",
                );
                script.push_str(&format!(
                    "add rule inet netkeep input_dns udp sport 53 queue num {dns_q} bypass\n",
                ));
            }
        }

        // POSTROUTING masquerade — rewrite source address to match the
        // egress interface chosen by our fwmark-based policy routing.
        //
        // Why this is necessary: when the NFQUEUE verdict in output_early
        // (`type route`) stamps a fwmark on the SYN, the kernel reruns the
        // route lookup but does NOT redo source-address selection. So a
        // packet that the kernel originally bound to (say) the VPN's source
        // 10.x.x.x can end up leaving via enp3s0 with that same VPN source
        // IP. Most ISPs drop such packets (BCP 38 / source-address
        // validation), and even when they don't, return traffic arrives via
        // the VPN — producing asymmetric routing and timeouts.
        //
        // Masquerade fixes this by rewriting the source IP at POSTROUTING
        // to the primary IP of the actual outgoing interface. Conntrack
        // reverses it on the inbound path so the application's socket
        // (still nominally bound to the original source) receives replies
        // transparently.
        //
        // Two rules — one each for meta mark and ct mark — because:
        //   * NFQUEUE-stamped packets carry the mark in `meta mark`.
        //   * Relay-path packets had `output_nat` (priority -199) overwrite
        //     `meta mark` with 0x2024 (the throne-bypass cookie) and saved
        //     the original into `ct mark`. We must match either.
        script.push_str(
            "add chain inet netkeep postrouting { type nat hook postrouting priority 100; policy accept; }\n",
        );
        script.push_str(&format!(
            "add rule inet netkeep postrouting meta mark >= {route_mark_base} oifname != \"lo\" masquerade\n",
        ));
        script.push_str(&format!(
            "add rule inet netkeep postrouting ct mark >= {route_mark_base} oifname != \"lo\" masquerade\n",
        ));

        // Per-proxy REDIRECT rules — each proxy has its own fwmark and local port.
        // Packets carrying a proxy fwmark are redirected to the corresponding
        // transparent proxy port. The proxy reads the original destination via
        // SO_ORIGINAL_DST and tunnels through SOCKS/HTTP.
        if !proxy_redirects.is_empty() {
            script.push_str(
                "add chain inet netkeep output_proxy_redirect { type nat hook output priority -50; policy accept; }\n",
            );
            for (mark, port) in proxy_redirects {
                script.push_str(&format!(
                    "add rule inet netkeep output_proxy_redirect meta mark {mark} meta l4proto tcp redirect to :{port}\n",
                ));
            }
        }

        run_nft_script(&script)
    }

    fn teardown(&self) -> Result<(), String> {
        run_nft_script("delete table inet netkeep\n")
    }
}

fn run_nft_script(script: &str) -> Result<(), String> {
    let mut child = std::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn nft: {e}"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("nft stdin write: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("nft wait: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("nft exited with {status}"))
    }
}

// ---------------------------------------------------------------------------
// Route manager — manages ip-rule/ip-route entries for marked packets
// ---------------------------------------------------------------------------

/// Manages policy routing rules so that packets marked with a specific fwmark
/// are routed through the designated interface (TUN device or physical NIC).
///
/// For each `RouteTarget`, a unique fwmark is allocated via `MarkAllocator`,
/// then:
///   - `ip rule add fwmark <mark> table <table_id>`
///   - `ip route add default dev <device> table <table_id>`
///
/// Table IDs start at 10000 + mark to avoid collisions with standard tables.
pub trait RouteManager: Send + Sync {
    /// Add a routing rule for the given target (idempotent).
    fn add_route(&self, target: &RouteTarget, fwmark: u32) -> Result<(), String>;
    /// Remove a routing rule for the given target.
    fn remove_route(&self, target: &RouteTarget, fwmark: u32) -> Result<(), String>;
    /// Remove all managed routes.
    fn remove_all(&self) -> Result<(), String>;
}

pub struct SystemRouteManager {
    /// Tracks which (target, fwmark) pairs have been installed.
    installed: std::sync::Mutex<Vec<(RouteTarget, u32)>>,
}

impl SystemRouteManager {
    pub fn new() -> Self {
        Self {
            installed: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Default for SystemRouteManager {
    fn default() -> Self {
        Self::new()
    }
}

fn device_name(target: &RouteTarget) -> &str {
    match target {
        RouteTarget::Tun(name) | RouteTarget::Device(name) => name,
        RouteTarget::Proxy(id) => id, // proxy config id — no device name
    }
}

fn default_gateway_for_device(dev: &str) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default", "dev", dev])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|p| *p == "via") {
            if let Some(via) = parts.get(idx + 1) {
                return Some((*via).to_string());
            }
        }
    }
    None
}

/// Parse `ip -o addr show dev <dev>` output into global-scope network prefixes.
/// Returns one `addr/len` entry per global v4/v6 address; link-local and
/// host-scope addresses are skipped (they never need a policy-route entry).
///
/// `ip -o addr` prints the interface *address* (e.g. `192.168.7.6/24`), which
/// is not a valid route prefix when host bits are set — `ip route` rejects
/// `192.168.7.6/24` with "Invalid prefix for given prefix length" — so the
/// address is masked down to its network (e.g. `192.168.7.0/24`).
fn parse_connected_prefixes(output: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // "2: wlan0 inet 192.168.7.6/24 brd ... scope global dynamic ..."
        if parts.len() < 4 || (parts[2] != "inet" && parts[2] != "inet6") {
            continue;
        }
        let is_global = parts
            .windows(2)
            .any(|w| w[0] == "scope" && w[1] == "global");
        if !is_global {
            continue;
        }
        if let Some(prefix) = mask_cidr_host_bits(parts[3]) {
            prefixes.push(prefix);
        }
    }
    prefixes
}

/// Mask the host bits of an `addr/len` CIDR down to the network prefix.
fn mask_cidr_host_bits(cidr: &str) -> Option<String> {
    let (addr, len) = cidr.split_once('/')?;
    let len: u32 = len.parse().ok()?;
    if addr.contains(':') {
        let addr = addr.parse::<std::net::Ipv6Addr>().ok()?;
        if len > 128 {
            return None;
        }
        let mask = if len == 0 {
            0
        } else {
            u128::MAX << (128 - len)
        };
        Some(format!("{}/{}", std::net::Ipv6Addr::from(u128::from(addr) & mask), len))
    } else {
        let addr = addr.parse::<std::net::Ipv4Addr>().ok()?;
        if len > 32 {
            return None;
        }
        let mask = if len == 0 {
            0
        } else {
            u32::MAX << (32 - len)
        };
        Some(format!("{}/{}", std::net::Ipv4Addr::from(u32::from(addr) & mask), len))
    }
}

fn connected_prefixes_for_device(dev: &str) -> Vec<String> {
    let output = match std::process::Command::new("ip")
        .args(["-o", "addr", "show", "dev", dev])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => return Vec::new(),
    };
    parse_connected_prefixes(&output)
}

impl RouteManager for SystemRouteManager {
    fn add_route(&self, target: &RouteTarget, fwmark: u32) -> Result<(), String> {
        let table_id = 10000 + fwmark as u32;
        let dev = device_name(target);
        let fwmark_s = fwmark.to_string();
        let table_s = table_id.to_string();

        // Fail-closed fallback lives INSIDE the lookup table at high metric,
        // so the kernel uses it whenever the primary route below is missing
        // or unusable. This avoids the policy-rule pref ordering trap (a
        // per-rule unreachable at a fixed pref easily ends up firing BEFORE
        // the lookup rule, dropping every marked packet) — and it keeps the
        // failure boundary inside one routing table instead of fanning out
        // into the global rule list. Without this, an empty/broken table
        // would fall through to `main` where a VPN's poisoned routes can
        // silently exit the wrong interface.
        run_ip(&[
            "route",
            "replace",
            "unreachable",
            "default",
            "table",
            &table_s,
            "metric",
            "1000",
        ])?;

        // Install the lookup rule. Clear any stale duplicate first.
        run_ip(&["rule", "del", "fwmark", &fwmark_s, "lookup", &table_s]).ok();
        if let Err(e) = run_ip(&["rule", "add", "fwmark", &fwmark_s, "lookup", &table_s]) {
            run_ip(&["route", "flush", "table", &table_s]).ok();
            return Err(format!("install lookup rule failed: {e}"));
        }

        // Install primary route. If this fails the in-table unreachable
        // remains, so the kernel returns EHOSTUNREACH for this mark instead
        // of falling through to `main`.
        let route_result = match target {
            RouteTarget::Device(_) => {
                if let Some(gateway) = default_gateway_for_device(dev) {
                    run_ip(&[
                        "route", "replace", "default", "via", &gateway, "dev", dev, "table",
                        &table_s, "metric", "100",
                    ])
                } else {
                    run_ip(&[
                        "route", "replace", "default", "dev", dev, "table", &table_s, "metric",
                        "100",
                    ])
                }
            }
            RouteTarget::Tun(_) => run_ip(&[
                "route", "replace", "default", "dev", dev, "table", &table_s, "metric", "100",
            ]),
            RouteTarget::Proxy(_) => {
                // Proxy routing is handled at the application layer,
                // not via policy routing tables. No ip-route manipulation needed.
                Ok(())
            }
        };

        if let Err(e) = route_result {
            return Err(format!("install primary route for {target:?} failed: {e}"));
        }

        // Keep on-link destinations on the egress device itself. Without this
        // the table's only entry is the `default` route, so marked traffic to
        // a host on the device's own subnet hairpins through the gateway —
        // which many routers drop — instead of taking the connected route the
        // unmarked path uses. Longest-prefix match makes these win over the
        // default regardless of metric.
        if let RouteTarget::Device(_) = target {
            for prefix in connected_prefixes_for_device(dev) {
                let mut args: Vec<&str> = Vec::new();
                if prefix.contains(':') {
                    args.push("-6");
                }
                args.extend([
                    "route",
                    "replace",
                    &prefix,
                    "dev",
                    dev,
                    "table",
                    &table_s,
                    "metric",
                    "50",
                ]);
                run_ip(&args)?;
            }
        }

        let mut installed = self.installed.lock().map_err(|e| e.to_string())?;
        if !installed.iter().any(|(t, m)| t == target && *m == fwmark) {
            installed.push((target.clone(), fwmark));
        }
        Ok(())
    }

    fn remove_route(&self, target: &RouteTarget, fwmark: u32) -> Result<(), String> {
        let table_id = 10000 + fwmark as u32;
        let fwmark_s = fwmark.to_string();
        let table_s = table_id.to_string();
        run_ip(&["route", "flush", "table", &table_s]).ok();
        run_ip(&["rule", "del", "fwmark", &fwmark_s, "lookup", &table_s]).ok();
        // Best-effort cleanup of a per-rule unreachable left over from an
        // earlier netkeep version that installed it as a separate rule.
        run_ip(&["rule", "del", "fwmark", &fwmark_s, "type", "unreachable"]).ok();

        let mut installed = self.installed.lock().map_err(|e| e.to_string())?;
        installed.retain(|(t, m)| !(t == target && *m == fwmark));
        Ok(())
    }

    fn remove_all(&self) -> Result<(), String> {
        let pairs: Vec<(RouteTarget, u32)> = {
            let installed = self.installed.lock().map_err(|e| e.to_string())?;
            installed.clone()
        };
        for (target, fwmark) in &pairs {
            self.remove_route(target, *fwmark)?;
        }
        Ok(())
    }
}

fn run_ip(args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new("ip")
        .args(args)
        .status()
        .map_err(|e| format!("failed to run ip {:?}: {e}", args))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("ip {:?} exited with {status}", args))
    }
}

// ---------------------------------------------------------------------------
// Test fakes (pub so downstream crates can use them too)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct FakeBootstrap {
    pub setup_count: std::sync::atomic::AtomicU32,
    pub teardown_count: std::sync::atomic::AtomicU32,
    pub fail: bool,
}

impl FakeBootstrap {
    pub fn setup_count(&self) -> u32 {
        self.setup_count.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn teardown_count(&self) -> u32 {
        self.teardown_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl NftablesBootstrap for FakeBootstrap {
    fn setup(
        &self,
        _queue_num: Option<u16>,
        _route_mark_base: u32,
        _proxy_redirects: &[(u32, u16)],
    ) -> Result<(), String> {
        self.setup_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail {
            Err("fake setup failure".to_string())
        } else {
            Ok(())
        }
    }
    fn teardown(&self) -> Result<(), String> {
        self.teardown_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail {
            Err("fake teardown failure".to_string())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
pub struct RecordingSink {
    pub applied: Vec<AppliedVerdict>,
}

impl VerdictSink for RecordingSink {
    fn apply(&mut self, verdict: AppliedVerdict) -> Result<(), String> {
        self.applied.push(verdict);
        Ok(())
    }
}

pub struct FakePacketSource {
    pub packets: Vec<PacketEvent>,
}

impl FakePacketSource {
    pub fn new(packets: Vec<PacketEvent>) -> Self {
        Self { packets }
    }
}

impl PacketSource for FakePacketSource {
    fn next_packet(&mut self) -> Option<PacketEvent> {
        if self.packets.is_empty() {
            None
        } else {
            Some(self.packets.remove(0))
        }
    }
}

pub struct FakeFlowRegistrar {
    pub decisions: Vec<FlowDecision>,
}

impl FakeFlowRegistrar {
    pub fn new(decisions: Vec<FlowDecision>) -> Self {
        Self { decisions }
    }
}

impl FlowRegistrar for FakeFlowRegistrar {
    fn register(&mut self, _flow: FlowContext, _now_secs: u64) -> FlowDecision {
        if self.decisions.is_empty() {
            FlowDecision::Immediate(RuleAction::Deny, None)
        } else {
            self.decisions.remove(0)
        }
    }

    fn route_mark(&mut self, _target: &RouteTarget) -> Option<u32> {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{FlowDirection, TransportProtocol};
    use flow_classifier::{FakeClassifier, RawPacket};

    fn raw_packet() -> RawPacket {
        RawPacket {
            src_ip: "10.0.0.1".to_string(),
            src_port: 12345,
            dst_ip: "1.1.1.1".to_string(),
            dst_port: 443,
            protocol: TransportProtocol::Tcp,
            sni_hint: None,
            ingress_interface: None,
            tcp_payload_empty: false,
            tcp_fin: false,
            tcp_rst: false,
            tcp_syn: false,
            sk_uid: None,
            forwarded: false,
        }
    }

    fn classified_flow() -> FlowContext {
        FlowContext {
            process_name: Some("curl".to_string()),
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: Some("example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
            tcp_syn: false,
        }
    }

    fn event(id: &str) -> PacketEvent {
        PacketEvent {
            flow_id: id.to_string(),
            raw: raw_packet(),
        }
    }

    fn processor(
        events: Vec<PacketEvent>,
        decisions: Vec<FlowDecision>,
    ) -> PacketProcessor<FakePacketSource, FakeClassifier, RecordingSink, FakeFlowRegistrar> {
        PacketProcessor::new(
            FakePacketSource::new(events),
            FakeClassifier {
                result: classified_flow(),
            },
            RecordingSink::default(),
            FakeFlowRegistrar::new(decisions),
        )
    }

    #[test]
    fn allow_rule_applies_allow_verdict() {
        let mut p = processor(
            vec![event("f1")],
            vec![FlowDecision::Immediate(RuleAction::Allow, None)],
        );
        let result = p.process_next(1000).expect("result");
        assert_eq!(result.verdict, EnforcementVerdict::Allow);
        assert_eq!(result.flow_id, "f1");
    }

    #[test]
    fn deny_rule_applies_deny_verdict() {
        let mut p = processor(
            vec![event("f2")],
            vec![FlowDecision::Immediate(RuleAction::Deny, None)],
        );
        let result = p.process_next(1000).expect("result");
        assert_eq!(result.verdict, EnforcementVerdict::Deny);
    }

    #[test]
    fn unknown_flow_creates_pending_and_drops_packet() {
        let mut p = processor(
            vec![event("f3")],
            vec![FlowDecision::Pending {
                id: "p1".to_string(),
                deadline_at_secs: 1100,
            }],
        );
        let result = p.process_next(1000).expect("result");
        assert_eq!(result.verdict, EnforcementVerdict::Deny);
        assert!(matches!(result.decision, FlowDecision::Pending { .. }));
    }

    #[test]
    fn exhausted_source_returns_none() {
        let mut p = processor(vec![], vec![]);
        assert!(p.process_next(1000).is_none());
    }

    #[test]
    fn sink_receives_verdict_with_correct_flow_id() {
        let mut p = processor(
            vec![event("f4")],
            vec![FlowDecision::Immediate(RuleAction::Allow, None)],
        );
        p.process_next(1000);
        assert_eq!(p.sink.applied.len(), 1);
        assert_eq!(p.sink.applied[0].flow_id, "f4");
        assert_eq!(p.sink.applied[0].verdict, EnforcementVerdict::Allow);
    }

    // --- DryRunEnforcer / MarkAllocator tests (kept from previous iteration) ---

    #[test]
    fn deny_verdict_has_no_mark() {
        let mut enforcer = DryRunEnforcer::new(RecordingSink::default());
        enforcer
            .apply_verdict("f1", EnforcementVerdict::Deny)
            .expect("apply");
        assert_eq!(enforcer.sink_mut().applied[0].fwmark, None);
    }

    #[test]
    fn route_verdict_assigns_stable_mark_per_target() {
        let mut enforcer = DryRunEnforcer::new(RecordingSink::default());
        let target = RouteTarget::Tun("tun0".to_string());
        enforcer
            .apply_verdict(
                "f1",
                EnforcementVerdict::Route {
                    target: target.clone(),
                },
            )
            .expect("apply");
        enforcer
            .apply_verdict(
                "f2",
                EnforcementVerdict::Route {
                    target: target.clone(),
                },
            )
            .expect("apply");
        let m1 = enforcer.sink_mut().applied[0].fwmark.expect("mark1");
        let m2 = enforcer.sink_mut().applied[1].fwmark.expect("mark2");
        assert_eq!(m1, m2);
    }

    #[test]
    fn different_targets_get_different_marks() {
        let mut enforcer = DryRunEnforcer::new(RecordingSink::default());
        enforcer
            .apply_verdict(
                "f1",
                EnforcementVerdict::Route {
                    target: RouteTarget::Tun("tun0".to_string()),
                },
            )
            .expect("apply");
        enforcer
            .apply_verdict(
                "f2",
                EnforcementVerdict::Route {
                    target: RouteTarget::Device("eth1".to_string()),
                },
            )
            .expect("apply");
        let m1 = enforcer.sink_mut().applied[0].fwmark.expect("mark1");
        let m2 = enforcer.sink_mut().applied[1].fwmark.expect("mark2");
        assert_ne!(m1, m2);
    }

    // --- NftablesBootstrap tests ---

    #[test]
    fn fake_bootstrap_setup_records_call() {
        let b = FakeBootstrap::default();
        assert!(b.setup(Some(0), ROUTE_MARK_BASE, &[]).is_ok());
        assert_eq!(b.setup_count(), 1);
        assert_eq!(b.teardown_count(), 0);
    }

    #[test]
    fn fake_bootstrap_teardown_records_call() {
        let b = FakeBootstrap::default();
        assert!(b.teardown().is_ok());
        assert_eq!(b.teardown_count(), 1);
    }

    #[test]
    fn fake_bootstrap_propagates_failure() {
        let b = FakeBootstrap {
            fail: true,
            ..Default::default()
        };
        assert!(b.setup(Some(0), ROUTE_MARK_BASE, &[]).is_err());
        assert!(b.teardown().is_err());
    }

    #[test]
    fn route_verdict_in_packet_processor() {
        let target = RouteTarget::Tun("tun0".to_string());
        let mut p = processor(
            vec![event("f-route")],
            vec![FlowDecision::Immediate(
                RuleAction::Route,
                Some(target.clone()),
            )],
        );
        let result = p.process_next(1000).expect("result");
        assert_eq!(result.verdict, EnforcementVerdict::Route { target });
        assert_eq!(result.flow_id, "f-route");
    }

    #[test]
    fn parse_connected_prefixes_keeps_global_skips_link_local() {
        let output = "2: wlan0    inet 192.168.7.6/24 brd 192.168.7.255 scope global dynamic wlan0\\       valid_lft 83871sec preferred_lft 83871sec\n\
                      2: wlan0    inet6 fe80::1e2b:31ff:fe4f:9c32/64 scope link \n\
                      2: wlan0    inet6 fd00::6/64 scope global dynamic mngtmpaddr noprefixroute wlan0\\       valid_lft 1784sec preferred_lft 1784sec\n";
        assert_eq!(
            parse_connected_prefixes(output),
            vec!["192.168.7.0/24".to_string(), "fd00::/64".to_string()]
        );
    }

    #[test]
    fn parse_connected_prefixes_skips_host_scope_and_malformed_lines() {
        let output = "3: utun420    inet 10.255.255.2/32 scope host utun420\n\
                      3: utun420    inet6 fe80::1/64 scope link stable-privacy\n\
                      not-an-addr-line\n";
        assert!(parse_connected_prefixes(output).is_empty());
    }

    #[test]
    fn mask_cidr_host_bits_masks_to_network() {
        assert_eq!(
            mask_cidr_host_bits("192.168.7.6/24").as_deref(),
            Some("192.168.7.0/24")
        );
        assert_eq!(
            mask_cidr_host_bits("fd00::6/64").as_deref(),
            Some("fd00::/64")
        );
        assert_eq!(
            mask_cidr_host_bits("10.255.255.2/32").as_deref(),
            Some("10.255.255.2/32")
        );
        assert_eq!(mask_cidr_host_bits("1.2.3.4/0").as_deref(), Some("0.0.0.0/0"));
        assert_eq!(mask_cidr_host_bits("no-slash"), None);
        assert_eq!(mask_cidr_host_bits("1.2.3.4/33"), None);
        assert_eq!(mask_cidr_host_bits("::1/129"), None);
    }
}

// ---------------------------------------------------------------------------
// FakeRouteManager (for tests in downstream crates)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct FakeRouteManager {
    pub routes: std::sync::Mutex<Vec<(RouteTarget, u32)>>,
}

impl RouteManager for FakeRouteManager {
    fn add_route(&self, target: &RouteTarget, fwmark: u32) -> Result<(), String> {
        let mut routes = self.routes.lock().map_err(|e| e.to_string())?;
        if !routes.iter().any(|(t, m)| t == target && *m == fwmark) {
            routes.push((target.clone(), fwmark));
        }
        Ok(())
    }

    fn remove_route(&self, target: &RouteTarget, fwmark: u32) -> Result<(), String> {
        let mut routes = self.routes.lock().map_err(|e| e.to_string())?;
        routes.retain(|(t, m)| !(t == target && *m == fwmark));
        Ok(())
    }

    fn remove_all(&self) -> Result<(), String> {
        let mut routes = self.routes.lock().map_err(|e| e.to_string())?;
        routes.clear();
        Ok(())
    }
}
