use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use core_types::{RuleAction, TransportProtocol};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use flow_classifier::diag;
use flow_classifier::{Classifier, RawPacket, SniDnsCache};
use metrics::{counter, gauge, histogram};
use nfq::{Queue, Verdict};

use crate::{FlowDecision, FlowRegistrar};

/// 5-tuple key for the per-connection verdict cache.
#[derive(Hash, Eq, PartialEq, Clone)]
struct ConnectionKey {
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    protocol: TransportProtocol,
}

#[derive(Clone, Copy)]
struct CachedVerdict {
    accept: bool,
    fwmark: Option<u32>,
    expires_at: u64,
}

/// Cached process attribution keyed by `(dst_ip, dst_port)`.
///
/// When the process resolver succeeds for a connection to server S, we store
/// the resolved process here. Later connections to the same server where
/// proc_resolver loses the /proc race re-use this attribution rather than
/// triggering a new pending decision for the user.
#[derive(Clone, Debug, PartialEq)]
struct CachedProcessAttr {
    process_name: String,
    process_exe: Option<String>,
    app_name: Option<String>,
    expires_at: u64,
}

/// IP-based attribution cache TTL and cap.
const PROC_ATTR_TTL_SECS: u64 = 900; // 15 min — outlasts most streaming sessions
const PROC_ATTR_MAX: usize = 1024;
// Domain-based attribution cache TTL and cap (longer, CDN IPs rotate more than domains).
const DOMAIN_ATTR_TTL_SECS: u64 = 3600; // 1 hour
const DOMAIN_ATTR_MAX: usize = 512;

/// Layer-0 destination-keyed process-attribution caches.
///
/// Two maps:
/// * `ip`    — `(dst_ip, dst_port) → CachedProcessAttr` (same CDN endpoint).
/// * `domain`— `(domain, dst_port) → CachedProcessAttr` (CDN rotated the IP).
///
/// These caches answer: *"the last process that reached this destination told
/// us who it was — a later packet whose live resolution failed is probably
/// the same process."* That inference is only safe while the destination is
/// used by exactly ONE local process. The moment a second, different process
/// is observed on the same key, the key becomes ambiguous and must never be
/// restored from again (until expiry) — otherwise packets from process B get
/// process A's name (and A's rules). This was a real misattribution source:
/// every local app sharing one DNS resolver, NTP server, or anycast CDN
/// endpoint reused the previous app's name whenever the live lookup raced.
pub(crate) struct AttrCache {
    proc_attr: HashMap<(String, u16), CachedProcessAttr>,
    domain_proc_attr: HashMap<(String, u16), CachedProcessAttr>,
}

impl AttrCache {
    fn new() -> Self {
        Self {
            proc_attr: HashMap::new(),
            domain_proc_attr: HashMap::new(),
        }
    }

    /// Record a successful live resolution for `(dst_ip, dst_port)` and, when
    /// known, `(domain, dst_port)`. A key currently held by a DIFFERENT
    /// process is poisoned (removed) — see the struct doc.
    fn record_success(
        &mut self,
        dst_ip: &str,
        dst_port: u16,
        domain: Option<&str>,
        proc: &flow_classifier::ProcessInfo,
        now_secs: u64,
    ) {
        let entry = CachedProcessAttr {
            process_name: proc.name.clone(),
            process_exe: proc.exe.clone(),
            app_name: proc.app_name.clone(),
            expires_at: now_secs + PROC_ATTR_TTL_SECS,
        };
        if self.proc_attr.len() >= PROC_ATTR_MAX {
            self.proc_attr.retain(|_, v| v.expires_at > now_secs);
        }
        Self::insert_unless_ambiguous(
            &mut self.proc_attr,
            (dst_ip.to_string(), dst_port),
            entry,
            now_secs,
        );

        if let Some(domain) = domain {
            if self.domain_proc_attr.len() >= DOMAIN_ATTR_MAX {
                self.domain_proc_attr.retain(|_, v| v.expires_at > now_secs);
            }
            Self::insert_unless_ambiguous(
                &mut self.domain_proc_attr,
                (domain.to_string(), dst_port),
                CachedProcessAttr {
                    expires_at: now_secs + DOMAIN_ATTR_TTL_SECS,
                    process_name: proc.name.clone(),
                    process_exe: proc.exe.clone(),
                    app_name: proc.app_name.clone(),
                },
                now_secs,
            );
        }
    }

    /// Insert `entry` under `key` unless the key is live and held by a
    /// different process — in that case remove it entirely: the key can
    /// never prove which process a future unresolved packet belongs to.
    fn insert_unless_ambiguous(
        map: &mut HashMap<(String, u16), CachedProcessAttr>,
        key: (String, u16),
        entry: CachedProcessAttr,
        now_secs: u64,
    ) {
        if let Some(existing) = map.get(&key) {
            if existing.expires_at > now_secs && existing.process_name != entry.process_name {
                diag!(
                    "layer0 key {key:?} AMBIGUOUS ({} vs {}) — entry dropped; \
                     future resolver misses on this destination stay unknown",
                    existing.process_name,
                    entry.process_name
                );
                map.remove(&key);
                return;
            }
        }
        map.insert(key, entry);
    }

    /// Restore attribution for an unresolved packet. IP cache first, then
    /// domain cache. Returns `None` when both miss or the key was poisoned
    /// as ambiguous.
    fn restore(
        &mut self,
        dst_ip: &str,
        dst_port: u16,
        domain: Option<&str>,
        now_secs: u64,
    ) -> Option<CachedProcessAttr> {
        let ip_key = (dst_ip.to_string(), dst_port);
        let cached_ip = self
            .proc_attr
            .get(&ip_key)
            .filter(|c| c.expires_at > now_secs)
            .cloned();
        if cached_ip.is_none() {
            self.proc_attr.remove(&ip_key);
        }
        if cached_ip.is_some() {
            return cached_ip;
        }

        domain.and_then(|d| {
            let dk = (d.to_string(), dst_port);
            let cached_dom = self
                .domain_proc_attr
                .get(&dk)
                .filter(|c| c.expires_at > now_secs)
                .cloned();
            if cached_dom.is_none() {
                self.domain_proc_attr.remove(&dk);
            }
            cached_dom
        })
    }

    fn len(&self) -> (usize, usize) {
        (self.proc_attr.len(), self.domain_proc_attr.len())
    }
}

/// Real packet processor that reads from an NFQUEUE and applies verdicts.
///
/// Open with `NfqueueProcessor::open`, then call `run_loop` on a dedicated thread.
/// The loop is intentionally blocking — each `recv` call parks the thread until
/// a packet arrives, so no busy-waiting occurs.
pub struct NfqueueProcessor<C, FR> {
    queue: Queue,
    classifier: C,
    registrar: FR,
    /// Shared cache updated whenever an SNI is extracted from a ClientHello.
    /// Allows subsequent packets (which carry no SNI) to still be matched
    /// against domain-based rules by IP lookup.
    dns_cache: SniDnsCache,
    /// Per-connection verdict cache. Stores the Allow/Deny decision made for the
    /// first classifiable packet of each connection so that retransmits and
    /// subsequent packets get the same verdict immediately without going through
    /// the full classification pipeline. Without this cache, a denied TCP connection
    /// would still pass through: the SYN is accepted (empty payload), completing the
    /// handshake and putting conntrack in "established" state, and then nftables
    /// `ct state established,related accept` would accept all retransmits before
    /// they reach NFQUEUE again.
    decided: HashMap<ConnectionKey, CachedVerdict>,
    /// Layer-0 destination-keyed process attribution caches (see `AttrCache`).
    attr_cache: AttrCache,
}

// Cached decisions expire after 10 minutes. TCP FINs evict the entry early
// (handled below), so this TTL is mostly a backstop for UDP and long-lived flows.
const CACHE_TTL_SECS: u64 = 600;
// Maximum cache entries before a sweep evicts expired entries.
const CACHE_MAX: usize = 8192;

/// Returns `true` for netlink/NFQUEUE errors that indicate the queue binding
/// has been invalidated and the socket needs to be reopened. Specifically:
///
/// - `ENOENT` (2): queue binding invalidated (nftables table flushed,
///   interface removed, kernel module reloaded).
pub(crate) fn is_queue_invalidated_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(e.kind(), ErrorKind::NotFound)
}

/// Returns `true` for netlink/NFQUEUE errors that are expected to be
/// transient and self-correcting without re-opening the socket:
///
/// - `EINTR` (4): interrupted by signal.
/// - `ENOBUFS` (105 on Linux): kernel queue overflow; next recv usually
///   succeeds.
/// - `EAGAIN` / `EWOULDBLOCK` (11): no data available on a non-blocking
///   socket (shouldn't happen with blocking mode, but harmless to retry).
pub(crate) fn is_transient_netlink_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    const ENOBUFS: i32 = 105; // Linux/POSIX
    matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock)
        || e.raw_os_error() == Some(ENOBUFS)
}

impl<C, FR> NfqueueProcessor<C, FR>
where
    C: Classifier,
    FR: FlowRegistrar,
{
    pub fn open(
        queue_num: u16,
        classifier: C,
        registrar: FR,
        dns_cache: SniDnsCache,
    ) -> std::io::Result<Self> {
        let mut queue = Queue::open()?;
        queue.bind(queue_num)?;
        // Ask the kernel to attach NFQA_UID / NFQA_GID to every queued
        // packet: the socket-owner credentials at enqueue time. Race-free
        // (captured from skb->sk while the socket cannot go away) and used
        // by the resolver to disambiguate port-only candidate matches.
        // Forged/misattributed candidates with a different UID can then be
        // rejected before they produce a wrong process name.
        if let Err(e) = queue.set_recv_uid_gid(queue_num, true) {
            eprintln!(
                "nfqueue: could not enable NFQA_UID/GID delivery ({e}) — \
                 process attribution loses the UID cross-check"
            );
        }
        Ok(Self {
            queue,
            classifier,
            registrar,
            dns_cache,
            decided: HashMap::new(),
            attr_cache: AttrCache::new(),
        })
    }

    /// Blocks indefinitely, processing one packet per iteration.
    ///
    /// **Error handling:**
    /// - Transient errors (EINTR, ENOBUFS, EWOULDBLOCK): retry with
    ///   exponential backoff, no recovery needed.
    /// - `ENOENT` (queue binding invalidated — nftables flushed, interface
    ///   removed): calls `recover()`, then re-opens and re-binds the queue.
    ///   Retries with backoff until recovery succeeds or the daemon exits.
    /// - Fatal errors (EBADF, etc.): returns the error, terminating the loop.
    ///
    /// The `recover` callback should re-apply nftables rules so the kernel
    /// starts delivering packets to the queue number again.  It receives the
    /// queue number in case it needs it.
    pub fn run_loop(
        &mut self,
        queue_num: u16,
        recover: impl Fn(u16) -> Result<(), String>,
    ) -> std::io::Result<()> {
        let mut backoff_ms: u64 = 100;
        const MAX_BACKOFF_MS: u64 = 30_000;
        loop {
            match self.queue.recv() {
                Ok(mut msg) => {
                    backoff_ms = 100;
                    counter!("netkeep.packets.received").increment(1);

                    let start = Instant::now();

                    let now_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let (verdict, fwmark) = match parse_raw_packet(msg.get_payload()) {
                        None => {
                            counter!("netkeep.packets.parse_failed").increment(1);
                            (Verdict::Drop, None)
                        }
                        Some(mut raw) => {
                            // Race-free kernel metadata for this exact packet.
                            raw.sk_uid = msg.get_uid();
                            let forwarded = msg.get_hook() == NF_INET_FORWARD;
                            raw.forwarded = forwarded;
                            if forwarded {
                                counter!("netkeep.packets.received", "hook" => "forward")
                                    .increment(1);
                            }
                            self.decide(&raw, now_secs)
                        }
                    };

                    histogram!("netkeep.packet.processing_duration")
                        .record(start.elapsed().as_secs_f64());

                    if let Some(mark) = fwmark {
                        msg.set_nfmark(mark);
                    }
                    msg.set_verdict(verdict);
                    self.queue.verdict(msg)?;
                }
                Err(e) if is_queue_invalidated_error(&e) => {
                    eprintln!(
                        "nfqueue: queue binding lost ({}), re-applying nftables in {}ms",
                        e, backoff_ms
                    );
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                    match recover(queue_num) {
                        Ok(()) => {
                            // nftables reapplied — reopen the netlink socket
                            // and rebind to the queue.
                            match self.reopen(queue_num) {
                                Ok(()) => {
                                    eprintln!("nfqueue: queue recovered successfully");
                                    backoff_ms = 100;
                                }
                                Err(reopen_err) => {
                                    eprintln!(
                                        "nfqueue: reopen failed after recovery ({}), retrying",
                                        reopen_err
                                    );
                                    backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                                }
                            }
                        }
                        Err(recover_err) => {
                            eprintln!(
                                "nfqueue: recovery failed ({}), retrying in {}ms",
                                recover_err, backoff_ms
                            );
                            backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                        }
                    }
                }
                Err(e) if is_transient_netlink_error(&e) => {
                    eprintln!(
                        "nfqueue: transient recv error ({}), retrying in {}ms",
                        e, backoff_ms
                    );
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                    backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Close the current netlink socket, open a fresh one, and bind to the
    /// given queue number. Called after the kernel invalidates the queue
    /// binding (ENOENT).
    ///
    /// The old socket MUST be unbound and dropped before binding the new one
    /// — the kernel only allows one process to bind to a given queue number
    /// at a time. Without the explicit `unbind`, `Queue::open()` + `bind()`
    /// returns `EPERM` because the old fd still holds the binding.
    fn reopen(&mut self, queue_num: u16) -> std::io::Result<()> {
        // Explicitly release the kernel queue binding before opening a new
        // socket. If unbind fails (e.g. socket already dead) we still proceed
        // — the Drop will close the fd anyway.
        let _ = self.queue.unbind(queue_num);
        // Drop the old queue (closes the netlink fd) before binding the new
        // one. Without this the kernel rejects the bind with EPERM.
        self.queue = Queue::open()?;
        self.queue.bind(queue_num)?;
        Ok(())
    }

    fn decide(&mut self, raw: &RawPacket, now_secs: u64) -> (Verdict, Option<u32>) {
        // Always pass loopback and DNS through without touching the cache.
        if is_loopback(&raw.dst_ip) || raw.dst_port == 53 {
            counter!("netkeep.packets.accepted", "reason" => "loopback").increment(1);
            return (Verdict::Accept, None);
        }

        // ICMP/ICMPv6 (protocol=Other, src_port=0) reaches here only if the
        // nftables bypass rule is somehow missing. Accept immediately — the
        // process resolver cannot match port-less packets and NDP in particular
        // must never be blocked.
        if matches!(raw.protocol, TransportProtocol::Other) {
            counter!("netkeep.packets.accepted", "reason" => "icmp").increment(1);
            return (Verdict::Accept, None);
        }

        let key = ConnectionKey {
            src_ip: raw.src_ip.clone(),
            src_port: raw.src_port,
            dst_ip: raw.dst_ip.clone(),
            dst_port: raw.dst_port,
            protocol: raw.protocol,
        };

        // FIN/RST — connection is closing/resetting. Evict the cached verdict so
        // that a future connection reusing the same 5-tuple gets a fresh decision.
        if raw.tcp_fin || raw.tcp_rst {
            if self.decided.remove(&key).is_some() {
                counter!("netkeep.verdict.cache.evictions", "reason" => "fin_rst").increment(1);
            }
            return (Verdict::Accept, None);
        }

        // Pure ACK (mid-connection, no SYN) — no application payload, nothing
        // new to classify. Return the cached verdict if one exists; otherwise
        // accept. Do NOT evict the cache: pure ACKs flow freely in established
        // connections and evicting here would force full re-classification on
        // the next data segment, which re-runs the /proc resolver and can
        // return process=None when the proc lookup races with a brief
        // fd-visibility gap.
        //
        // SYNs are NOT short-circuited even though they're payload-empty: the
        // SYN is the conntrack-NEW packet, and any NAT decision (e.g. our
        // POSTROUTING masquerade for routed marks) is locked in at NEW time.
        // If the SYN goes unmarked, the conntrack records a no-NAT mapping
        // and the connection is permanently nailed to whichever interface the
        // kernel's pre-rule routing chose — typically the VPN. A later data
        // packet getting a routing mark cannot undo that. So we must classify
        // SYNs and stamp the mark on packet 1.
        if raw.tcp_payload_empty && !raw.tcp_syn {
            if let Some(cached) = self.decided.get(&key) {
                if cached.expires_at > now_secs {
                    counter!("netkeep.packets.accepted", "reason" => "pure_ack").increment(1);
                    let v = if cached.accept {
                        Verdict::Accept
                    } else {
                        Verdict::Drop
                    };
                    return (v, cached.fwmark);
                }
                self.decided.remove(&key);
            }
            return (Verdict::Accept, None);
        }

        // Fast path: return cached verdict if still valid.
        if let Some(cached) = self.decided.get(&key) {
            if cached.expires_at > now_secs {
                counter!("netkeep.packets.accepted", "reason" => "cache_hit").increment(1);
                let v = if cached.accept {
                    Verdict::Accept
                } else {
                    Verdict::Drop
                };
                return (v, cached.fwmark);
            }
            self.decided.remove(&key);
        }

        // Slow path: classify the connection for the first time.
        let slow_start = Instant::now();
        let proto_str = match raw.protocol {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
            TransportProtocol::Quic => "quic",
            TransportProtocol::Other => "other",
        };
        diag!(
            "pkt {proto_str} {}:{} -> {}:{} syn={} fin={} rst={}",
            raw.src_ip,
            raw.src_port,
            raw.dst_ip,
            raw.dst_port,
            raw.tcp_syn,
            raw.tcp_fin,
            raw.tcp_rst
        );
        if let Some(sni) = &raw.sni_hint {
            self.dns_cache.insert(&raw.dst_ip, sni);
        }
        let mut flow = self.classifier.classify(raw);

        if flow.process_name.is_none() {
            // Live resolution failed for this packet. Layer-0 can only
            // *guess* the process from the destination — and for forwarded
            // packets (no local socket: containers without an eBPF entry,
            // LAN clients behind this host) any restored local process name
            // would be flatly wrong. Never restore for forwarded traffic.
            if !raw.forwarded {
                if let Some(c) = self.attr_cache.restore(
                    &raw.dst_ip,
                    raw.dst_port,
                    flow.destination_domain.as_deref(),
                    now_secs,
                ) {
                    let cache_kind = "ip|domain";
                    diag!(
                        "layer0 {}:{} restored name={:?} ({cache_kind}) — \
                         live resolution FAILED for this packet",
                        raw.dst_ip,
                        raw.dst_port,
                        c.process_name
                    );
                    flow.process_name = Some(c.process_name.clone());
                    flow.process_exe = c.process_exe.clone();
                    flow.app_name = c.app_name.clone();
                }
            } else {
                diag!(
                    "layer0 {}:{} skipped restore — packet is FORWARDED \
                     (no local socket can own it)",
                    raw.dst_ip,
                    raw.dst_port
                );
            }
        } else {
            // Successful resolution — populate both caches.
            self.attr_cache.record_success(
                &raw.dst_ip,
                raw.dst_port,
                flow.destination_domain.as_deref(),
                &flow_classifier::ProcessInfo {
                    name: flow.process_name.clone().unwrap_or_default(),
                    exe: flow.process_exe.clone(),
                    app_name: flow.app_name.clone(),
                },
                now_secs,
            );
        }

        let register_start = Instant::now();
        let flow_name = flow.process_name.clone();
        let decision = self.registrar.register(flow, now_secs);
        diag!(
            "flow {proto_str} {}:{} -> {}:{} process={:?} verdict={}",
            raw.src_ip,
            raw.src_port,
            raw.dst_ip,
            raw.dst_port,
            flow_name,
            verdict_label(&decision),
        );
        histogram!("netkeep.registration.duration").record(register_start.elapsed().as_secs_f64());
        histogram!("netkeep.decision.slow_path.duration")
            .record(slow_start.elapsed().as_secs_f64());

        // Only cache definitive decisions. Pending/Ask flows must NOT be cached:
        // sweep_pending will resolve them shortly and the next retransmit must
        // re-classify to pick up the newly installed rule.
        let should_cache = matches!(
            &decision,
            FlowDecision::Immediate(RuleAction::Allow, _)
                | FlowDecision::Immediate(RuleAction::Route, Some(_))
                | FlowDecision::Immediate(RuleAction::Deny, _)
        );

        let fwmark = match &decision {
            FlowDecision::Immediate(RuleAction::Route, Some(target)) => {
                self.registrar.route_mark(target)
            }
            _ => None,
        };

        let verdict = match &decision {
            FlowDecision::Immediate(RuleAction::Allow, _)
            | FlowDecision::Immediate(RuleAction::Route, Some(_))
            | FlowDecision::DeferSni => Verdict::Accept,
            _ => Verdict::Drop,
        };

        if should_cache {
            if self.decided.len() >= CACHE_MAX {
                let before = self.decided.len();
                self.decided.retain(|_, v| v.expires_at > now_secs);
                let evicted = before - self.decided.len();
                if evicted > 0 {
                    counter!("netkeep.verdict.cache.evictions", "reason" => "expiry_sweep")
                        .increment(evicted as u64);
                }
            }
            self.decided.insert(
                key,
                CachedVerdict {
                    accept: matches!(verdict, Verdict::Accept),
                    fwmark,
                    expires_at: now_secs + CACHE_TTL_SECS,
                },
            );
        }

        gauge!("netkeep.verdict.cache.entries").set(self.decided.len() as f64);
        let (ip_entries, domain_entries) = self.attr_cache.len();
        gauge!("netkeep.proc.attr.cache.entries", "cache" => "ip").set(ip_entries as f64);
        gauge!("netkeep.proc.attr.cache.entries", "cache" => "domain").set(domain_entries as f64);

        match &decision {
            FlowDecision::Immediate(RuleAction::Allow, _) => {
                counter!("netkeep.packets.accepted", "reason" => "rule_allow").increment(1);
            }
            FlowDecision::Immediate(RuleAction::Route, Some(_)) => {
                counter!("netkeep.packets.accepted", "reason" => "rule_route").increment(1);
            }
            FlowDecision::DeferSni => {
                counter!("netkeep.packets.accepted", "reason" => "defer_sni").increment(1);
            }
            FlowDecision::Immediate(RuleAction::Deny, _) => {
                counter!("netkeep.packets.dropped", "reason" => "rule_deny").increment(1);
            }
            FlowDecision::Pending { .. } => {
                counter!("netkeep.packets.dropped", "reason" => "pending").increment(1);
            }
            FlowDecision::Immediate(RuleAction::Route, None) => {
                counter!("netkeep.packets.dropped", "reason" => "no_target").increment(1);
            }
            FlowDecision::Immediate(RuleAction::Ask, _) => {
                counter!("netkeep.packets.dropped", "reason" => "ask").increment(1);
            }
        }

        (verdict, fwmark)
    }
}

/// Short verdict label for diag lines.
fn verdict_label(decision: &FlowDecision) -> &'static str {
    match decision {
        FlowDecision::Immediate(RuleAction::Allow, _) => "allow",
        FlowDecision::Immediate(RuleAction::Deny, _) => "deny",
        FlowDecision::Immediate(RuleAction::Route, Some(_)) => "route",
        FlowDecision::Immediate(RuleAction::Route, None) => "route-no-target",
        FlowDecision::Immediate(RuleAction::Ask, _) => "ask",
        FlowDecision::Pending { .. } => "pending",
        FlowDecision::DeferSni => "defer-sni",
    }
}

fn is_loopback(ip: &str) -> bool {
    // IPv4 loopback: 127.0.0.0/8
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        return v4.octets()[0] == 127;
    }
    // IPv6 loopback: ::1, and IPv4-mapped loopback ::ffff:127.x.x.x (Rust's
    // `Ipv6Addr::is_loopback` is false for mapped addresses, so those packets
    // were still queued and produced Ask spam).
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        if v6.is_loopback() {
            return true;
        }
        if let Some(v4) = v6.to_ipv4_mapped() {
            return v4.octets()[0] == 127;
        }
    }
    false
}

/// Parse a raw IP-layer payload (as delivered by NFQUEUE) into a `RawPacket`.
/// Returns `None` for unsupported/malformed packets — caller should drop those.
pub fn parse_raw_packet(payload: &[u8]) -> Option<RawPacket> {
    let sliced = SlicedPacket::from_ip(payload).ok()?;

    let (src_ip, dst_ip) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(s) => {
            let h = s.header();
            (
                h.source_addr().to_string(),
                h.destination_addr().to_string(),
            )
        }
        NetSlice::Ipv6(s) => {
            let h = s.header();
            (
                h.source_addr().to_string(),
                h.destination_addr().to_string(),
            )
        }
    };

    let (src_port, dst_port, protocol, sni_hint, tcp_payload_empty, tcp_fin, tcp_rst, tcp_syn) =
        match sliced.transport.as_ref() {
            Some(TransportSlice::Tcp(t)) => {
                let payload = t.payload();
                let domain_hint = if payload.is_empty() {
                    None
                } else if is_tls_clienthello_packet(payload) {
                    let extract_start = Instant::now();
                    counter!("netkeep.sni.extraction.attempts", "kind" => "tls").increment(1);
                    let hint = if let Some(sni) = extract_tls_sni(payload) {
                        counter!("netkeep.sni.extraction.success", "source" => "tls").increment(1);
                        Some(sni)
                    } else {
                        counter!("netkeep.sni.extraction.missed", "kind" => "tls").increment(1);
                        None
                    };
                    histogram!("netkeep.sni.extraction.duration")
                        .record(extract_start.elapsed().as_secs_f64());
                    hint
                } else if starts_with_http_method(payload) {
                    let extract_start = Instant::now();
                    counter!("netkeep.sni.extraction.attempts", "kind" => "http").increment(1);
                    let hint = if let Some(host) = extract_http_host(payload) {
                        counter!("netkeep.sni.extraction.success", "source" => "http_host")
                            .increment(1);
                        Some(host)
                    } else {
                        counter!("netkeep.sni.extraction.missed", "kind" => "http").increment(1);
                        None
                    };
                    histogram!("netkeep.sni.extraction.duration")
                        .record(extract_start.elapsed().as_secs_f64());
                    hint
                } else {
                    // Encrypted TLS app data, ServerHello, SSH, etc. — not extractable.
                    counter!("netkeep.sni.extraction.skipped").increment(1);
                    None
                };
                (
                    t.source_port(),
                    t.destination_port(),
                    TransportProtocol::Tcp,
                    domain_hint,
                    payload.is_empty(),
                    t.fin(),
                    t.rst(),
                    t.syn(),
                )
            }
            Some(TransportSlice::Udp(u)) => {
                let (sp, dp) = (u.source_port(), u.destination_port());
                // Best-effort QUIC detection: UDP to/from port 443.
                let proto = if dp == 443 || sp == 443 {
                    TransportProtocol::Quic
                } else {
                    TransportProtocol::Udp
                };
                (sp, dp, proto, None, false, false, false, false)
            }
            _ => (
                0,
                0,
                TransportProtocol::Other,
                None,
                false,
                false,
                false,
                false,
            ),
        };

    Some(RawPacket {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
        sni_hint,
        ingress_interface: None,
        tcp_payload_empty,
        tcp_fin,
        tcp_rst,
        tcp_syn,
        // Filled in by the caller from NFQUEUE metadata (uid/hook).
        sk_uid: None,
        forwarded: false,
    })
}

/// `NF_INET_FORWARD` from `<linux/netfilter.h>` — packets routed through
/// this host (containers, VMs, LAN clients) rather than generated by it.
const NF_INET_FORWARD: u8 = 2;

/// Extract the TLS SNI hostname from a TCP payload containing a TLS ClientHello.
///
/// TLS record layout:
///   [0]    content type: 0x16 (handshake)
///   [1..2] legacy version: 0x03 0x01 (or 0x03 0x03)
///   [3..4] record length (big-endian u16)
///   [5]    handshake type: 0x01 (ClientHello)
///   [6..8] handshake length (big-endian u24)
///   [9..10] client version
///   [11..42] random (32 bytes)
///   [43]   session id length
///   ...    session id
///   then:  cipher suites length (u16), cipher suites
///   then:  compression methods length (u8), compression methods
///   then:  extensions length (u16), extensions
///     each extension: type (u16) + length (u16) + data
///     SNI extension type = 0x0000
///       SNI list length (u16)
///       SNI entry type (u8, 0x00 = host_name) + name length (u16) + name bytes
fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    // Need at least TLS record header (5) + handshake header (4) + hello header (34+)
    if payload.len() < 43 {
        return None;
    }
    // TLS handshake record
    if payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    // Handshake type must be ClientHello (0x01)
    if payload[5] != 0x01 {
        return None;
    }

    let mut pos = 43; // start of session id length

    // Skip session id
    let session_id_len = *payload.get(pos)? as usize;
    pos += 1 + session_id_len;

    // Skip cipher suites
    let cipher_suites_len =
        u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]) as usize;
    pos += 2 + cipher_suites_len;

    // Skip compression methods
    let compression_len = *payload.get(pos)? as usize;
    pos += 1 + compression_len;

    // Extensions length
    if pos + 2 > payload.len() {
        return None;
    }
    let extensions_end = pos + 2 + u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    // Walk extensions
    while pos + 4 <= extensions_end && pos + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > payload.len() {
            return None;
        }

        if ext_type == 0x0000 {
            // SNI extension: list_length(u16) + type(u8) + name_length(u16) + name
            if ext_len < 5 {
                return None;
            }
            let ext_data = &payload[pos..pos + ext_len];
            // SNI entry type 0x00 = host_name
            if ext_data[2] != 0x00 {
                return None;
            }
            let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
            if ext_data.len() < 5 + name_len {
                return None;
            }
            return std::str::from_utf8(&ext_data[5..5 + name_len])
                .ok()
                .map(str::to_string);
        }

        pos += ext_len;
    }

    None
}

/// Extract the `Host` header value from a plaintext HTTP/1.x request payload.
///
/// Used as a fallback for flows that don't have TLS SNI (e.g. `curl
/// example.com` over port 80) so the user sees a real domain in the
/// decision dialog instead of just the IP.
///
/// Bounds and safety:
/// * Only scans the first 4 KiB of the payload — bounded cost per packet, and
///   real HTTP requests' header blocks are well under this in practice.
/// * Rejects payloads that don't start with a known HTTP method, so we don't
///   waste cycles substring-searching arbitrary TCP traffic.
/// * Strips an optional `:port` suffix (e.g. `Host: example.com:8080` →
///   `example.com`) because that's what users mean by "the destination".
/// * Lowercases the result (DNS / SNI / `Host` are all case-insensitive).
/// * Returns `None` for anything that isn't ASCII-clean — both for safety and
///   because anything else isn't a legal HTTP/1.x Host header anyway.
fn extract_http_host(payload: &[u8]) -> Option<String> {
    if !starts_with_http_method(payload) {
        return None;
    }

    // 4 KiB is plenty for the request line + headers in any realistic HTTP/1.x
    // request. Anything beyond that is either malicious or oversized and not
    // worth blocking the packet decision on.
    let scan = &payload[..payload.len().min(4096)];

    // Headers end at the first \r\n\r\n (or end-of-payload for partial reads).
    let header_end = scan
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(scan.len());
    let headers = &scan[..header_end];

    // Look for "\r\nHost:" (case-insensitive). Skipping the first request line
    // means we don't get tricked by an absolute-form URL on the request line
    // (e.g. `GET http://example.com/ HTTP/1.1`) — we want the actual Host
    // header value.
    let needle = b"\r\nhost:";
    let mut start = None;
    for i in 0..headers.len().saturating_sub(needle.len()) {
        if headers[i..i + needle.len()].eq_ignore_ascii_case(needle) {
            start = Some(i + needle.len());
            break;
        }
    }
    let value_start = start?;

    // Take until end of line (CRLF or LF or end-of-headers).
    let line_end = headers[value_start..]
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .map(|i| value_start + i)
        .unwrap_or(headers.len());

    let raw = &headers[value_start..line_end];

    // Trim ASCII whitespace.
    let trimmed = trim_ascii(raw);
    if trimmed.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(trimmed).ok()?;

    // Reject anything that isn't a plausible hostname (rough RFC 952/1123
    // shape — letters, digits, dots, hyphens, optional `:port`, optional
    // IPv6 literal in brackets). Catches non-HTTP traffic that happens to
    // contain a `\r\nHost:` byte sequence by coincidence.
    if !looks_like_host_value(s) {
        return None;
    }

    // Strip optional :port suffix. Handles both `example.com:8080` and
    // bracketed IPv6 `[::1]:8080` (the bracketed form is what HTTP requires
    // for IPv6 Host headers).
    let host = if let Some(rest) = s.strip_prefix('[') {
        // IPv6 literal: take until the closing `]`.
        let end = rest.find(']')?;
        &rest[..end]
    } else if let Some((h, _port)) = s.rsplit_once(':') {
        // Only treat the trailing colon as a port separator when what's
        // after it is all digits — otherwise this could mangle a literal
        // IPv6 (which should have been in brackets, but be lenient).
        if _port.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            s
        }
    } else {
        s
    };

    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// True when the TCP payload begins with a TLS ClientHello handshake record.
/// Used to gate SNI extraction metrics — post-handshake ciphertext and other
/// TLS record types are not SNI candidates and must not count as failed attempts.
fn is_tls_clienthello_packet(payload: &[u8]) -> bool {
    payload.len() >= 43 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

/// HTTP/1.x request methods we care about. We only need a quick early-reject
/// for "this payload doesn't look like HTTP at all" — the full method set
/// isn't required for correctness, just for avoiding a `\r\nHost:` substring
/// search on arbitrary binary TCP payloads.
fn starts_with_http_method(payload: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|m| payload.starts_with(m))
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &s[start..end]
}

fn looks_like_host_value(s: &str) -> bool {
    // Conservative: at least one char, and every char is in the
    // hostname-or-port-or-bracket set. Length-cap to avoid accepting huge
    // malformed values.
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    // -------------------------------------------------------------------
    // Layer-0 destination-keyed attribution cache (AttrCache)
    // -------------------------------------------------------------------

    /// Test helper: build a ProcessInfo for AttrCache::record_success.
    fn proc_info(name: &str) -> flow_classifier::ProcessInfo {
        flow_classifier::ProcessInfo {
            name: name.to_string(),
            exe: None,
            app_name: None,
        }
    }

    /// Baseline behavior: a single process's successful resolution is
    /// restored for a later packet whose live resolution failed (the
    /// CDN-rotation fix from Bug 24 — must keep working).
    #[test]
    fn layer0_restores_same_process_after_resolver_miss() {
        let mut cache = AttrCache::new();
        cache.record_success(
            "1.2.3.4",
            443,
            Some("cdn.example.com"),
            &proc_info("firefox"),
            1000,
        );

        let restored = cache.restore("1.2.3.4", 443, None, 1100);
        assert_eq!(
            restored.map(|c| c.process_name),
            Some("firefox".to_string()),
            "same-process restore must keep working"
        );

        // Domain fallback for a rotated CDN IP.
        let restored = cache.restore("5.6.7.8", 443, Some("cdn.example.com"), 1200);
        assert_eq!(
            restored.map(|c| c.process_name),
            Some("firefox".to_string()),
            "domain-cache restore must keep working"
        );
    }

    /// REGRESSION (misattribution): two DIFFERENT processes reaching the same
    /// `(dst_ip, dst_port)` make the key ambiguous. A third packet whose live
    /// resolution fails must NOT be attributed to either process — the cache
    /// cannot know which of the two it belongs to. Before the fix the cache
    /// happily returned whichever process resolved last, producing confident
    /// wrong process names (e.g. every local app sharing one DNS resolver,
    /// NTP server, or any anycast CDN endpoint).
    #[test]
    fn layer0_does_not_restore_when_second_process_shares_destination() {
        let mut cache = AttrCache::new();
        cache.record_success("8.8.8.8", 53, None, &proc_info("curl"), 1000);
        cache.record_success("8.8.8.8", 53, None, &proc_info("chrome"), 1100);

        let restored = cache.restore("8.8.8.8", 53, None, 1200);
        assert_eq!(
            restored, None,
            "destination shared by two processes is ambiguous — must restore nothing"
        );
    }

    /// Same requirement for the domain-keyed cache.
    #[test]
    fn layer0_domain_cache_does_not_restore_when_shared() {
        let mut cache = AttrCache::new();
        cache.record_success(
            "1.1.1.1",
            443,
            Some("shared.example.com"),
            &proc_info("firefox"),
            1000,
        );
        cache.record_success(
            "2.2.2.2",
            443,
            Some("shared.example.com"),
            &proc_info("chromium"),
            1100,
        );

        // IP keys are distinct, so IP restore works — but the shared DOMAIN
        // key must not restore for a fresh unknown IP.
        assert_eq!(
            cache.restore("3.3.3.3", 443, Some("shared.example.com"), 1200),
            None,
            "domain shared by two processes is ambiguous — must restore nothing"
        );
        // The single-process IP keys still restore.
        assert_eq!(
            cache
                .restore("1.1.1.1", 443, None, 1200)
                .map(|c| c.process_name),
            Some("firefox".to_string())
        );
    }

    /// Ambiguity is a property of the live TTL window, not forever: after the
    /// entries expire the key can be re-armed by a new successful resolution.
    #[test]
    fn layer0_key_re_arms_after_expiry() {
        let mut cache = AttrCache::new();
        cache.record_success("8.8.8.8", 53, None, &proc_info("curl"), 1000);
        cache.record_success("8.8.8.8", 53, None, &proc_info("chrome"), 1100);
        // Both entries expire (> 15 min later).
        assert_eq!(
            cache.restore("8.8.8.8", 53, None, 1000 + PROC_ATTR_TTL_SECS + 10),
            None
        );
        // A fresh single-process success re-arms the key.
        cache.record_success(
            "8.8.8.8",
            53,
            None,
            &proc_info("dig"),
            1000 + PROC_ATTR_TTL_SECS + 20,
        );
        assert_eq!(
            cache
                .restore("8.8.8.8", 53, None, 1000 + PROC_ATTR_TTL_SECS + 30)
                .map(|c| c.process_name),
            Some("dig".to_string())
        );
    }

    fn build_ipv4_tcp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let payload = b"hello";
        let mut buf = Vec::new();
        PacketBuilder::ipv4(src, dst, 64)
            .tcp(src_port, dst_port, 0, 65535)
            .write(&mut buf, payload)
            .unwrap();
        // NFQUEUE delivers the IP layer, so strip Ethernet (there is none here).
        buf
    }

    fn build_ipv4_udp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let payload = b"hi";
        let mut buf = Vec::new();
        PacketBuilder::ipv4(src, dst, 64)
            .udp(src_port, dst_port)
            .write(&mut buf, payload)
            .unwrap();
        buf
    }

    #[test]
    fn parses_ipv4_tcp_packet() {
        let raw = build_ipv4_tcp([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443);
        let pkt = parse_raw_packet(&raw).expect("parsed");
        assert_eq!(pkt.src_ip, "10.0.0.1");
        assert_eq!(pkt.dst_ip, "1.1.1.1");
        assert_eq!(pkt.src_port, 54321);
        assert_eq!(pkt.dst_port, 443);
        assert_eq!(pkt.protocol, TransportProtocol::Tcp);
    }

    #[test]
    fn parses_ipv4_udp_non_quic() {
        let raw = build_ipv4_udp([192, 168, 1, 1], [8, 8, 8, 8], 12345, 53);
        let pkt = parse_raw_packet(&raw).expect("parsed");
        assert_eq!(pkt.protocol, TransportProtocol::Udp);
        assert_eq!(pkt.dst_port, 53);
    }

    #[test]
    fn udp_port_443_detected_as_quic() {
        let raw = build_ipv4_udp([10, 0, 0, 2], [1, 1, 1, 1], 55000, 443);
        let pkt = parse_raw_packet(&raw).expect("parsed");
        assert_eq!(pkt.protocol, TransportProtocol::Quic);
    }

    #[test]
    fn malformed_payload_returns_none() {
        assert!(parse_raw_packet(&[0xde, 0xad, 0xbe, 0xef]).is_none());
        assert!(parse_raw_packet(&[]).is_none());
    }

    /// Build a minimal TLS ClientHello TCP payload with the given SNI hostname.
    fn build_tls_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let name_len = sni_bytes.len() as u16;
        // SNI extension data: list_len(u16) + entry_type(u8) + name_len(u16) + name
        let sni_ext_data_len = (2 + 1 + 2 + sni_bytes.len()) as u16;
        // Full extension wire size: type(2) + len(2) + data
        let sni_ext_total = 4 + sni_ext_data_len as usize;
        // Minimal ClientHello body: version(2) + random(32) + session_id_len(1) +
        // cipher_suites_len(2) + cipher_suite(2) + compression_len(1) + null(1) +
        // extensions_len(2) + SNI extension
        let hello_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + sni_ext_total;
        // TLS record length: handshake_type(1) + handshake_len(3) + body
        let record_len = (1 + 3 + hello_body_len) as u16;

        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x16, 0x03, 0x01]); // TLS record header
        buf.extend_from_slice(&record_len.to_be_bytes());
        buf.push(0x01); // handshake type: ClientHello
        buf.push(0x00);
        buf.extend_from_slice(&(hello_body_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        buf.extend_from_slice(&[0u8; 32]); // random
        buf.push(0x00); // session_id_len = 0
        buf.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // cipher_suites
        buf.extend_from_slice(&[0x01, 0x00]); // compression: null
        buf.extend_from_slice(&(sni_ext_total as u16).to_be_bytes()); // extensions_len
        buf.extend_from_slice(&[0x00, 0x00]); // SNI extension type
        buf.extend_from_slice(&sni_ext_data_len.to_be_bytes());
        buf.extend_from_slice(&(1 + 2 + name_len).to_be_bytes()); // SNI list_len
        buf.push(0x00); // entry type: host_name
        buf.extend_from_slice(&name_len.to_be_bytes());
        buf.extend_from_slice(sni_bytes);
        buf
    }

    #[test]
    fn sni_extracted_from_tls_client_hello() {
        let hello = build_tls_client_hello("example.com");
        assert_eq!(extract_tls_sni(&hello), Some("example.com".to_string()));
    }

    #[test]
    fn sni_not_present_in_non_tls_payload() {
        assert_eq!(extract_tls_sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(extract_tls_sni(&[]), None);
    }

    // ----- HTTP Host header extraction (the `curl google.com` fallback) -----

    #[test]
    fn http_host_extracted_from_get_request() {
        let payload = b"GET / HTTP/1.1\r\nHost: google.com\r\nUser-Agent: curl/8.0\r\n\r\n";
        assert_eq!(extract_http_host(payload), Some("google.com".to_string()));
    }

    #[test]
    fn http_host_extracted_case_insensitive() {
        // Header names are case-insensitive per RFC 7230 §3.2.
        let payload = b"GET / HTTP/1.1\r\nHOST: Example.COM\r\n\r\n";
        assert_eq!(extract_http_host(payload), Some("example.com".to_string()));
    }

    #[test]
    fn http_host_strips_port_suffix() {
        // Hosts with explicit port — what we want in the rule is the host,
        // not the host:port pair. Otherwise wildcard rules `*.example.com`
        // wouldn't match a flow with `Host: api.example.com:8080`.
        let payload = b"POST / HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n";
        assert_eq!(
            extract_http_host(payload),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn http_host_strips_ipv6_bracket_port() {
        let payload = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n";
        assert_eq!(extract_http_host(payload), Some("2001:db8::1".to_string()));
    }

    #[test]
    fn http_host_returns_none_for_non_http_payload() {
        // Random TCP payload that happens to contain `\r\nHost:` bytes by
        // coincidence — must NOT be picked up as an HTTP host. The early
        // method-prefix check is what prevents the false positive.
        assert_eq!(
            extract_http_host(b"\x00\x01\x02\r\nHost: tricked.com\r\n\x05"),
            None
        );
    }

    #[test]
    fn http_host_returns_none_for_tls_payload() {
        // TLS ClientHello shouldn't accidentally match as HTTP.
        let hello = build_tls_client_hello("example.com");
        assert_eq!(extract_http_host(&hello), None);
    }

    #[test]
    fn http_host_returns_none_when_header_missing() {
        // Malformed HTTP/1.0 request with no Host header is still legal
        // for HTTP/1.0 — we just have no domain to report.
        let payload = b"GET / HTTP/1.0\r\nUser-Agent: weird\r\n\r\n";
        assert_eq!(extract_http_host(payload), None);
    }

    #[test]
    fn http_host_rejects_non_hostname_garbage() {
        // Defensive: if a malicious client sends `Host: <huge binary blob>`
        // we shouldn't treat that as a domain. The `looks_like_host_value`
        // guard rejects anything outside the host-character set.
        let mut payload = b"GET / HTTP/1.1\r\nHost: ".to_vec();
        payload.extend_from_slice(&[0xff; 16]);
        payload.extend_from_slice(b"\r\n\r\n");
        assert_eq!(extract_http_host(&payload), None);
    }

    #[test]
    fn http_host_handles_multiple_headers_before_host() {
        // Real curl puts `User-Agent` and `Accept` before `Host` only some
        // of the time, but we should find Host regardless of position.
        let payload =
            b"GET /path HTTP/1.1\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\nHost: example.org\r\n\r\n";
        assert_eq!(extract_http_host(payload), Some("example.org".to_string()));
    }

    #[test]
    fn http_host_truncated_payload_returns_none_safely() {
        // Don't panic on a payload that ends mid-Host-header.
        let payload = b"GET / HTTP/1.1\r\nHost: example.com"; // no CRLF after value
                                                              // We accept the unfinished value — it's still useful information.
        assert_eq!(extract_http_host(payload), Some("example.com".to_string()));
    }

    #[test]
    fn http_connect_method_extracts_host() {
        // HTTPS proxies negotiate via CONNECT; the request line carries
        // `CONNECT host:port HTTP/1.1`. The Host header is still present
        // and that's what we extract (we don't need the request line).
        let payload = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert_eq!(extract_http_host(payload), Some("example.com".to_string()));
    }

    #[test]
    fn parsed_tcp_packet_with_http_request_populates_sni_hint_with_host() {
        // End-to-end: a parsed TCP packet whose payload is a plaintext
        // HTTP GET request should expose the Host as `sni_hint`.
        // (Field name `sni_hint` is historical — it now holds any extracted
        // domain hint, SNI *or* HTTP Host.)
        let body = b"GET / HTTP/1.1\r\nHost: google.com\r\nUser-Agent: curl/8\r\n\r\n";
        let mut buf = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 1], [1, 1, 1, 1], 64)
            .tcp(54321, 80, 0, 65535)
            .write(&mut buf, body)
            .unwrap();
        let pkt = parse_raw_packet(&buf).expect("parsed");
        assert_eq!(pkt.sni_hint.as_deref(), Some("google.com"));
    }

    #[test]
    fn tcp_packet_with_tls_hello_populates_sni_hint() {
        let hello = build_tls_client_hello("secure.example.org");
        let mut buf = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 1], [1, 1, 1, 1], 64)
            .tcp(54321, 443, 0, 65535)
            .write(&mut buf, &hello)
            .unwrap();
        let pkt = parse_raw_packet(&buf).expect("parsed");
        assert_eq!(pkt.sni_hint.as_deref(), Some("secure.example.org"));
    }

    #[test]
    fn tcp_packet_without_tls_has_no_sni_hint() {
        let raw = build_ipv4_tcp([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443);
        let pkt = parse_raw_packet(&raw).expect("parsed");
        assert_eq!(pkt.sni_hint, None);
    }

    #[test]
    fn loopback_includes_ipv4_mapped_127() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.42.3.4"));
        assert!(is_loopback("::1"));
        assert!(is_loopback("::ffff:127.0.0.1"));
        assert!(is_loopback("::ffff:127.255.0.1"));
        assert!(!is_loopback("10.0.0.1"));
        assert!(!is_loopback("::ffff:8.8.8.8"));
        assert!(!is_loopback("2001:db8::1"));
    }

    #[test]
    fn transient_error_detection() {
        use std::io::ErrorKind;
        // ENOENT is NOT transient — it's a queue-invalidated error that
        // requires re-applying nftables and reopening the socket.
        assert!(!is_transient_netlink_error(
            &std::io::Error::from_raw_os_error(2)
        ));
        assert!(is_queue_invalidated_error(
            &std::io::Error::from_raw_os_error(2)
        ));
        // EINTR — signal interrupt (truly transient)
        assert!(is_transient_netlink_error(&std::io::Error::new(
            ErrorKind::Interrupted,
            "interrupted"
        )));
        // ENOBUFS — kernel queue overflow (truly transient)
        assert!(is_transient_netlink_error(
            &std::io::Error::from_raw_os_error(105)
        ));
        // EAGAIN / EWOULDBLOCK (truly transient)
        assert!(is_transient_netlink_error(&std::io::Error::new(
            ErrorKind::WouldBlock,
            "would block"
        )));
        // EBADF — fatal, should kill the loop
        assert!(!is_transient_netlink_error(
            &std::io::Error::from_raw_os_error(9)
        ));
        assert!(!is_queue_invalidated_error(
            &std::io::Error::from_raw_os_error(9)
        ));
        // ECONNREFUSED — fatal
        assert!(!is_transient_netlink_error(
            &std::io::Error::from_raw_os_error(111)
        ));
    }
}
