pub mod diag;
pub mod proc_resolver;
pub mod ptr;
pub mod sni;
pub mod sock_diag;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use core_types::{DomainSource, FlowContext, FlowDirection, ProcessOrigin, TransportProtocol};
use metrics::{counter, histogram};

// ── SNI DNS cache ──────────────────────────────────────────────────────────────

/// Maximum bindings kept per destination IP (most-recent-first list).
/// CDN IPs legitimately serve many domains — and, with process scoping, the
/// same domain may appear once per resolving process — so the list must hold
/// them instead of overwriting.
const MAX_DOMAINS_PER_IP: usize = 32;
/// Soft cap on tracked IPs before an expiry sweep runs.
const MAX_IPS: usize = 8192;
/// Clamp for DNS-derived TTLs (seconds). TTL 0 answers are kept for the
/// minimum so a connection landing in the same second still resolves.
const MIN_TTL_SECS: u64 = 1;
const MAX_TTL_SECS: u64 = 86_400;

/// One learned `ip → domain` binding with optional expiry and provenance.
struct DomainEntry {
    domain: String,
    /// `None` for in-band hints (SNI/Host — valid until evicted),
    /// `Some` for DNS answers (expires per the DNS record TTL).
    expires_at: Option<Instant>,
    /// Provenance at learning time. Cache hits are always reported to the
    /// classifier as `Dns`: an entry learned from an earlier connection's SNI
    /// is still only a prior for *this* connection.
    #[allow(dead_code)]
    source: DomainSource,
    /// Process that observed the binding, when known. `None` for passive DNS
    /// snoop answers, which carry no process identity.
    process_name: Option<String>,
    process_exe: Option<String>,
    /// Destination port observed when the binding was learned in-band.
    /// `None` for DNS-derived bindings, which carry no port; those only
    /// describe ports that speak a hostname-bearing protocol
    /// ([`port_accepts_dns_prior`]).
    port: Option<u16>,
}

/// Ports where a name can legitimately describe the connection.
///
/// A DNS answer arrives without a port and without proof of which service the
/// caller will reach, so it is only a plausible name on ports that carry a
/// hostname (TLS, HTTP, and their common alternates). Treating it as
/// port-agnostic is how `ssh` to `:22` inherited an unrelated app's HTTPS
/// name from the shared IP→domain cache.
fn port_accepts_dns_prior(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443)
}

impl DomainEntry {
    fn alive(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|t| t > now)
    }

    /// Whether this binding can describe a connection to `port`.
    ///
    /// An in-band observation must match the port it was seen on. A DNS answer
    /// has no port and may describe only hostname-bearing ports.
    fn port_matches(&self, port: u16) -> bool {
        match self.port {
            Some(observed) => observed == port,
            None => port_accepts_dns_prior(port),
        }
    }

    fn has_owner(&self) -> bool {
        self.process_name.is_some() || self.process_exe.is_some()
    }
}

/// Process identity comparison for cache lookups: the executable path is the
/// strong key when both sides have one; otherwise fall back to the display
/// name. An unknown identity on either side never proves a match.
fn same_process(
    entry_name: Option<&str>,
    entry_exe: Option<&str>,
    name: Option<&str>,
    exe: Option<&str>,
) -> bool {
    match (entry_exe, exe) {
        (Some(a), Some(b)) => a == b,
        _ => match (entry_name, name) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
    }
}

/// Shared, thread-safe cache of `dst_ip → [domains]` bindings learned from
/// SNI, HTTP Host headers, and DNS answers.
///
/// Populated by the NFQUEUE run loop whenever a TLS ClientHello carries an
/// SNI, and by the DNS snoop / forwarder from A and AAAA answers. Consulted
/// by `FlowClassifier` for every subsequent packet to the same IP so the
/// domain survives beyond the ClientHello and rules keep matching.
///
/// An IP maps to a *list* of domains ordered most-recent-first: several
/// domains legitimately share one IP (CDN multi-tenancy, shared hosting),
/// and a single-valued map made the last writer win, mislabeling (and for
/// proxied routing, misrouting) every other domain on that IP.
///
/// Bindings are also scoped by the process that observed them. Policy paths
/// must use [`SniDnsCache::lookup_for`], which refuses a binding owned by a
/// different process: an IP→domain map shared by every local app was how
/// `ssh` inherited another app's HTTPS name. [`SniDnsCache::lookup`] remains
/// for display-only callers (e.g. the transparent proxy's dialog name).
#[derive(Clone, Default)]
pub struct SniDnsCache(Arc<Mutex<HashMap<String, Vec<DomainEntry>>>>);

impl SniDnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an in-band hint (SNI / HTTP Host / cmdline) observed on a
    /// connection to `ip:port` by `process_name`/`process_exe`.
    pub fn insert_in_band(
        &self,
        ip: impl Into<String>,
        port: u16,
        domain: impl Into<String>,
        source: DomainSource,
        process_name: Option<&str>,
        process_exe: Option<&str>,
    ) {
        debug_assert!(
            source.is_in_band() || source == DomainSource::Cmdline,
            "insert_in_band called with non-in-band source {source:?}"
        );
        self.insert_entry(
            ip,
            DomainEntry {
                domain: domain.into(),
                expires_at: None,
                source,
                process_name: process_name.map(str::to_string),
                process_exe: process_exe.map(str::to_string),
                port: Some(port),
            },
        );
    }

    /// Record a DNS-learned binding for `ip → domain`, expiring after
    /// `ttl_secs` (clamped to `[MIN_TTL_SECS, MAX_TTL_SECS]`).
    ///
    /// `process_name`/`process_exe` identify the app that resolved the name,
    /// when the caller knows it. Passive snoop answers pass `None`.
    pub fn insert_dns(
        &self,
        ip: impl Into<String>,
        domain: impl Into<String>,
        ttl_secs: u64,
        process_name: Option<&str>,
        process_exe: Option<&str>,
    ) {
        let expires_at =
            Instant::now() + Duration::from_secs(ttl_secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS));
        self.insert_entry(
            ip,
            DomainEntry {
                domain: domain.into(),
                expires_at: Some(expires_at),
                source: DomainSource::Dns,
                process_name: process_name.map(str::to_string),
                process_exe: process_exe.map(str::to_string),
                port: None,
            },
        );
    }

    fn insert_entry(&self, ip: impl Into<String>, entry: DomainEntry) {
        if entry.domain.is_empty() {
            return;
        }
        let now = Instant::now();
        let Ok(mut m) = self.0.lock() else {
            return;
        };

        if m.len() >= MAX_IPS {
            m.retain(|_, list| list.iter().any(|e| e.alive(now)));
        }

        let list = m.entry(ip.into()).or_default();
        // Replace the same (domain, port, process) binding, keeping a distinct
        // process's observation of the same domain alive.
        list.retain(|e| {
            !(e.domain == entry.domain
                && e.port == entry.port
                && e.process_name == entry.process_name
                && e.process_exe == entry.process_exe)
        });
        list.insert(0, entry);
        list.truncate(MAX_DOMAINS_PER_IP);
    }

    /// Most recent live domain for `ip`, or `None`. Expired entries are
    /// pruned as a side effect. Display-only: this ignores process ownership,
    /// so policy paths must use [`SniDnsCache::lookup_for`].
    pub fn lookup(&self, ip: &str) -> Option<String> {
        let mut m = self.0.lock().ok()?;
        let now = Instant::now();
        let list = m.get_mut(ip)?;
        list.retain(|e| e.alive(now));
        if list.is_empty() {
            m.remove(ip);
            return None;
        }
        Some(list[0].domain.clone())
    }

    /// Process-scoped lookup for policy paths.
    ///
    /// Only bindings that can describe a connection to `port` are considered.
    /// A binding owned by this process wins. Otherwise an *unowned* binding
    /// (passive DNS snoop, or a relay-only resolver) is returned only when it
    /// names a single live domain — anything else would be a guess. A binding
    /// owned by a local process never describes a different caller, and never
    /// describes a caller with no identity at all, which is what stops `ssh`
    /// from inheriting another app's HTTPS name.
    ///
    /// Callers with no process identity (forwarded traffic, `/proc` race) get
    /// an unambiguous unowned name, otherwise `None`.
    pub fn lookup_for(
        &self,
        ip: &str,
        port: u16,
        process_name: Option<&str>,
        process_exe: Option<&str>,
    ) -> Option<String> {
        let mut m = self.0.lock().ok()?;
        let now = Instant::now();
        let list = m.get_mut(ip)?;
        list.retain(|e| e.alive(now));
        if list.is_empty() {
            m.remove(ip);
            return None;
        }

        let has_candidate = list.iter().any(|e| e.port_matches(port));
        if !has_candidate {
            counter!("netkeep.domain.cache_lookup", "result" => "miss").increment(1);
            return None;
        }

        let caller_known = process_name.is_some() || process_exe.is_some();
        if caller_known {
            let observed =
                domain_choice(list.iter().filter(|e| e.port_matches(port)).filter(|e| {
                    same_process(
                        e.process_name.as_deref(),
                        e.process_exe.as_deref(),
                        process_name,
                        process_exe,
                    )
                }));
            // The caller itself observed these bindings — the strongest
            // evidence a cache hit can carry. It may still have observed more
            // than one name on this IP (a shared CDN), and then the cache
            // cannot say which name this connection is for.
            match observed {
                DomainChoice::None => {}
                DomainChoice::One(domain) => {
                    counter!("netkeep.domain.cache_lookup", "result" => "observed").increment(1);
                    return Some(domain.to_string());
                }
                DomainChoice::Many => {
                    counter!("netkeep.domain.cache_lookup", "result" => "ambiguous").increment(1);
                    return None;
                }
            }
        }
        // Every remaining binding belongs to a different process, or the
        // caller has no identity at all — neither can claim an owned name.
        match domain_choice(
            list.iter()
                .filter(|e| e.port_matches(port) && !e.has_owner()),
        ) {
            DomainChoice::None => {
                counter!("netkeep.domain.cache_lookup", "result" => "miss").increment(1);
                None
            }
            DomainChoice::One(only) => {
                // A single unowned name is the only cache prior allowed to
                // label a flow for a process that never resolved it. Counting
                // it makes the "process/domain pair was never observed"
                // volume visible during replay acceptance.
                counter!("netkeep.domain.cache_lookup", "result" => "unobserved_pair").increment(1);
                Some(only.to_string())
            }
            DomainChoice::Many => {
                counter!("netkeep.domain.cache_lookup", "result" => "ambiguous").increment(1);
                None
            }
        }
    }
}

/// What the live bindings for one `(ip, port)` say about the domain.
///
/// Scans lazily: the packet path may not allocate two vectors and sort them
/// just to learn that the names disagree.
enum DomainChoice<'a> {
    /// No binding survived the filter.
    None,
    /// Every binding agrees on this name.
    One(&'a str),
    /// Bindings disagree; the cache cannot choose.
    Many,
}

fn domain_choice<'a>(entries: impl IntoIterator<Item = &'a DomainEntry>) -> DomainChoice<'a> {
    let mut found: Option<&'a str> = None;
    for entry in entries {
        match found {
            None => found = Some(entry.domain.as_str()),
            Some(name) if name == entry.domain.as_str() => {}
            Some(_) => return DomainChoice::Many,
        }
    }
    match found {
        None => DomainChoice::None,
        Some(name) => DomainChoice::One(name),
    }
}

impl DnsResolver for SniDnsCache {
    fn resolve_dns(&self, dst_ip: &str) -> Option<String> {
        self.lookup(dst_ip)
    }

    fn resolve_dns_for(
        &self,
        dst_ip: &str,
        dst_port: u16,
        process_name: Option<&str>,
        process_exe: Option<&str>,
    ) -> Option<String> {
        self.lookup_for(dst_ip, dst_port, process_name, process_exe)
    }
}

/// Raw packet information from the network layer before classification.
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
    /// Domain hint extracted from the packet payload.
    ///
    /// For HTTPS / TLS this is the SNI value from the ClientHello. For
    /// plaintext HTTP/1.x it's the `Host:` header value (with `:port`
    /// suffix stripped and lowercased). Both feed the same `SniDnsCache`
    /// so that later packets in the same connection — and any other
    /// connections to the same IP — also resolve to a domain.
    ///
    /// The field name is `sni_hint` for historical reasons; both
    /// `sni::extract_tls_sni` and `sni::extract_http_host` in this crate
    /// write to it.
    pub sni_hint: Option<String>,
    /// Provenance of `sni_hint`: `Sni` for a TLS ClientHello, `Host` for a
    /// plaintext HTTP `Host:` header, `None` when no hint was extracted.
    /// `FlowClassifier` copies this into `FlowContext::domain_source` so the
    /// deferral guard can tell a real in-band name from a cache prior.
    pub domain_hint_source: DomainSource,
    /// Network interface the packet arrived on (populated for gateway/routed traffic).
    pub ingress_interface: Option<String>,
    /// True when the TCP payload carries no application data (SYN, pure ACK, FIN, RST).
    /// Used to skip SNI/Host extraction for control-only frames.
    pub tcp_payload_empty: bool,
    /// True when the TCP FIN flag is set (connection teardown initiated by this side).
    pub tcp_fin: bool,
    /// True when the TCP RST flag is set (connection forcibly reset).
    pub tcp_rst: bool,
    /// True when the TCP SYN flag is set (first packet of a connection).
    /// Distinguishes the connection-initiating handshake from pure ACKs
    /// mid-connection: both have `tcp_payload_empty=true`, but only the SYN
    /// must be classified — otherwise conntrack records a no-NAT decision
    /// for the connection before the routing rule ever runs, and a later
    /// data packet's fwmark can't undo that.
    pub tcp_syn: bool,
    /// UID of the socket that produced this packet, as reported by the
    /// kernel (`NFQA_UID`) at NFQUEUE enqueue time. Race-free credentials —
    /// used to reject candidate (pid, socket) matches that belong to a
    /// different user. `None` for forwarded packets (no local socket) or
    /// when the kernel/crate cannot deliver the attribute.
    pub sk_uid: Option<u32>,
    /// True when the packet was captured on the FORWARD hook (routed
    /// traffic from containers/VMs/LAN clients) rather than OUTPUT.
    /// Forwarded packets may have no local socket at all; attribution
    /// fallbacks that guess from destination caches must be skipped.
    pub forwarded: bool,
}

/// Full information about the local process that owns a network socket.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Display name — exe basename, possibly mapped to a user-friendly label
    /// (e.g. "cursor" instead of "electron" for Electron AppImage apps).
    pub name: String,
    /// Full path to the executable as read from `/proc/<pid>/exe`.
    /// Used as the unique identity for rule matching.
    pub exe: Option<String>,
    /// Process ID at resolution time, when known. The destination-keyed
    /// attribution cache compares it alongside the name so a recycled port
    /// under the same program name is still treated as a different owner.
    pub pid: Option<u32>,
    /// App name from the system package manager (e.g. `pacman -Qo <exe>` on
    /// Arch Linux). Shown alongside `name` in the decision dialog when it
    /// differs (e.g. name="electron", app_name="cursor").
    pub app_name: Option<String>,
}

/// Resolves the local process owning a network socket.
///
/// `sk_uid` is the packet's kernel-reported socket-owner UID (`NFQA_UID`),
/// when available. Implementations use it to reject candidate matches that
/// belong to a different user (port collisions across users, stale entries).
pub trait ProcessResolver {
    /// Resolve the owning process and say how it was established.
    ///
    /// The distinction matters: "no process" from a failed lookup and "no
    /// process, because the kernel owns the socket" lead to different
    /// decisions, and only the second one may bypass the dialog.
    fn lookup(
        &self,
        src_ip: &str,
        src_port: u16,
        protocol: TransportProtocol,
        sk_uid: Option<u32>,
    ) -> ProcessLookup;

    /// Convenience wrapper for callers that only need the process.
    fn resolve(
        &self,
        src_ip: &str,
        src_port: u16,
        protocol: TransportProtocol,
        sk_uid: Option<u32>,
    ) -> Option<ProcessInfo> {
        match self.lookup(src_ip, src_port, protocol, sk_uid) {
            ProcessLookup::Found(info) => Some(info),
            ProcessLookup::KernelOwned | ProcessLookup::Missing => None,
        }
    }
}

/// Outcome of a process lookup.
#[derive(Debug, Clone)]
pub enum ProcessLookup {
    Found(ProcessInfo),
    /// Inode found, the `/proc/*/fd` scan completed without permission errors,
    /// and no process owns it: a kernel service holds the socket.
    KernelOwned,
    /// Nothing could be proven. Never treat this as "no app".
    Missing,
}

/// Resolves a domain name from the DNS cache for a given destination IP.
pub trait DnsResolver {
    /// Process-agnostic lookup. Display-only callers may keep using this.
    fn resolve_dns(&self, dst_ip: &str) -> Option<String>;

    /// Process-scoped lookup used on policy paths. Implementations that do
    /// not track process ownership fall back to [`DnsResolver::resolve_dns`].
    fn resolve_dns_for(
        &self,
        dst_ip: &str,
        _dst_port: u16,
        _process_name: Option<&str>,
        _process_exe: Option<&str>,
    ) -> Option<String> {
        self.resolve_dns(dst_ip)
    }
}

/// Maps a network interface + source IP to a human-readable device label.
pub trait DeviceLabelResolver {
    fn resolve(&self, ingress_interface: &str, src_ip: &str) -> Option<String>;
}

pub struct FlowClassifier<P, D, L> {
    process_resolver: P,
    dns_resolver: D,
    device_label_resolver: L,
    /// Reverse-DNS names, display-only. `None` disables the lookup entirely.
    reverse_ptr: Option<std::sync::Arc<ptr::PtrCache>>,
}

impl<P, D, L> FlowClassifier<P, D, L>
where
    P: ProcessResolver,
    D: DnsResolver,
    L: DeviceLabelResolver,
{
    pub fn new(process_resolver: P, dns_resolver: D, device_label_resolver: L) -> Self {
        Self {
            process_resolver,
            dns_resolver,
            device_label_resolver,
            reverse_ptr: None,
        }
    }

    /// Attach the reverse-DNS cache. Names from it are display hints and are
    /// never used for rule matching.
    pub fn with_reverse_ptr(mut self, cache: std::sync::Arc<ptr::PtrCache>) -> Self {
        self.reverse_ptr = Some(cache);
        self
    }

    pub fn classify(&self, packet: &RawPacket) -> FlowContext {
        let start = Instant::now();
        let proto_str = match packet.protocol {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
            TransportProtocol::Quic => "quic",
            TransportProtocol::Other => "other",
        };

        let lookup = self.process_resolver.lookup(
            &packet.src_ip,
            packet.src_port,
            packet.protocol,
            packet.sk_uid,
        );

        let (proc_info, process_origin) = match lookup {
            ProcessLookup::Found(info) => (Some(info), ProcessOrigin::Proved),
            ProcessLookup::KernelOwned => (None, ProcessOrigin::Kernel),
            ProcessLookup::Missing => (None, ProcessOrigin::Unresolved),
        };

        if proc_info.is_some() {
            counter!("netkeep.process.resolved", "result" => "hit").increment(1);
        } else {
            counter!("netkeep.process.resolved", "result" => "miss").increment(1);
        }

        counter!("netkeep.flows.classified", "protocol" => proto_str).increment(1);

        let process_name = proc_info.as_ref().map(|p| p.name.clone());
        let process_exe = proc_info.as_ref().and_then(|p| p.exe.clone());
        let app_name = proc_info.as_ref().and_then(|p| p.app_name.clone());

        let (destination_domain, domain_source) = self.resolve_domain(packet, proc_info.as_ref());

        // Only ask when the packet itself gave no name: SNI/Host and the DNS
        // cache are observations about this connection, a PTR is a hint about
        // the address.
        let reverse_dns = if destination_domain.is_none() {
            self.reverse_ptr
                .as_ref()
                .and_then(|cache| cache.lookup(&packet.dst_ip))
        } else {
            None
        };

        let device_label = if process_name.is_none() {
            packet
                .ingress_interface
                .as_deref()
                .and_then(|iface| self.device_label_resolver.resolve(iface, &packet.src_ip))
        } else {
            None
        };

        histogram!("netkeep.flow.classification.duration").record(start.elapsed().as_secs_f64());

        FlowContext {
            process_name,
            process_origin,
            process_exe,
            app_name,
            source_ip: packet.src_ip.clone(),
            source_port: packet.src_port,
            destination_ip: packet.dst_ip.clone(),
            destination_port: packet.dst_port,
            destination_domain,
            reverse_dns,
            domain_source,
            protocol: packet.protocol,
            direction: FlowDirection::Outbound,
            device_label,
            tcp_syn: packet.tcp_syn,
        }
    }

    /// Resolve the destination domain and its provenance.
    ///
    /// Only the packet's own payload hint is in-band. A DNS-cache hit is
    /// always reported as [`DomainSource::Dns`], even when the cached entry
    /// was learned from another connection's SNI: it is a prior for the IP,
    /// not an observation for this connection, and must not decide a TLS SYN.
    fn resolve_domain(
        &self,
        packet: &RawPacket,
        proc_info: Option<&ProcessInfo>,
    ) -> (Option<String>, DomainSource) {
        let dns_domain = || {
            self.dns_resolver.resolve_dns_for(
                &packet.dst_ip,
                packet.dst_port,
                proc_info.map(|p| p.name.as_str()),
                proc_info.and_then(|p| p.exe.as_deref()),
            )
        };
        let sni_domain = packet.sni_hint.clone();

        let resolved = match (sni_domain, packet.protocol) {
            // QUIC: SNI is encrypted in QUIC v1; use DNS cache only.
            (_, TransportProtocol::Quic) => dns_domain().map(|d| (d, DomainSource::Dns)),
            // SNI/Host is authoritative — extracted directly from the packet
            // being classified. Always prefer it over the shared DNS cache,
            // which may be stale or overwritten by another domain sharing the
            // same CDN IP (a single IP → single domain map cannot correctly
            // represent CDN multi-tenancy).
            (Some(sni), _) => Some((sni, packet.domain_hint_source)),
            // No per-packet hint → fall back to the process-scoped cache.
            (None, _) => dns_domain().map(|d| (d, DomainSource::Dns)),
        };

        let resolved = resolved.map(|(domain, source)| {
            // A hint without provenance is treated as SNI (the only writer
            // before provenance existed was TLS extraction).
            let source = match (source, domain.is_empty()) {
                (DomainSource::None, false) => DomainSource::Sni,
                (s, _) => s,
            };
            let label = match source {
                DomainSource::None => "none",
                DomainSource::Sni => "sni",
                DomainSource::Host => "http_host",
                DomainSource::Dns => "dns_cache",
                DomainSource::Cmdline => "cmdline",
            };
            counter!("netkeep.domain.resolved", "source" => label).increment(1);
            (domain, source)
        });

        match resolved {
            Some((domain, source)) => (Some(domain), source),
            None => {
                counter!("netkeep.domain.resolved", "source" => "none").increment(1);
                (None, DomainSource::None)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test fakes
// ---------------------------------------------------------------------------

pub struct FakeProcessResolver {
    pub result: Option<String>,
}

impl ProcessResolver for FakeProcessResolver {
    fn lookup(
        &self,
        _src_ip: &str,
        _src_port: u16,
        _protocol: TransportProtocol,
        _sk_uid: Option<u32>,
    ) -> ProcessLookup {
        match &self.result {
            Some(name) => ProcessLookup::Found(ProcessInfo {
                name: name.clone(),
                exe: None,
                pid: None,
                app_name: None,
            }),
            None => ProcessLookup::Missing,
        }
    }
}

pub struct FakeDnsResolver {
    pub result: Option<String>,
}

impl DnsResolver for FakeDnsResolver {
    fn resolve_dns(&self, _dst_ip: &str) -> Option<String> {
        self.result.clone()
    }
}

pub struct FakeDeviceLabelResolver {
    pub result: Option<String>,
}

impl DeviceLabelResolver for FakeDeviceLabelResolver {
    fn resolve(&self, _iface: &str, _src_ip: &str) -> Option<String> {
        self.result.clone()
    }
}

/// Trait for classifying a raw packet into a `FlowContext`.
/// Implemented by `FlowClassifier` and test fakes.
pub trait Classifier {
    fn classify(&self, packet: &RawPacket) -> FlowContext;
}

impl<P, D, L> Classifier for FlowClassifier<P, D, L>
where
    P: ProcessResolver,
    D: DnsResolver,
    L: DeviceLabelResolver,
{
    fn classify(&self, packet: &RawPacket) -> FlowContext {
        self.classify(packet)
    }
}

/// Test fake that returns a fixed `FlowContext` regardless of the packet.
pub struct FakeClassifier {
    pub result: FlowContext,
}

impl Classifier for FakeClassifier {
    fn classify(&self, _packet: &RawPacket) -> FlowContext {
        self.result.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SniDnsCache: shared-IP multi-domain regression tests ─────────────
    //
    // The old cache was HashMap<ip, String>: the last writer won, so two
    // domains resolving to one IP mislabeled every connection to that IP.
    // These tests pin the new semantics.

    fn in_band(c: &SniDnsCache, ip: &str, port: u16, domain: &str, proc: Option<&str>) {
        c.insert_in_band(ip, port, domain, DomainSource::Sni, proc, None);
    }

    #[test]
    fn shared_ip_domains_coexist_most_recent_wins() {
        let c = SniDnsCache::new();
        in_band(&c, "1.2.3.4", 443, "a.example", Some("curl"));
        in_band(&c, "1.2.3.4", 443, "b.example", Some("curl"));
        // b was learned last → it wins, but a must not be destroyed.
        assert_eq!(c.lookup("1.2.3.4").as_deref(), Some("b.example"));

        // A fresh binding for a moves it back to the front.
        in_band(&c, "1.2.3.4", 443, "a.example", Some("curl"));
        assert_eq!(c.lookup("1.2.3.4").as_deref(), Some("a.example"));
        in_band(&c, "1.2.3.4", 443, "b.example", Some("curl"));
        assert_eq!(c.lookup("1.2.3.4").as_deref(), Some("b.example"));
    }

    #[test]
    fn per_ip_domain_list_is_capped() {
        let c = SniDnsCache::new();
        for i in 0..(MAX_DOMAINS_PER_IP + 4) {
            in_band(&c, "9.9.9.9", 443, &format!("d{i}.example"), Some("curl"));
        }
        assert_eq!(
            c.lookup("9.9.9.9").as_deref(),
            Some(format!("d{}.example", MAX_DOMAINS_PER_IP + 3).as_str())
        );
        // Oldest entries evicted — lookup only ever returns live ones.
        assert_eq!(c.lookup("d0.example").as_deref(), None);
    }

    #[test]
    fn expired_dns_binding_is_not_returned() {
        let c = SniDnsCache::new();
        // Already-expired binding (TTL in the past).
        c.insert_entry(
            "7.7.7.7",
            DomainEntry {
                domain: "gone.example".to_string(),
                expires_at: Some(Instant::now() - Duration::from_secs(1)),
                source: DomainSource::Dns,
                process_name: None,
                process_exe: None,
                port: None,
            },
        );
        c.insert_entry(
            "7.7.7.7",
            DomainEntry {
                domain: "live.example".to_string(),
                expires_at: Some(Instant::now() + Duration::from_secs(60)),
                source: DomainSource::Dns,
                process_name: None,
                process_exe: None,
                port: None,
            },
        );
        assert_eq!(c.lookup("7.7.7.7").as_deref(), Some("live.example"));

        // Everything expired → None, and the key is pruned.
        c.insert_entry(
            "8.8.8.8",
            DomainEntry {
                domain: "old.example".to_string(),
                expires_at: Some(Instant::now() - Duration::from_secs(1)),
                source: DomainSource::Dns,
                process_name: None,
                process_exe: None,
                port: None,
            },
        );
        assert_eq!(c.lookup("8.8.8.8"), None);
    }

    #[test]
    fn ttl_is_clamped() {
        let c = SniDnsCache::new();
        // TTL 0 is raised to the minimum rather than expiring instantly.
        c.insert_dns("6.6.6.6", "zero.example", 0, None, None);
        assert_eq!(c.lookup("6.6.6.6").as_deref(), Some("zero.example"));
    }

    #[test]
    fn empty_domain_is_ignored() {
        let c = SniDnsCache::new();
        in_band(&c, "5.5.5.5", 443, "", Some("curl"));
        assert_eq!(c.lookup("5.5.5.5"), None);
        // Lookup of a never-seen IP is None.
        assert_eq!(c.lookup("4.4.4.4"), None);
    }

    #[test]
    fn sni_hint_never_expires() {
        let c = SniDnsCache::new();
        in_band(&c, "3.3.3.3", 443, "sni.example", Some("curl"));
        // A later DNS binding for the same IP with a short TTL must not
        // evict the SNI entry from the list.
        c.insert_dns("3.3.3.3", "dns.example", 1, Some("curl"), None);
        assert_eq!(c.lookup("3.3.3.3").as_deref(), Some("dns.example"));
        in_band(&c, "3.3.3.3", 443, "sni.example", Some("curl"));
        assert_eq!(c.lookup("3.3.3.3").as_deref(), Some("sni.example"));
    }

    // ── Process-scoped lookups (the `ssh` inheritance fix) ───────────────

    #[test]
    fn lookup_for_returns_none_for_a_different_process() {
        let c = SniDnsCache::new();
        c.insert_dns("5.202.198.83", "sm.logicamp.dev", 60, Some("brave"), None);

        assert_eq!(
            c.lookup_for("5.202.198.83", 443, Some("ssh"), None),
            None,
            "a name resolved by brave must not describe an ssh connection"
        );
        assert_eq!(
            c.lookup_for("5.202.198.83", 443, Some("brave"), None)
                .as_deref(),
            Some("sm.logicamp.dev"),
            "the owning process keeps the binding"
        );
    }

    /// Forwarded packets and `/proc` misses have no local socket, so a name
    /// owned by a local app cannot describe them either.
    #[test]
    fn lookup_for_ownerless_caller_cannot_claim_an_owned_binding() {
        let c = SniDnsCache::new();
        c.insert_in_band(
            "203.0.113.9",
            443,
            "app.example",
            DomainSource::Sni,
            Some("brave"),
            Some("/usr/bin/brave"),
        );

        assert_eq!(
            c.lookup_for("203.0.113.9", 443, None, None),
            None,
            "an unidentified caller must not inherit a local app's name"
        );
        // An unowned (relay-learned) binding is still available to it.
        let unowned = SniDnsCache::new();
        unowned.insert_dns("203.0.113.9", "relay.example", 60, None, None);
        assert_eq!(
            unowned
                .lookup_for("203.0.113.9", 443, None, None)
                .as_deref(),
            Some("relay.example")
        );
    }

    #[test]
    fn lookup_for_returns_none_when_the_caller_has_two_names_on_one_ip() {
        let c = SniDnsCache::new();
        in_band(&c, "188.114.98.0", 443, "a.example", Some("chrome"));
        in_band(&c, "188.114.98.0", 443, "b.example", Some("chrome"));

        assert_eq!(
            c.lookup_for("188.114.98.0", 443, Some("chrome"), None),
            None,
            "one process with two live names on one IP is still ambiguous"
        );

        // Deduplicating the same name observed twice is not ambiguity.
        let same = SniDnsCache::new();
        in_band(&same, "188.114.98.0", 443, "a.example", Some("chrome"));
        in_band(&same, "188.114.98.0", 443, "a.example", Some("chrome"));
        assert_eq!(
            same.lookup_for("188.114.98.0", 443, Some("chrome"), None)
                .as_deref(),
            Some("a.example")
        );
    }

    #[test]
    fn lookup_for_returns_none_for_an_ambiguous_ip() {
        let c = SniDnsCache::new();
        c.insert_dns("188.114.98.0", "synara-orgs.workers.dev", 60, None, None);
        c.insert_dns("188.114.98.0", "api.zed.dev", 60, None, None);

        assert_eq!(
            c.lookup_for("188.114.98.0", 443, None, None),
            None,
            "an IP carrying several names has no truthful single answer"
        );
        // One live name and no owner is the only unowned case that resolves.
        let single = SniDnsCache::new();
        single.insert_dns("188.114.98.0", "synara-orgs.workers.dev", 60, None, None);
        assert_eq!(
            single
                .lookup_for("188.114.98.0", 443, None, None)
                .as_deref(),
            Some("synara-orgs.workers.dev")
        );
    }

    #[test]
    fn lookup_for_does_not_borrow_a_name_across_ports() {
        let c = SniDnsCache::new();
        // An HTTPS binding learned in-band must not describe an SSH port.
        in_band(&c, "5.202.198.83", 443, "sm.logicamp.dev", Some("ssh"));
        assert_eq!(c.lookup_for("5.202.198.83", 52176, Some("ssh"), None), None);
        assert_eq!(
            c.lookup_for("5.202.198.83", 443, Some("ssh"), None)
                .as_deref(),
            Some("sm.logicamp.dev")
        );
    }

    // ── Port scoping for DNS-derived names (Stage 1 item 2) ──────────────
    //
    // A DNS answer carries no port, so it cannot prove it describes a
    // non-web service. Before this rule, one unowned HTTPS name on an IP was
    // enough to label an `ssh` connection to `:22` (the reported
    // `oevaite.kaariiz.com` / `sm.logicamp.dev` oscillation).

    #[test]
    fn unowned_dns_name_does_not_describe_a_non_web_port() {
        let c = SniDnsCache::new();
        c.insert_dns("5.202.198.83", "sm.logicamp.dev", 60, None, None);

        assert_eq!(
            c.lookup_for("5.202.198.83", 22, Some("ssh"), None),
            None,
            "a web name must not label an ssh connection"
        );
        assert_eq!(
            c.lookup_for("5.202.198.83", 443, Some("ssh"), None)
                .as_deref(),
            Some("sm.logicamp.dev"),
            "the same name is still a prior on a hostname-bearing port"
        );
    }

    /// Even the process that resolved the name cannot carry it onto a
    /// non-web port: `ssh hostA` and `ssh hostB` may resolve to the same IP,
    /// and the answer does not prove which host this connection targets.
    #[test]
    fn owned_dns_name_does_not_describe_a_non_web_port() {
        let c = SniDnsCache::new();
        c.insert_dns("5.202.198.83", "host-a.example", 60, Some("ssh"), None);

        assert_eq!(c.lookup_for("5.202.198.83", 22, Some("ssh"), None), None);
        assert_eq!(
            c.lookup_for("5.202.198.83", 443, Some("ssh"), None)
                .as_deref(),
            Some("host-a.example")
        );
    }

    /// In-band observations are port-specific, so they still describe the
    /// exact port they were seen on — including non-web ports.
    #[test]
    fn in_band_name_still_describes_its_own_non_web_port() {
        let c = SniDnsCache::new();
        in_band(&c, "5.202.198.83", 22, "shell.example", Some("ssh"));
        assert_eq!(
            c.lookup_for("5.202.198.83", 22, Some("ssh"), None)
                .as_deref(),
            Some("shell.example")
        );
    }

    fn classifier(
        process: Option<&str>,
        dns: Option<&str>,
        device_label: Option<&str>,
    ) -> FlowClassifier<FakeProcessResolver, FakeDnsResolver, FakeDeviceLabelResolver> {
        FlowClassifier::new(
            FakeProcessResolver {
                result: process.map(str::to_string),
            },
            FakeDnsResolver {
                result: dns.map(str::to_string),
            },
            FakeDeviceLabelResolver {
                result: device_label.map(str::to_string),
            },
        )
    }

    fn packet(protocol: TransportProtocol, sni: Option<&str>, iface: Option<&str>) -> RawPacket {
        RawPacket {
            src_ip: "192.168.1.5".to_string(),
            src_port: 54321,
            dst_ip: "1.1.1.1".to_string(),
            dst_port: 443,
            protocol,
            sni_hint: sni.map(str::to_string),
            domain_hint_source: if sni.is_some() {
                DomainSource::Sni
            } else {
                DomainSource::None
            },
            ingress_interface: iface.map(str::to_string),
            tcp_payload_empty: false,
            tcp_fin: false,
            tcp_rst: false,
            tcp_syn: false,
            sk_uid: None,
            forwarded: false,
        }
    }

    #[test]
    fn process_attribution_success() {
        let c = classifier(Some("curl"), None, None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, None, None));
        assert_eq!(ctx.process_name.as_deref(), Some("curl"));
    }

    #[test]
    fn process_attribution_missing_falls_back_to_none() {
        let c = classifier(None, None, None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, None, None));
        assert_eq!(ctx.process_name, None);
    }

    #[test]
    fn dns_derived_domain_association() {
        let c = classifier(Some("curl"), Some("example.com"), None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, None, None));
        assert_eq!(ctx.destination_domain.as_deref(), Some("example.com"));
        assert_eq!(ctx.domain_source, DomainSource::Dns);
    }

    #[test]
    fn sni_derived_domain_association() {
        let c = classifier(Some("curl"), None, None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, Some("example.com"), None));
        assert_eq!(ctx.destination_domain.as_deref(), Some("example.com"));
        assert_eq!(ctx.domain_source, DomainSource::Sni);
    }

    #[test]
    fn sni_overrides_stale_dns_cache_on_cdn_ip() {
        // A CDN IP serves multiple domains. The DNS cache has one domain
        // (stale, written by a different connection) but the current packet's
        // SNI is authoritative. SNI wins.
        let c = classifier(Some("curl"), Some("other-customer.com"), None);
        let ctx = c.classify(&packet(
            TransportProtocol::Tcp,
            Some("api2.cursor.sh"),
            None,
        ));
        assert_eq!(ctx.destination_domain.as_deref(), Some("api2.cursor.sh"));
    }

    #[test]
    fn dns_cache_used_when_no_sni() {
        // No SNI in packet → fall back to DNS cache.
        let c = classifier(Some("curl"), Some("example.com"), None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, None, None));
        assert_eq!(ctx.destination_domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn quic_falls_back_to_dns_ignores_sni() {
        // QUIC with both sources: SNI is ignored, DNS is used.
        let c = classifier(Some("app"), Some("quic-cdn.com"), None);
        let ctx = c.classify(&packet(
            TransportProtocol::Quic,
            Some("different.com"),
            None,
        ));
        assert_eq!(ctx.destination_domain.as_deref(), Some("quic-cdn.com"));

        // QUIC with no DNS: domain is None regardless of SNI.
        let c2 = classifier(Some("app"), None, None);
        let ctx2 = c2.classify(&packet(
            TransportProtocol::Quic,
            Some("different.com"),
            None,
        ));
        assert_eq!(ctx2.destination_domain, None);
    }

    #[test]
    fn gateway_flow_device_label_attached() {
        // No local process → device label resolver is consulted.
        let c = classifier(None, None, Some("home-laptop"));
        let ctx = c.classify(&packet(TransportProtocol::Tcp, None, Some("eth0")));
        assert_eq!(ctx.process_name, None);
        assert_eq!(ctx.device_label.as_deref(), Some("home-laptop"));
    }
}

// ---------------------------------------------------------------------------
// eBPF socket tracker trait (decouples flow-classifier from dns-tracker)
// ---------------------------------------------------------------------------

/// eBPF-based socket tracker that captures PIDs at socket creation time.
///
/// This trait decouples `flow-classifier` from the `dns-tracker` crate (which
/// provides the eBPF loader). When available, the eBPF map is checked *before*
/// SOCK_DIAG or `/proc/net` lookups, eliminating TOCTOU races entirely.
pub trait SocketTracker: Send + Sync {
    /// Look up the PID and UID for a socket by source IP, port, and protocol.
    ///
    /// Returns `None` if the eBPF map has no entry (socket created before the
    /// tracker was loaded, or the entry was evicted).
    fn lookup_pid(
        &self,
        src_ip: std::net::IpAddr,
        src_port: u16,
        protocol: TransportProtocol,
    ) -> Option<TrackedProcess>;
}

/// Result from the eBPF socket tracker: PID and UID captured at socket
/// creation/send time.
#[derive(Debug, Clone)]
pub struct TrackedProcess {
    pub pid: u32,
    pub uid: u32,
    /// Process comm captured at eBPF hook time — survives the exit race
    /// that empties /proc/<pid>/exe for short-lived processes.
    pub comm: String,
    /// Which BPF map the entry came from — the port-only fallback map is
    /// inherently ambiguous (ports are not unique across sockets) and its
    /// answers carry lower confidence.
    pub source: TrackerSource,
}

/// Which eBPF map satisfied a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerSource {
    /// `SOCK_EVENTS[(src_ip, src_port, protocol)]` — full socket key.
    FullKey,
    /// `PORT_PIDS[(src_port, protocol)]` — port-only fallback for
    /// unconnected UDP sockets (source address unknown at send time).
    PortKey,
    /// Test fakes that don't model the two-map split.
    Unknown,
}

impl TrackerSource {
    pub fn label(&self) -> &'static str {
        match self {
            TrackerSource::FullKey => "full-key",
            TrackerSource::PortKey => "port-key",
            TrackerSource::Unknown => "unknown",
        }
    }
}
