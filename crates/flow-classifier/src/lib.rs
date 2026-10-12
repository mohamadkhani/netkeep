pub mod diag;
pub mod proc_resolver;
pub mod sni;
pub mod sock_diag;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use core_types::{FlowContext, FlowDirection, TransportProtocol};
use metrics::{counter, histogram};

// ── SNI DNS cache ──────────────────────────────────────────────────────────────

/// Maximum hostnames kept per destination IP (most-recent-first list).
/// CDN IPs legitimately serve many domains; the list must hold them all
/// instead of overwriting.
const MAX_DOMAINS_PER_IP: usize = 8;
/// Soft cap on tracked IPs before an expiry sweep runs.
const MAX_IPS: usize = 8192;
/// Clamp for DNS-derived TTLs (seconds). TTL 0 answers are kept for the
/// minimum so a connection landing in the same second still resolves.
const MIN_TTL_SECS: u64 = 1;
const MAX_TTL_SECS: u64 = 86_400;

/// One learned `ip → domain` binding with optional expiry.
struct DomainEntry {
    domain: String,
    /// `None` for in-band hints (SNI/Host — valid until evicted),
    /// `Some` for DNS answers (expires per the DNS record TTL).
    expires_at: Option<Instant>,
}

impl DomainEntry {
    fn alive(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|t| t > now)
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
#[derive(Clone, Default)]
pub struct SniDnsCache(Arc<Mutex<HashMap<String, Vec<DomainEntry>>>>);

impl SniDnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `ip` resolved to `domain`.
    ///
    /// * `ttl_secs = Some(s)` — DNS-learned binding, expires after `s`
    ///   seconds (clamped to `[MIN_TTL_SECS, MAX_TTL_SECS]`).
    /// * `ttl_secs = None` — in-band hint (SNI / HTTP Host), kept until
    ///   evicted by newer entries.
    ///
    /// Re-inserting a known domain moves it to the front (most recent).
    pub fn insert_with_ttl(
        &self,
        ip: impl Into<String>,
        domain: impl Into<String>,
        ttl_secs: Option<u64>,
    ) {
        let expires_at = ttl_secs
            .map(|s| Instant::now() + Duration::from_secs(s.clamp(MIN_TTL_SECS, MAX_TTL_SECS)));
        self.insert_at(ip, domain, expires_at);
    }

    /// Record an in-band hint (SNI / HTTP Host) that never TTL-expires.
    pub fn insert(&self, ip: impl Into<String>, domain: impl Into<String>) {
        self.insert_at(ip, domain, None);
    }

    fn insert_at(
        &self,
        ip: impl Into<String>,
        domain: impl Into<String>,
        expires_at: Option<Instant>,
    ) {
        let domain = domain.into();
        if domain.is_empty() {
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
        list.retain(|e| e.domain != domain);
        list.insert(0, DomainEntry { domain, expires_at });
        list.truncate(MAX_DOMAINS_PER_IP);
    }

    /// Most recent live domain for `ip`, or `None`. Expired entries are
    /// pruned as a side effect.
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
}

impl DnsResolver for SniDnsCache {
    fn resolve_dns(&self, dst_ip: &str) -> Option<String> {
        self.lookup(dst_ip)
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
    fn resolve(
        &self,
        src_ip: &str,
        src_port: u16,
        protocol: TransportProtocol,
        sk_uid: Option<u32>,
    ) -> Option<ProcessInfo>;
}

/// Resolves a domain name from the DNS cache for a given destination IP.
pub trait DnsResolver {
    fn resolve_dns(&self, dst_ip: &str) -> Option<String>;
}

/// Maps a network interface + source IP to a human-readable device label.
pub trait DeviceLabelResolver {
    fn resolve(&self, ingress_interface: &str, src_ip: &str) -> Option<String>;
}

pub struct FlowClassifier<P, D, L> {
    process_resolver: P,
    dns_resolver: D,
    device_label_resolver: L,
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
        }
    }

    pub fn classify(&self, packet: &RawPacket) -> FlowContext {
        let start = Instant::now();
        let proto_str = match packet.protocol {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
            TransportProtocol::Quic => "quic",
            TransportProtocol::Other => "other",
        };

        let proc_info = self.process_resolver.resolve(
            &packet.src_ip,
            packet.src_port,
            packet.protocol,
            packet.sk_uid,
        );

        if proc_info.is_some() {
            counter!("netkeep.process.resolved", "result" => "hit").increment(1);
        } else {
            counter!("netkeep.process.resolved", "result" => "miss").increment(1);
        }

        counter!("netkeep.flows.classified", "protocol" => proto_str).increment(1);

        let process_name = proc_info.as_ref().map(|p| p.name.clone());
        let process_exe = proc_info.as_ref().and_then(|p| p.exe.clone());
        let app_name = proc_info.as_ref().and_then(|p| p.app_name.clone());

        let destination_domain = self.resolve_domain(packet);

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
            process_exe,
            app_name,
            source_ip: packet.src_ip.clone(),
            source_port: packet.src_port,
            destination_ip: packet.dst_ip.clone(),
            destination_port: packet.dst_port,
            destination_domain,
            protocol: packet.protocol,
            direction: FlowDirection::Outbound,
            device_label,
            tcp_syn: packet.tcp_syn,
        }
    }

    fn resolve_domain(&self, packet: &RawPacket) -> Option<String> {
        let dns_domain = self.dns_resolver.resolve_dns(&packet.dst_ip);
        let sni_domain = packet.sni_hint.clone();

        let resolved = match (sni_domain, dns_domain) {
            // QUIC: SNI is encrypted in QUIC v1; use DNS cache only.
            (_, dns) if packet.protocol == TransportProtocol::Quic => dns,
            // SNI/Host is authoritative — extracted directly from the packet
            // being classified. Always prefer it over the shared DNS cache,
            // which may be stale or overwritten by another domain sharing the
            // same CDN IP (a single IP → single domain map cannot correctly
            // represent CDN multi-tenancy).
            (Some(sni), _) => Some(sni),
            // No per-packet hint → fall back to DNS cache.
            (None, Some(dns)) => Some(dns),
            (None, None) => None,
        };

        let source = if resolved.is_none() {
            "none"
        } else if packet.protocol == TransportProtocol::Quic {
            "dns_cache"
        } else if packet.sni_hint.is_some() {
            "sni"
        } else {
            "dns_cache"
        };
        counter!("netkeep.domain.resolved", "source" => source).increment(1);

        resolved
    }
}

// ---------------------------------------------------------------------------
// Test fakes
// ---------------------------------------------------------------------------

pub struct FakeProcessResolver {
    pub result: Option<String>,
}

impl ProcessResolver for FakeProcessResolver {
    fn resolve(
        &self,
        _src_ip: &str,
        _src_port: u16,
        _protocol: TransportProtocol,
        _sk_uid: Option<u32>,
    ) -> Option<ProcessInfo> {
        self.result.as_ref().map(|name| ProcessInfo {
            name: name.clone(),
            exe: None,
            app_name: None,
        })
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

    #[test]
    fn shared_ip_domains_coexist_most_recent_wins() {
        let c = SniDnsCache::new();
        c.insert("1.2.3.4", "a.example");
        c.insert("1.2.3.4", "b.example");
        // b was learned last → it wins, but a must not be destroyed.
        assert_eq!(c.lookup("1.2.3.4").as_deref(), Some("b.example"));

        // A fresh binding for a moves it back to the front.
        c.insert("1.2.3.4", "a.example");
        assert_eq!(c.lookup("1.2.3.4").as_deref(), Some("a.example"));
        c.insert("1.2.3.4", "b.example");
        assert_eq!(c.lookup("1.2.3.4").as_deref(), Some("b.example"));
    }

    #[test]
    fn per_ip_domain_list_is_capped() {
        let c = SniDnsCache::new();
        for i in 0..(MAX_DOMAINS_PER_IP + 4) {
            c.insert("9.9.9.9", format!("d{i}.example"));
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
        c.insert_at(
            "7.7.7.7",
            "gone.example",
            Some(Instant::now() - Duration::from_secs(1)),
        );
        c.insert_at(
            "7.7.7.7",
            "live.example",
            Some(Instant::now() + Duration::from_secs(60)),
        );
        assert_eq!(c.lookup("7.7.7.7").as_deref(), Some("live.example"));

        // Everything expired → None, and the key is pruned.
        c.insert_at(
            "8.8.8.8",
            "old.example",
            Some(Instant::now() - Duration::from_secs(1)),
        );
        assert_eq!(c.lookup("8.8.8.8"), None);
    }

    #[test]
    fn ttl_is_clamped() {
        let c = SniDnsCache::new();
        // TTL 0 is raised to the minimum rather than expiring instantly.
        c.insert_with_ttl("6.6.6.6", "zero.example", Some(0));
        assert_eq!(c.lookup("6.6.6.6").as_deref(), Some("zero.example"));
    }

    #[test]
    fn empty_domain_is_ignored() {
        let c = SniDnsCache::new();
        c.insert("5.5.5.5", "");
        assert_eq!(c.lookup("5.5.5.5"), None);
        // Lookup of a never-seen IP is None.
        assert_eq!(c.lookup("4.4.4.4"), None);
    }

    #[test]
    fn sni_hint_never_expires() {
        let c = SniDnsCache::new();
        c.insert("3.3.3.3", "sni.example");
        // A later DNS binding for the same IP with a short TTL must not
        // evict the SNI entry from the list.
        c.insert_with_ttl("3.3.3.3", "dns.example", Some(1));
        assert_eq!(c.lookup("3.3.3.3").as_deref(), Some("dns.example"));
        c.insert("3.3.3.3", "sni.example");
        assert_eq!(c.lookup("3.3.3.3").as_deref(), Some("sni.example"));
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
    }

    #[test]
    fn sni_derived_domain_association() {
        let c = classifier(Some("curl"), None, None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, Some("example.com"), None));
        assert_eq!(ctx.destination_domain.as_deref(), Some("example.com"));
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
