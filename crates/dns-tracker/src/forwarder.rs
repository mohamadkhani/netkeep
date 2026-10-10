use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use core_types::{ProxyConfig, RouteTarget, TransportProtocol};
use flow_classifier::{proc_resolver::ProcProcessResolver, ProcessResolver, SniDnsCache};
use state_store::ProxyRepository;

use crate::tracker::DnsTracker;

/// Timeout for DNS-over-SOCKS5 handshake and TCP exchange.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum DNS message size (standard UDP limit).
const DNS_BUF: usize = 512;

/// DNS RCODE 2 — server failure (RFC 1035 §4.1.1). Returned to the app when
/// egress resolution fails, instead of leaking the query to system DNS.
const RCODE_SERVFAIL: u8 = 2;

/// Comms of well-known local stub/caching resolvers (bpf comm is truncated
/// to 15 bytes, hence `systemd-resolve`). Queries arriving from these are
/// re-attributed to the real app via [`DnsForwarder::resolve_behind_resolver`].
const LOCAL_RESOLVER_COMMS: &[&str] = &[
    "systemd-resolve",
    "dnsmasq",
    "unbound",
    "stubby",
    "dnscrypt-proxy",
    "kresd",
    "pdns-recursor",
    "dohclient",
];

/// Whether `comm` belongs to a local resolver or to this daemon itself.
/// Empty comm (attribution failed) is treated like a resolver so the
/// behind-resolver recovery still gets a chance to name the real app.
fn is_local_resolver_comm(comm: &str) -> bool {
    comm.is_empty()
        || comm.starts_with("netkeep")
        || LOCAL_RESOLVER_COMMS.iter().any(|r| comm.starts_with(r))
}

/// Read a process name from `/proc/<pid>/comm`.
fn comm_for_pid(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Dispatch function: given `(process_name, domain)`, return the `RouteTarget`
/// and the list of DNS servers to use, or `None` for system DNS.
pub type EgressResolver =
    Arc<dyn Fn(&str, &str) -> Option<(RouteTarget, Vec<String>)> + Send + Sync>;

/// Resolves a `RouteTarget` to its policy-routing fwmark.
/// Returns `None` if no mark is available (fall back to plain UDP).
pub type FwmarkResolver = Arc<dyn Fn(&RouteTarget) -> Option<u32> + Send + Sync>;

/// The system DNS address to use when no rule matches.
/// Read from `/etc/resolv.conf` before we bind on port 53.
#[derive(Clone, Debug)]
pub struct SystemDns {
    pub addr: SocketAddr,
}

impl SystemDns {
    /// Parse the first usable `nameserver` line from `/etc/resolv.conf`.
    /// Skips loopback addresses (127.x.x.x, ::1) to avoid a loop when we
    /// own port 53 on loopback. Falls back to `1.1.1.1` if nothing else is found.
    pub fn from_resolv_conf() -> Option<Self> {
        let data = std::fs::read_to_string("/etc/resolv.conf").ok()?;
        for line in data.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                let ip_str = rest.trim();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    // Skip loopback — that's us; using it would loop.
                    if ip.is_loopback() {
                        continue;
                    }
                    return Some(Self {
                        addr: SocketAddr::new(ip, 53),
                    });
                }
            }
        }
        // Hard fallback so the daemon is never stranded.
        eprintln!(
            "dns-forwarder: no non-loopback nameserver in /etc/resolv.conf; falling back to 1.1.1.1"
        );
        Some(Self {
            addr: "1.1.1.1:53".parse().unwrap(),
        })
    }
}

/// DNS forwarder: listens on `127.0.0.1:53`, identifies the source process
/// via the eBPF tracker, matches against routing rules, and resolves through
/// the correct egress's DNS servers.
pub struct DnsForwarder {
    socket: UdpSocket,
    tracker: Option<Arc<DnsTracker>>,
    proc_resolver: ProcProcessResolver,
    egress_resolver: EgressResolver,
    fwmark_resolver: FwmarkResolver,
    system_dns: Option<SystemDns>,
    dns_cache: SniDnsCache,
    /// Cache of proxy configs keyed by proxy_id to avoid per-query SQLite opens.
    proxy_cache: Arc<Mutex<HashMap<String, ProxyConfig>>>,
    /// Fwmark stamped on all daemon-originated sockets so nftables bypasses
    /// NFQUEUE. Without this, the daemon's own DNS/TCP relay connections are
    /// intercepted and attributed to "netkeep-daemon" instead of the real
    /// application. Set to `ROUTE_MARK_BASE` (20000) by the daemon.
    daemon_mark: u32,
}

impl DnsForwarder {
    /// Create a new forwarder bound to `127.0.0.1:53`.
    ///
    /// `egress_resolver` — called with `(process_name, domain)` to find the
    /// routing target and DNS servers. Returns `None` to fall through to system DNS.
    ///
    /// `fwmark_resolver` — called with `&RouteTarget` to obtain the fwmark for
    /// policy routing (used by Tun egress). Returns `None` to fall back to plain UDP.
    ///
    /// `dns_cache` — shared IP→domain cache populated from DNS response A/AAAA records.
    ///
    /// `daemon_mark` — fwmark stamped on all daemon-originated sockets so
    /// nftables bypasses NFQUEUE. Must be `>= ROUTE_MARK_BASE` (20000).
    /// Pass 0 to disable marking (e.g. in tests).
    pub fn bind(
        tracker: Option<Arc<DnsTracker>>,
        egress_resolver: EgressResolver,
        fwmark_resolver: FwmarkResolver,
        system_dns: Option<SystemDns>,
        dns_cache: SniDnsCache,
        daemon_mark: u32,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:53")?;
        socket.set_read_timeout(Some(Duration::from_secs(30)))?;
        eprintln!(
            "dns-forwarder: listening on 127.0.0.1:53 (system DNS fallback: {:?}, daemon_mark={daemon_mark})",
            system_dns.as_ref().map(|s| s.addr)
        );
        Ok(Self {
            socket,
            tracker,
            proc_resolver: ProcProcessResolver::new(),
            egress_resolver,
            fwmark_resolver,
            system_dns,
            dns_cache,
            proxy_cache: Arc::new(Mutex::new(HashMap::new())),
            daemon_mark,
        })
    }

    /// Run the query processing loop with a bounded worker pool.
    /// Limits concurrent queries to avoid unbounded thread growth when a
    /// misbehaving process sends DNS queries in a tight loop.
    pub fn run(self) {
        // Maximum simultaneous in-flight DNS queries.
        const MAX_CONCURRENT: usize = 32;
        let sem = Arc::new(Mutex::new(0usize));

        let shared = Arc::new(self);
        loop {
            let mut buf = [0u8; DNS_BUF];
            let (len, peer) = match shared.socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(e) => {
                    eprintln!("dns-forwarder: recv_from error: {e}");
                    break;
                }
            };

            // Acquire semaphore slot — drop oldest if full rather than spawning unbounded.
            {
                let mut count = sem.lock().unwrap();
                if *count >= MAX_CONCURRENT {
                    // Drop this query — client will retry; DNS is resilient to dropped UDP.
                    continue;
                }
                *count += 1;
            }

            let query = buf[..len].to_vec();
            let fwd = Arc::clone(&shared);
            let sem2 = Arc::clone(&sem);
            std::thread::spawn(move || {
                if let Err(e) = fwd.handle_query(query, peer) {
                    eprintln!("dns-forwarder: query from {peer} failed: {e}");
                }
                // Release semaphore slot.
                *sem2.lock().unwrap() -= 1;
            });
        }
    }

    fn handle_query(&self, query: Vec<u8>, peer: SocketAddr) -> Result<(), String> {
        // Parse domain from query.
        let domain = parse_qname_from_query(&query).unwrap_or_default();

        // Identify source process.
        let process_name = self.resolve_process(peer, &domain);

        eprintln!(
            "dns-forwarder: {} process={} domain={}",
            peer,
            process_name.as_deref().unwrap_or("?"),
            domain
        );

        // Match rule: (process, domain) → (egress target, dns servers).
        let response = if let Some(name) = &process_name {
            if let Some((target, dns_servers)) = (self.egress_resolver)(name, &domain) {
                if dns_servers.is_empty() {
                    // Fail closed: an egress with no DNS servers cannot resolve
                    // through its own path, and falling back to system DNS
                    // would leak routed domains to the local resolver.
                    eprintln!(
                        "dns-forwarder: egress {target:?} matched for '{domain}' but has no DNS servers configured; answering SERVFAIL (configure DNS servers for this egress to enable resolution)"
                    );
                    build_dns_error_response(&query, RCODE_SERVFAIL)
                        .ok_or_else(|| "malformed query: cannot build SERVFAIL reply".to_string())?
                } else {
                    self.resolve_via_egress(&query, &target, &dns_servers)?
                }
            } else {
                self.forward_system(&query)?
            }
        } else {
            self.forward_system(&query)?
        };

        // Populate SniDnsCache: extract (ip → domain) from DNS response A/AAAA records.
        if !domain.is_empty() {
            let pairs = parse_dns_response_ips(&response);
            for (ip, d) in &pairs {
                self.dns_cache.insert(ip.to_string(), d.as_str());
            }
            if !pairs.is_empty() {
                eprintln!(
                    "dns-forwarder: cached {} IP→domain mapping(s) for '{}'",
                    pairs.len(),
                    domain
                );
            }
        }

        // Send response back to the application.
        self.socket
            .send_to(&response, peer)
            .map_err(|e| format!("send_to {peer}: {e}"))?;

        Ok(())
    }

    /// Identify the source process for a query arriving from `peer`.
    ///
    /// Socket-level attribution names the process owning `peer`'s socket.
    /// When that is a local stub resolver (systemd-resolved, dnsmasq, …) the
    /// real application is hidden behind it, so [`Self::resolve_behind_resolver`]
    /// recovers the app that asked for `domain`.
    fn resolve_process(&self, peer: SocketAddr, domain: &str) -> Option<String> {
        // Try eBPF tracker first (100% accurate, no /proc race).
        let mut direct = None;
        if let Some(tracker) = &self.tracker {
            if let SocketAddr::V4(v4) = peer {
                if let Some(info) = tracker.lookup(*v4.ip(), v4.port()) {
                    if !info.comm.is_empty() {
                        direct = Some(info.comm);
                    }
                }
            }
        }

        // Fallback: SOCK_DIAG + /proc scan.
        // The app is blocked on getaddrinfo() so its socket is still open.
        if direct.is_none() {
            if let SocketAddr::V4(v4) = peer {
                let src_ip = v4.ip().to_string();
                if let Some(proc_info) =
                    self.proc_resolver
                        .resolve(&src_ip, v4.port(), TransportProtocol::Udp, None)
                {
                    if !proc_info.name.is_empty() {
                        direct = Some(proc_info.name);
                    }
                }
            }
        }

        match direct {
            Some(name) if !is_local_resolver_comm(&name) => Some(name),
            direct => self.resolve_behind_resolver(domain).or(direct),
        }
    }

    /// Best-effort attribution of a query that arrived from a local stub
    /// resolver: find the app that originally asked for `domain`.
    ///
    /// Layer 1 — eBPF DNS map scan (domain-exact, when the tracker loaded):
    /// the app's query to the stub has dport 53 too, so the map holds an
    /// entry for the app's socket; its current owner is verified via
    /// SOCK_DIAG before use.
    ///
    /// Layer 2 — /proc socket scan: apps blocked in getaddrinfo() hold a UDP
    /// socket with the stub as remote (loopback:53). Used when the eBPF DNS
    /// tracker is unavailable. With several apps resolving concurrently the
    /// attribution is ambiguous and we refuse to guess (returns `None`), so
    /// the query keeps the resolver's identity rather than a wrong one.
    fn resolve_behind_resolver(&self, domain: &str) -> Option<String> {
        if let Some(tracker) = &self.tracker {
            for candidate in tracker.lookup_all_by_domain(domain) {
                if is_local_resolver_comm(&candidate.info.comm) {
                    continue;
                }
                // Prefer the socket's CURRENT owner — the app is usually
                // still blocked in getaddrinfo(), so SOCK_DIAG sees it.
                if let Some(owner) = self.proc_resolver.resolve(
                    &candidate.src_ip.to_string(),
                    candidate.src_port,
                    TransportProtocol::Udp,
                    None,
                ) {
                    if !owner.name.is_empty() && !is_local_resolver_comm(&owner.name) {
                        return Some(owner.name);
                    }
                }
                // Socket already closed: trust the eBPF comm if still alive.
                if candidate.info.pid != 0
                    && std::path::Path::new(&format!("/proc/{}", candidate.info.pid)).exists()
                {
                    return Some(candidate.info.comm);
                }
            }
        }

        let mut clients: Vec<String> = Vec::new();
        for pid in flow_classifier::proc_resolver::stub_resolver_client_pids() {
            if let Some(comm) = comm_for_pid(pid) {
                if !is_local_resolver_comm(&comm) && !clients.contains(&comm) {
                    clients.push(comm);
                }
            }
        }
        if clients.len() == 1 {
            return clients.pop();
        }
        None
    }

    fn resolve_via_egress(
        &self,
        query: &[u8],
        target: &RouteTarget,
        dns_servers: &[String],
    ) -> Result<Vec<u8>, String> {
        let result = match target {
            RouteTarget::Proxy(id) => self.resolve_via_proxy(query, dns_servers, id),
            RouteTarget::Tun(iface) => {
                let fwmark = (self.fwmark_resolver)(target).unwrap_or(0);
                resolve_via_so_mark(query, dns_servers, iface, fwmark)
            }
            RouteTarget::Device(iface) => {
                resolve_via_bindtodevice(query, dns_servers, iface, self.daemon_mark)
            }
        };
        // Fail closed: never fall back to system DNS when the egress fails.
        // A rule that routes a domain through a private egress (proxy, tun,
        // device) means the caller does not want the local network's resolver
        // to see that domain. Answering SERVFAIL leaks nothing; querying the
        // system DNS would hand the routed domain to the very path the rule
        // steers traffic away from.
        match result {
            ok @ Ok(_) => ok,
            Err(e) => {
                eprintln!(
                    "dns-forwarder: egress DNS failed via {target:?} (servers: {dns_servers:?}): {e}; answering SERVFAIL (system DNS fallback disabled to prevent domain leak)"
                );
                build_dns_error_response(query, RCODE_SERVFAIL).ok_or_else(|| {
                    format!("egress DNS failed ({e}) and malformed query prevented SERVFAIL reply")
                })
            }
        }
    }

    fn forward_system(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let upstream = self
            .system_dns
            .as_ref()
            .ok_or_else(|| "no system DNS configured".to_string())?;
        forward_udp(query, upstream.addr, self.daemon_mark)
    }

    /// Send DNS query via SOCKS5 (DNS-over-SOCKS5).
    /// Uses cached proxy config to avoid per-query SQLite opens.
    fn resolve_via_proxy(
        &self,
        query: &[u8],
        dns_servers: &[String],
        proxy_id: &str,
    ) -> Result<Vec<u8>, String> {
        // Check cache first.
        let proxy = {
            let cache = self.proxy_cache.lock().unwrap();
            cache.get(proxy_id).cloned()
        };
        let proxy = match proxy {
            Some(p) => p,
            None => {
                let db_path = std::env::var("NETKEEP_DB_PATH").unwrap_or_else(|_| {
                    format!(
                        "{}/.config/netkeep/netkeep.db",
                        std::env::var("HOME").unwrap_or_default()
                    )
                });
                let repo = state_store::SqliteRuleRepository::open(&db_path)
                    .map_err(|e| format!("open db: {e}"))?;
                let proxy = repo
                    .get_proxy(proxy_id)
                    .ok_or_else(|| format!("proxy '{proxy_id}' not found"))?;
                self.proxy_cache
                    .lock()
                    .unwrap()
                    .insert(proxy_id.to_string(), proxy.clone());
                proxy
            }
        };

        let mut last_err = String::new();
        for dns_server in dns_servers {
            match dns_over_socks(&proxy, dns_server, query, self.daemon_mark) {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    last_err = format!("{dns_server}: {e}");
                }
            }
        }
        Err(format!("proxy DNS failed ({last_err})"))
    }
}

// ---------------------------------------------------------------------------
// Per-egress DNS resolution helpers
// ---------------------------------------------------------------------------

/// Connect to a DNS server via SOCKS5 and exchange a DNS query.
///
/// Uses TCP DNS (RFC 1035 §4.2.2 — 2-byte message length prefix) because
/// SOCKS5 CONNECT only supports TCP streams. Most public DNS servers (1.1.1.1,
/// 8.8.8.8) accept DNS-over-TCP on port 53.
///
/// `daemon_mark` is set via `SO_MARK` on the TCP socket **before** connect so
/// the SYN and the whole SOCKS handshake bypass NFQUEUE.
fn dns_over_socks(
    proxy: &ProxyConfig,
    dns_server_ip: &str,
    query: &[u8],
    daemon_mark: u32,
) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};

    let mut stream =
        proxy_client::connect_via_proxy(proxy, dns_server_ip, 53, DNS_TIMEOUT, daemon_mark)
            .map_err(|e| format!("socks connect to {dns_server_ip}:53: {e}"))?;

    // `connect_via_proxy` clears I/O timeouts after its handshake (relay-path
    // semantics), but this is a bounded request/response exchange: re-arm
    // DNS_TIMEOUT so a silent proxy/DNS server cannot wedge this worker
    // thread (and its semaphore slot) forever.
    stream
        .set_read_timeout(Some(DNS_TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(DNS_TIMEOUT))
        .map_err(|e| e.to_string())?;

    // TCP DNS framing: 2-byte big-endian length prefix, then query.
    let len_prefix = (query.len() as u16).to_be_bytes();
    stream.write_all(&len_prefix).map_err(|e| e.to_string())?;
    stream.write_all(query).map_err(|e| e.to_string())?;
    // Flush to ensure everything is sent before we read.
    stream.flush().map_err(|e| e.to_string())?;

    // Read 2-byte response length.
    let mut resp_len_buf = [0u8; 2];
    stream
        .read_exact(&mut resp_len_buf)
        .map_err(|e| format!("read resp len: {e}"))?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    if resp_len == 0 || resp_len > 65535 {
        return Err(format!("invalid TCP DNS response length: {resp_len}"));
    }

    let mut resp = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp)
        .map_err(|e| format!("read resp body: {e}"))?;

    Ok(resp)
}

/// Send DNS query with SO_MARK to route it through the fwmark-based policy table.
fn resolve_via_so_mark(
    query: &[u8],
    dns_servers: &[String],
    _iface: &str,
    fwmark: u32,
) -> Result<Vec<u8>, String> {
    use std::os::unix::io::AsRawFd;

    for dns_server in dns_servers {
        let addr: SocketAddr = format!("{dns_server}:53")
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?;

        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;

        // Set SO_MARK so the packet follows the fwmark policy route.
        if fwmark != 0 {
            let ret = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &fwmark as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                eprintln!(
                    "dns-forwarder: SO_MARK({fwmark}) failed: {}",
                    std::io::Error::last_os_error()
                );
                // Continue without mark — might still work via default route.
            }
        }

        socket
            .set_read_timeout(Some(DNS_TIMEOUT))
            .map_err(|e| e.to_string())?;

        match socket.send_to(query, addr) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("dns-forwarder: tun DNS send to {dns_server} failed: {e}");
                continue;
            }
        }

        let mut buf = [0u8; DNS_BUF];
        match socket.recv(&mut buf) {
            Ok(n) => return Ok(buf[..n].to_vec()),
            Err(e) => {
                eprintln!("dns-forwarder: tun DNS recv from {dns_server} failed: {e}");
            }
        }
    }
    Err("all tun DNS servers failed".to_string())
}

/// Send DNS query with SO_BINDTODEVICE.
fn resolve_via_bindtodevice(
    query: &[u8],
    dns_servers: &[String],
    iface: &str,
    daemon_mark: u32,
) -> Result<Vec<u8>, String> {
    use std::io;
    use std::os::unix::io::AsRawFd;

    for dns_server in dns_servers {
        let addr: SocketAddr = format!("{dns_server}:53")
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?;

        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;

        // SO_BINDTODEVICE
        let iface_cstr = std::ffi::CString::new(iface).map_err(|e| e.to_string())?;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface_cstr.as_ptr() as *const libc::c_void,
                iface_cstr.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if ret < 0 {
            eprintln!(
                "dns-forwarder: SO_BINDTODEVICE({iface}) failed: {}",
                io::Error::last_os_error()
            );
        }

        // Stamp daemon fwmark so nftables output_early bypasses NFQUEUE.
        if daemon_mark != 0 {
            let ret = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &daemon_mark as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                eprintln!(
                    "dns-forwarder: SO_MARK({daemon_mark}) on bindtodevice socket failed: {}",
                    io::Error::last_os_error()
                );
            }
        }

        socket
            .set_read_timeout(Some(DNS_TIMEOUT))
            .map_err(|e| e.to_string())?;
        match socket.send_to(query, addr) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("dns-forwarder: device DNS send to {dns_server} failed: {e}");
                continue;
            }
        }

        let mut buf = [0u8; DNS_BUF];
        match socket.recv(&mut buf) {
            Ok(n) => return Ok(buf[..n].to_vec()),
            Err(e) => {
                eprintln!("dns-forwarder: device DNS recv from {dns_server} failed: {e}");
            }
        }
    }
    Err(format!("all device DNS servers failed for iface {iface}"))
}

/// Per-attempt timeout for UDP DNS retries.
const UDP_RETRY_TIMEOUT: Duration = Duration::from_secs(3);
/// Maximum number of send attempts for a single UDP DNS query.
const UDP_MAX_RETRIES: usize = 2;

/// Forward a UDP DNS query to `upstream` and return the response.
///
/// Retries up to [`UDP_MAX_RETRIES`] times on timeout (EAGAIN / WouldBlock).
/// DNS over UDP is inherently unreliable; retries are standard client behavior.
///
/// `daemon_mark` is set via `SO_MARK` so the daemon's own DNS packets bypass
/// NFQUEUE. Pass 0 to skip marking (e.g. in tests).
fn forward_udp(query: &[u8], upstream: SocketAddr, daemon_mark: u32) -> Result<Vec<u8>, String> {
    use std::os::unix::io::AsRawFd;

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;

    // Stamp daemon fwmark so nftables output_early bypasses NFQUEUE.
    if daemon_mark != 0 {
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &daemon_mark as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            eprintln!(
                "dns-forwarder: SO_MARK({daemon_mark}) on forward_udp socket failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    socket
        .set_read_timeout(Some(UDP_RETRY_TIMEOUT))
        .map_err(|e| e.to_string())?;

    let mut last_err = String::new();
    for attempt in 0..=UDP_MAX_RETRIES {
        if attempt > 0 {
            eprintln!(
                "dns-forwarder: retry {attempt}/{} to {upstream}",
                UDP_MAX_RETRIES
            );
        }
        socket
            .send_to(query, upstream)
            .map_err(|e| format!("send to {upstream}: {e}"))?;

        let mut buf = [0u8; DNS_BUF];
        match socket.recv(&mut buf) {
            Ok(n) => return Ok(buf[..n].to_vec()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout — retry.
                last_err = format!("recv from {upstream}: {e}");
                continue;
            }
            Err(e) => {
                return Err(format!("recv from {upstream}: {e}"));
            }
        }
    }
    Err(format!(
        "recv from {upstream}: {last_err} (after {UDP_MAX_RETRIES} retries)"
    ))
}

// ---------------------------------------------------------------------------
// DNS wire format helpers
// ---------------------------------------------------------------------------

/// Build a minimal DNS response that echoes the query's question section and
/// carries the given RCODE (e.g. [`RCODE_SERVFAIL`]). Lets the forwarder
/// answer with a proper error instead of leaking the query to system DNS or
/// silently timing the client out.
///
/// Returns `None` for malformed input shorter than a DNS header.
fn build_dns_error_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // Echo exactly the first question (QNAME + QTYPE + QCLASS) when parseable.
    let mut pos = 12usize;
    let question = if skip_name(query, &mut pos).is_some() && pos + 4 <= query.len() {
        Some(query[12..pos + 4].to_vec())
    } else {
        None
    };
    let mut resp = Vec::with_capacity(12 + question.as_ref().map_or(0, Vec::len));
    resp.extend_from_slice(&query[0..2]); // ID — must echo so the client accepts it
    resp.push(query[2] | 0x80); // flags: copy opcode/RD, set QR (is a response)
    resp.push((query[3] & 0xF0) | (rcode & 0x0F)); // preserve Z/AD/CD, set RCODE
    let qdcount: u16 = if question.is_some() { 1 } else { 0 };
    resp.extend_from_slice(&qdcount.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&[0, 0]); // ANCOUNT
    resp.extend_from_slice(&[0, 0]); // NSCOUNT
    resp.extend_from_slice(&[0, 0]); // ARCOUNT
    if let Some(q) = question {
        resp.extend_from_slice(&q);
    }
    Some(resp)
}

/// Extract the QNAME from a DNS query message.
pub fn parse_qname_from_query(data: &[u8]) -> Option<String> {
    if data.len() < 13 {
        return None;
    }
    // Byte 2 bit 7 = QR; must be 0 for a query.
    // We accept both queries and responses for logging.
    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *data.get(pos)? as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            break; // compression pointer — stop
        }
        pos += 1;
        if pos + len > data.len() {
            break;
        }
        let label = std::str::from_utf8(&data[pos..pos + len])
            .unwrap_or("")
            .to_ascii_lowercase();
        labels.push(label);
        pos += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Parse A/AAAA records from a DNS response, returning `(ip, domain)` pairs.
/// Used to populate the SniDnsCache so subsequent connections to the same IP
/// can be attributed to the domain the application originally queried.
fn parse_dns_response_ips(data: &[u8]) -> Vec<(IpAddr, String)> {
    if data.len() < 12 {
        return vec![];
    }
    // Byte 2 bit 7 = QR flag: 1 = response.
    if data[2] & 0x80 == 0 {
        return vec![];
    }
    // Byte 3 bits 0-3 = RCODE: 0 = no error.
    if data[3] & 0x0F != 0 {
        return vec![];
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if ancount == 0 {
        return vec![];
    }

    let mut pos = 12;

    // Extract the QNAME (the domain the application queried).
    let domain = match read_name(data, &mut pos) {
        Some(d) if !d.is_empty() => d,
        _ => return vec![],
    };
    // Skip QTYPE (2) + QCLASS (2).
    if pos + 4 > data.len() {
        return vec![];
    }
    pos += 4;

    // Skip additional questions.
    for _ in 1..qdcount {
        if skip_name(data, &mut pos).is_none() {
            return vec![];
        }
        if pos + 4 > data.len() {
            return vec![];
        }
        pos += 4;
    }

    // Parse answer resource records.
    let mut results = Vec::new();
    for _ in 0..ancount {
        if skip_name(data, &mut pos).is_none() {
            break;
        }
        // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes.
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        match rtype {
            1 if rdlength == 4 => {
                let ip = IpAddr::from([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                results.push((ip, domain.clone()));
            }
            28 if rdlength == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&data[pos..pos + 16]);
                results.push((IpAddr::from(bytes), domain.clone()));
            }
            _ => {}
        }
        pos += rdlength;
    }
    results
}

/// Read a DNS name (with compression pointer support) from `data` starting at `pos`.
fn read_name(data: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_pos = 0usize;
    let max_jumps = 10; // prevent infinite loops from malicious data

    for _ in 0..max_jumps {
        let len = *data.get(*pos)? as usize;
        if len == 0 {
            if !jumped {
                *pos += 1;
            } else {
                *pos = jump_pos;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer.
            if !jumped {
                jump_pos = *pos + 2;
                jumped = true;
            }
            let offset = ((len & 0x3F) << 8) | (*data.get(*pos + 1)? as usize);
            *pos = offset;
            continue;
        }
        *pos += 1;
        if *pos + len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[*pos..*pos + len])
            .unwrap_or("")
            .to_ascii_lowercase();
        labels.push(label);
        *pos += len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Skip a DNS name (handling compression pointers) without returning it.
fn skip_name(data: &[u8], pos: &mut usize) -> Option<()> {
    let max_jumps = 10;
    for _ in 0..max_jumps {
        let len = *data.get(*pos)? as usize;
        if len == 0 {
            *pos += 1;
            return Some(());
        }
        if len & 0xC0 == 0xC0 {
            *pos += 2;
            return Some(());
        }
        *pos += 1 + len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal well-formed A query for `example.com` (RD set).
    fn sample_query() -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&[0xAB, 0xCD]); // ID
        q.extend_from_slice(&[0x01, 0x00]); // flags: standard query, RD=1
        q.extend_from_slice(&[0, 1]); // QDCOUNT = 1
        q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
        for label in ["example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0); // root label
        q.extend_from_slice(&[0, 1]); // QTYPE = A
        q.extend_from_slice(&[0, 1]); // QCLASS = IN
        q
    }

    #[test]
    fn servfail_response_echoes_query() {
        let query = sample_query();
        let resp = build_dns_error_response(&query, RCODE_SERVFAIL).expect("response built");

        // ID echoed.
        assert_eq!(&resp[0..2], &[0xAB, 0xCD]);
        // QR set (response), opcode and RD preserved from the query.
        assert_eq!(resp[2] & 0x80, 0x80, "QR bit must be set");
        assert_eq!(resp[2] & 0x7F, query[2] & 0x7F, "opcode/RD echoed");
        // RCODE = SERVFAIL (2), upper nibble preserved.
        assert_eq!(resp[3] & 0x0F, RCODE_SERVFAIL);
        // Counts: one question, no answers.
        assert_eq!(&resp[4..6], &[0, 1]);
        assert_eq!(&resp[6..12], &[0, 0, 0, 0, 0, 0]);
        // Question section echoed verbatim.
        let question_end = 12 + query.len() - 12;
        assert_eq!(&resp[12..], &query[12..question_end]);
        // The response parses as a name-bearing message and yields no IPs.
        assert_eq!(
            parse_qname_from_query(&resp).as_deref(),
            Some("example.com")
        );
        assert!(parse_dns_response_ips(&resp).is_empty());
    }

    #[test]
    fn error_response_header_only_without_question() {
        // A 12-byte header with QDCOUNT=0 — no question section to echo.
        let query = vec![0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let resp = build_dns_error_response(&query, RCODE_SERVFAIL).expect("response built");
        assert_eq!(resp.len(), 12);
        assert_eq!(&resp[4..6], &[0, 0], "QDCOUNT must be 0");
        assert_eq!(resp[3] & 0x0F, RCODE_SERVFAIL);
    }

    #[test]
    fn error_response_rejects_malformed_query() {
        assert!(build_dns_error_response(&[0, 1, 2], RCODE_SERVFAIL).is_none());
    }

    #[test]
    fn resolver_comm_detection() {
        assert!(is_local_resolver_comm("systemd-resolve")); // 15-char comm truncation
        assert!(is_local_resolver_comm("systemd-resolved"));
        assert!(is_local_resolver_comm("dnsmasq"));
        assert!(is_local_resolver_comm("netkeepd"));
        assert!(is_local_resolver_comm("netkeep-daemon"));
        assert!(is_local_resolver_comm(""));
        assert!(!is_local_resolver_comm("chromium"));
        assert!(!is_local_resolver_comm("dig"));
        assert!(!is_local_resolver_comm("curl"));
    }
}
