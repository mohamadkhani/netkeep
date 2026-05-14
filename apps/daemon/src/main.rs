use std::fs;
use std::io::{BufRead, BufReader, Write, copy};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::fs::PermissionsExt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use control_api::{ControlRequest, ControlResponse, PushNotification};
use control_service::{ControlService, HealthConfig, SharedService};
use core_types::{Egress, RouteTarget};
use decision_engine::{DecisionEngine, OverflowPolicy};
use enforcer::{NftablesBootstrap, RouteManager, SystemNftablesBootstrap, SystemRouteManager, ROUTE_MARK_BASE};
use enforcer::nfqueue::NfqueueProcessor;
use flow_classifier::{
    FlowClassifier, FakeDeviceLabelResolver, SniDnsCache,
    proc_resolver::ProcProcessResolver,
};
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use rusqlite::{Connection, params};
use state_store::{EgressRepository, PendingRepository, RuleRepository, SqliteRuleRepository};
use tokio::sync::broadcast;

const DEFAULT_SOCKET_PATH: &str = "/tmp/logiguard.sock";
const DEFAULT_DB_RELATIVE: &str = ".config/logiguard/logiguard.db";
const DEFAULT_TIMEOUT_SECS: u64 = 100;
const DEFAULT_PENDING_LIMIT: usize = 100;
const ROUTED_CONNECT_TIMEOUT_SECS: u64 = 8;
const DEVICE_ROUTE_FALLBACK_ENV: &str = "LOGIGUARD_DEVICE_ROUTE_FALLBACK";
const ROUTE_MARK_BASE_ENV: &str = "LOGIGUARD_ROUTE_MARK_BASE";

struct RoutePolicyState {
    next_mark: u32,
    marks_by_target: HashMap<RouteTarget, u32>,
    manager: SystemRouteManager,
}

impl RoutePolicyState {
    fn with_base(mark_base: u32) -> Self {
        Self {
            next_mark: mark_base,
            marks_by_target: HashMap::new(),
            manager: SystemRouteManager::new(),
        }
    }
}

fn route_policy_state() -> &'static Mutex<RoutePolicyState> {
    static STATE: OnceLock<Mutex<RoutePolicyState>> = OnceLock::new();
    // Initialised explicitly by init_route_policy before any relay thread runs.
    // Falls back to ROUTE_MARK_BASE if somehow called before init (shouldn't happen).
    STATE.get_or_init(|| Mutex::new(RoutePolicyState::with_base(ROUTE_MARK_BASE)))
}

/// Call once in main before any relay threads start.
/// Forces the singleton to use the runtime mark base instead of the compiled default.
fn init_route_policy(mark_base: u32) {
    if let Ok(mut s) = route_policy_state().lock() {
        s.next_mark = mark_base;
    }
}

fn ensure_route_mark(target: &RouteTarget) -> Result<u32, String> {
    let mut state = route_policy_state()
        .lock()
        .map_err(|_| "route policy state lock poisoned".to_string())?;
    if let Some(mark) = state.marks_by_target.get(target).copied() {
        return Ok(mark);
    }
    let mark = state.next_mark;
    state.next_mark = state
        .next_mark
        .checked_add(1)
        .ok_or_else(|| "device route mark overflow".to_string())?;
    state
        .manager
        .add_route(target, mark)
        .map_err(|e| format!("install route policy for {target:?} failed: {e}"))?;
    state.marks_by_target.insert(target.clone(), mark);
    eprintln!("routed policy installed: target={target:?} fwmark={mark}");
    Ok(mark)
}

fn parse_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Detect local interfaces and build initial egress records.
/// Includes:


/// Returns true if the process `peer_pid` has stdin on a physical console
/// (/dev/tty[0-9]* or /dev/console), not a pseudo-terminal (/dev/pts/*).
fn is_physical_console(peer_pid: i32) -> bool {
    match fs::read_link(format!("/proc/{}/fd/0", peer_pid)) {
        Ok(target) => {
            let s = target.to_string_lossy();
            (s.starts_with("/dev/tty") && !s.starts_with("/dev/pts"))
                || s == "/dev/console"
        }
        Err(_) => false,
    }
}

fn peer_pid(stream: &UnixStream) -> Option<i32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 { Some(cred.pid) } else { None }
}

fn relay_bidirectional(client: TcpStream, upstream: TcpStream) -> Result<(), String> {
    let mut c_read = client.try_clone().map_err(|e| e.to_string())?;
    let mut c_write = client;
    let mut u_read = upstream.try_clone().map_err(|e| e.to_string())?;
    let mut u_write = upstream;
    let t1 = std::thread::spawn(move || copy(&mut c_read, &mut u_write).map_err(|e| e.to_string()));
    let t2 = std::thread::spawn(move || copy(&mut u_read, &mut c_write).map_err(|e| e.to_string()));
    let _ = t1.join().map_err(|_| "relay thread join failed".to_string())??;
    let _ = t2.join().map_err(|_| "relay thread join failed".to_string())??;
    Ok(())
}

fn route_target_to_parts(target: &RouteTarget) -> (i64, &str) {
    match target {
        RouteTarget::Tun(v) => (1, v.as_str()),
        RouteTarget::Device(v) => (2, v.as_str()),
        RouteTarget::Proxy(v) => (3, v.as_str()),
    }
}

fn load_dns_servers_for_target(db_path: &str, target: &RouteTarget) -> Result<Vec<String>, String> {
    let conn = Connection::open(db_path).map_err(|e| format!("open db for egress dns failed: {e}"))?;
    let (target_kind, target_value) = route_target_to_parts(target);
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT d.dns_server
             FROM egress_targets t
             JOIN egress_dns_servers d ON d.egress_id = t.egress_id
             WHERE t.target_kind = ?1 AND t.target_value = ?2
             ORDER BY d.dns_server",
        )
        .map_err(|e| format!("prepare egress dns query failed: {e}"))?;
    let mapped = stmt
        .query_map(params![target_kind, target_value], |row| row.get::<_, String>(0))
        .map_err(|e| format!("query egress dns failed: {e}"))?;
    Ok(mapped.filter_map(Result::ok).collect())
}

fn resolve_with_dns_servers(host: &str, dns_servers: &[String]) -> Result<Vec<IpAddr>, String> {
    let mut cfg = ResolverConfig::new();
    for dns in dns_servers {
        let ip: IpAddr = dns
            .parse()
            .map_err(|e| format!("invalid DNS server ip '{dns}': {e}"))?;
        cfg.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(ip, 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
        });
        cfg.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(ip, 53),
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
        });
    }
    let resolver = Resolver::new(cfg, ResolverOpts::default())
        .map_err(|e| format!("create resolver failed: {e}"))?;
    let lookup = resolver
        .lookup_ip(host)
        .map_err(|e| format!("dns lookup for {host} failed: {e}"))?;
    let ips: Vec<IpAddr> = lookup.into_iter().collect();
    if ips.is_empty() {
        return Err(format!("dns lookup for {host} returned no addresses"));
    }
    Ok(ips)
}

fn resolve_socket_addrs(
    host: &str,
    port: u16,
    target: Option<&RouteTarget>,
    db_path: &str,
) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    if let Some(target) = target {
        let dns_servers = load_dns_servers_for_target(db_path, target)?;
        if !dns_servers.is_empty() {
            let ips = resolve_with_dns_servers(host, &dns_servers)?;
            let addrs: Vec<SocketAddr> = ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
            eprintln!(
                "routed dns: host={host} target={target:?} resolvers={dns_servers:?} addrs={addrs:?}"
            );
            return Ok(addrs);
        }
    }

    let addr = format!("{host}:{port}");
    let socket_addrs: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .map_err(|e| format!("system DNS resolve failed for {addr}: {e}"))?
        .collect();
    if socket_addrs.is_empty() {
        return Err(format!("no address found for {addr}"));
    }
    eprintln!(
        "routed dns: host={host} target={target:?} resolvers=system addrs={socket_addrs:?}"
    );
    Ok(socket_addrs)
}

#[cfg(target_os = "linux")]
fn linux_socket_bind_to_device(fd: i32, iface: &str) -> Result<(), std::io::Error> {
    let cname = std::ffi::CString::new(iface).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "interface name contains NUL")
    })?;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            cname.as_ptr() as *const libc::c_void,
            cname.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn connect_via_device(addrs: &[SocketAddr], iface: &str) -> Result<TcpStream, String> {
    let src_ip = iface_primary_ipv4(iface)?;
    let mark = ensure_route_mark(&RouteTarget::Device(iface.to_string()))?;
    let mut last_err: Option<String> = None;
    eprintln!("routed device connect: iface={iface} src_ip={src_ip} fwmark={mark} addrs={addrs:?}");

    for sockaddr in addrs {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(*sockaddr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .map_err(|e| format!("socket create failed: {e}"))?;
        #[cfg(target_os = "linux")]
        {
            if let Err(e) = linux_socket_bind_to_device(socket.as_raw_fd(), iface) {
                eprintln!(
                    "routed device connect: SO_BINDTODEVICE({iface}) failed ({e}); continuing with fwmark-only"
                );
            }
        }
        unsafe {
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const _,
                std::mem::size_of::<u32>() as u32,
            );
            if ret < 0 {
                return Err(format!(
                    "SO_MARK failed for device {iface} mark={mark}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        let local = SocketAddrV4::new(src_ip, 0);
        if let Err(e) = socket.bind(&socket2::SockAddr::from(local)) {
            eprintln!("routed device connect: source bind failed for {iface} ({src_ip}): {e}; continuing with mark-only routing");
        }
        let sock_addr: socket2::SockAddr = (*sockaddr).into();
        match socket.connect_timeout(&sock_addr, Duration::from_secs(ROUTED_CONNECT_TIMEOUT_SECS)) {
            Ok(()) => return Ok(TcpStream::from(socket)),
            Err(e) => {
                last_err = Some(format!(
                    "connect via {iface} to {sockaddr} failed (timeout={}s): {e}",
                    ROUTED_CONNECT_TIMEOUT_SECS
                ));
            }
        }
    }
    let fallback_enabled = std::env::var(DEVICE_ROUTE_FALLBACK_ENV)
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    if fallback_enabled {
        let current_default = default_route_iface();
        eprintln!(
            "routed device connect fallback: env {DEVICE_ROUTE_FALLBACK_ENV}=1, \
             iface={iface}, current_default={current_default:?}, retrying plain connect"
        );
        return connect_plain(addrs);
    }
    Err(last_err.unwrap_or_else(|| "no candidate address to connect".to_string()))
}

fn iface_primary_ipv4(iface: &str) -> Result<Ipv4Addr, String> {
    let out = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", iface, "scope", "global"])
        .output()
        .map_err(|e| format!("failed to inspect interface {iface}: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        // Example:
        // 3: wlp0s20f3    inet 192.168.7.11/24 brd ...
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|p| *p == "inet") {
            if let Some(cidr) = parts.get(idx + 1) {
                let ip = cidr.split('/').next().unwrap_or_default();
                if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
                    return Ok(parsed);
                }
            }
        }
    }
    Err(format!("no global IPv4 found on interface {iface}"))
}

fn default_route_iface() -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|p| *p == "dev") {
            if let Some(dev) = parts.get(idx + 1) {
                return Some((*dev).to_string());
            }
        }
    }
    None
}

fn route_probe_for(ip: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "get", ip])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next().unwrap_or_default().trim().to_string();
    if line.is_empty() { None } else { Some(line) }
}

/// Route lookup **with** SO_MARK — reflects policy routing for our routed connects (unmarked `ip route get` follows default route only).
fn route_probe_marked(ip: &str, mark: u32) -> Option<String> {
    let mark_arg = format!("0x{mark:x}");
    let out = std::process::Command::new("ip")
        .args(["route", "get", ip, "mark", &mark_arg])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next().unwrap_or_default().trim().to_string();
    if line.is_empty() { None } else { Some(line) }
}

fn fwmark_for_route_probe(target: &RouteTarget) -> Option<u32> {
    match target {
        RouteTarget::Tun(iface) => ensure_route_mark(&RouteTarget::Tun(iface.clone())).ok(),
        RouteTarget::Device(iface) => ensure_route_mark(&RouteTarget::Device(iface.clone())).ok(),
        RouteTarget::Proxy(_) => None, // Proxies don't use fwmark-based routing
    }
}

fn connect_plain(addrs: &[SocketAddr]) -> Result<TcpStream, String> {
    let mut last_err: Option<String> = None;
    for sockaddr in addrs {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(*sockaddr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .map_err(|e| format!("socket create failed: {e}"))?;
        let sock_addr: socket2::SockAddr = (*sockaddr).into();
        match socket.connect_timeout(&sock_addr, Duration::from_secs(ROUTED_CONNECT_TIMEOUT_SECS)) {
            Ok(()) => return Ok(TcpStream::from(socket)),
            Err(e) => {
                last_err = Some(format!(
                    "plain connect to {sockaddr} failed (timeout={}s): {e}",
                    ROUTED_CONNECT_TIMEOUT_SECS
                ));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "no candidate address to connect".to_string()))
}

fn connect_via_tun(addrs: &[SocketAddr], iface: &str) -> Result<TcpStream, String> {
    // Do not reuse fwmarks discovered from `ip rule` (e.g. WireGuard's 0xca6c). That mark often means
    // "split-tunnel / bypass VPN" — SO_MARK then sends traffic out LAN (`main`), not the tunnel.
    let mark = ensure_route_mark(&RouteTarget::Tun(iface.to_string()))?;
    let mut last_err: Option<String> = None;
    eprintln!("routed tun connect: iface={iface} fwmark={mark} addrs={addrs:?}");
    for sockaddr in addrs {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(*sockaddr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .map_err(|e| format!("socket create failed: {e}"))?;
        unsafe {
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const _,
                std::mem::size_of::<u32>() as u32,
            );
            if ret < 0 {
                return Err(format!("SO_MARK failed for tun {iface} mark={mark}: {}", std::io::Error::last_os_error()));
            }
        }
        let sock_addr: socket2::SockAddr = (*sockaddr).into();
        match socket.connect_timeout(&sock_addr, Duration::from_secs(ROUTED_CONNECT_TIMEOUT_SECS)) {
            Ok(()) => return Ok(TcpStream::from(socket)),
            Err(e) => {
                last_err = Some(format!(
                    "connect via tun {iface} to {sockaddr} failed (timeout={}s): {e}",
                    ROUTED_CONNECT_TIMEOUT_SECS
                ));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "no candidate address to connect".to_string()))
}

/// Seed useful egresses on first run: one LAN egress for the default-route
/// interface, plus one TUN egress per TUN/WireGuard interface found on the
/// system. Only called when no user-defined egresses exist yet.
fn seed_initial_egresses(repo: &mut SqliteRuleRepository) {
    // LAN — primary default-route interface.
    if let Some(iface) = detect_default_iface() {
        let id = format!("eg-lan-{iface}");
        if repo.get_egress(&id).is_none() {
            eprintln!("seed: creating LAN egress for default interface {iface}");
            repo.upsert_egress(&Egress {
                id,
                name: format!("LAN ({iface})"),
                color: "#3b82f6".to_string(),
                targets: vec![RouteTarget::Device(iface)],
                dns_servers: vec![],
                is_system_default: false,
                is_available: true,
            });
        }
    } else {
        eprintln!("seed: could not detect default route interface, skipping LAN egress");
    }

    // TUN interfaces — WireGuard, throne, OpenVPN, etc.
    for iface in detect_tun_ifaces() {
        let id = format!("eg-tun-{iface}");
        if repo.get_egress(&id).is_none() {
            eprintln!("seed: creating TUN egress for {iface}");
            repo.upsert_egress(&Egress {
                id,
                name: format!("TUN ({iface})"),
                color: "#8b5cf6".to_string(),
                targets: vec![RouteTarget::Tun(iface)],
                dns_servers: vec![],
                is_system_default: false,
                is_available: true,
            });
        }
    }
}

/// Run `ip route get 8.8.8.8` and extract the `dev <iface>` field.
fn detect_default_iface() -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "get", "8.8.8.8"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Output: "8.8.8.8 via 192.168.1.1 dev enp3s0 src 192.168.1.5 …"
    let mut iter = text.split_whitespace();
    while let Some(tok) = iter.next() {
        if tok == "dev" {
            return iter.next().map(str::to_string);
        }
    }
    None
}

/// Return all TUN-type interfaces on the system (type=65534 in sysfs).
/// Excludes loopback. Used for initial egress seeding.
fn detect_tun_ifaces() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else { return vec![] };
    let mut ifaces = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let type_path = format!("/sys/class/net/{name}/type");
        if let Ok(t) = fs::read_to_string(&type_path) {
            // type 65534 = TUN/TAP; WireGuard reports as type 65534 (wireguard interfaces
            // also appear here as they are tun devices at the kernel level).
            if t.trim() == "65534" {
                ifaces.push(name);
            }
        }
    }
    ifaces.sort();
    ifaces
}

fn open_routed_tcp(host: String, port: u16, target: RouteTarget, db_path: String) -> Result<String, String> {
    // Resolve and connect upstream synchronously so any failure is reported
    // to the emulator as a ControlResponse::Error *before* RoutedTcpReady is
    // sent.  Previously the connect happened inside the relay thread, so the
    // emulator received RoutedTcpReady immediately and curl was left stuck for
    // up to ROUTED_CONNECT_TIMEOUT_SECS before getting an abrupt TCP close.
    let addrs = resolve_socket_addrs(&host, port, Some(&target), &db_path)?;
    if let Some(first) = addrs.first() {
        if let Some(route_line) = route_probe_for(&first.ip().to_string()) {
            eprintln!(
                "routed route-probe (default/unmarked): target={target:?} first_addr={first} ip_route_get=\"{route_line}\""
            );
        }
        if let Some(mark) = fwmark_for_route_probe(&target) {
            if let Some(mline) = route_probe_marked(&first.ip().to_string(), mark) {
                eprintln!(
                    "routed route-probe (fwmark={mark}): target={target:?} first_addr={first} ip_route_get=\"{mline}\""
                );
            }
        }
    }
    let upstream = match &target {
        RouteTarget::Tun(iface) => connect_via_tun(&addrs, iface),
        RouteTarget::Device(iface) => connect_via_device(&addrs, iface),
        RouteTarget::Proxy(id) => Err(format!("proxy routing not yet implemented: {id}")),
    }?;

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let listen_addr = listener.local_addr().map_err(|e| e.to_string())?.to_string();
    std::thread::spawn(move || {
        let (client, _) = match listener.accept() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("routed relay accept failed: {e}");
                return;
            }
        };
        let _ = relay_bidirectional(client, upstream);
    });
    Ok(listen_addr)
}

/// Runtime knobs that `handle_client` needs to actually carry out side-effecting
/// requests like `SetNfqueueEnabled` (which rewrites nftables) and `Unlock`.
///
/// Kept as a small struct rather than free-floating parameters so the
/// `handle_client` signature stays readable as more knobs land.
#[derive(Clone)]
struct DaemonRuntime {
    /// nftables bootstrap, `None` only when nft setup failed at boot (in which
    /// case there's nothing to toggle).
    bootstrap: Option<Arc<dyn NftablesBootstrap>>,
    /// Queue number to use when interception is *enabled*. When `None`, the
    /// daemon was started without `LOGIGUARD_NFQUEUE` and the tray toggle
    /// can't bring interception up on its own — there is no userspace
    /// `NfqueueProcessor` running to drain the queue, so installing
    /// `queue num N` rules would just drop every packet.
    nfqueue_num: Option<u16>,
    route_mark_base: u32,
}

/// Decision returned by [`plan_nfqueue_toggle`]. Splitting the gate logic from
/// the side-effecting call keeps the toggle behavior unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum NfqueueToggleAction {
    /// Re-apply nftables with `queue` (`Some(n)` adds `queue num n` rules,
    /// `None` removes them), then commit the cached flag.
    Apply { queue: Option<u16> },
    /// Reject the toggle with this error message; the cached flag stays where
    /// it was so `Health` keeps reporting the actual kernel state.
    Reject(String),
}

/// Decide what to do for a `SetNfqueueEnabled { enabled }` request given the
/// daemon's current runtime config. Pure function so the table of (bootstrap
/// present, queue configured, enabled requested) is exhaustive and testable.
fn plan_nfqueue_toggle(
    bootstrap_present: bool,
    nfqueue_num: Option<u16>,
    enabled: bool,
) -> NfqueueToggleAction {
    if !bootstrap_present {
        return NfqueueToggleAction::Reject(
            "cannot toggle interception: nftables not active (daemon failed to install rules at boot — re-check root permissions and `nft list ruleset`)".to_string(),
        );
    }
    if enabled && nfqueue_num.is_none() {
        return NfqueueToggleAction::Reject(
            "cannot enable interception: daemon was started without LOGIGUARD_NFQUEUE — without a queue number there is no NfqueueProcessor draining packets, so adding `queue num N` rules would drop every flow. Set LOGIGUARD_NFQUEUE (e.g. 0) in the systemd unit and restart logiguardd.".to_string(),
        );
    }
    NfqueueToggleAction::Apply {
        queue: if enabled { nfqueue_num } else { None },
    }
}

fn handle_client(
    stream: UnixStream,
    service: &Arc<Mutex<ControlService<SqliteRuleRepository>>>,
    runtime: &DaemonRuntime,
    notification_tx: &broadcast::Sender<PushNotification>,
    db_path: &str,
) -> Result<(), String> {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if bytes == 0 {
        return Err("empty request".to_string());
    }
    let request: ControlRequest =
        serde_json::from_str(line.trim_end()).map_err(|e| e.to_string())?;

    let is_subscribe = matches!(request, ControlRequest::SubscribeToPending);

    let response = if matches!(request, ControlRequest::Unlock) {
        let on_console = peer_pid(&stream).map(is_physical_console).unwrap_or(false);
        if !on_console {
            ControlResponse::Error(
                "unlock rejected: must be run from a physical console (not SSH or pty)".to_string(),
            )
        } else if let Some(bs) = runtime.bootstrap.as_deref() {
            match bs.teardown() {
                Ok(()) => ControlResponse::Unlocked,
                Err(e) => ControlResponse::Error(format!("nftables teardown failed: {e}")),
            }
        } else {
            // No nftables active — nothing to tear down.
            ControlResponse::Unlocked
        }
    } else if let ControlRequest::SetNfqueueEnabled { enabled } = request {
        // Previously this just flipped a status bit in the service and never
        // touched the kernel — which is exactly why the tray toggle felt
        // "unreliable" (it was a no-op the user couldn't observe). Now the
        // handler actually re-applies the nftables protection chains with
        // `queue num N` rules added or omitted, and only on success does it
        // record the flag in the service so `Health` reflects truth.
        match plan_nfqueue_toggle(runtime.bootstrap.is_some(), runtime.nfqueue_num, enabled) {
            NfqueueToggleAction::Reject(msg) => ControlResponse::Error(msg),
            NfqueueToggleAction::Apply { queue } => {
                // `bootstrap.is_some()` already checked by the planner.
                let bs = runtime.bootstrap.as_deref().expect("bootstrap present");
                match bs.setup(queue, runtime.route_mark_base) {
                    Ok(()) => {
                        // Only commit the flag after nftables actually applied,
                        // so a kernel failure can't leave the UI claiming
                        // interception is on when no rules exist.
                        let mut svc = service
                            .lock()
                            .map_err(|_| "service lock poisoned".to_string())?;
                        svc.handle(ControlRequest::SetNfqueueEnabled { enabled })
                    }
                    Err(e) => ControlResponse::Error(format!(
                        "nftables update failed: {e} (interception state unchanged)"
                    )),
                }
            }
        }
    } else if let ControlRequest::OpenRoutedTcp { host, port, target } = request {
        match open_routed_tcp(host, port, target, db_path.to_string()) {
            Ok(listen_addr) => ControlResponse::RoutedTcpReady { listen_addr },
            Err(e) => ControlResponse::Error(e),
        }
    } else {
        let mut svc = service.lock().map_err(|_| "service lock poisoned".to_string())?;
        svc.handle(request)
    };

    let mut writer = &stream;
    let payload = serde_json::to_string(&response).map_err(|e| e.to_string())?;
    writer
        .write_all(format!("{payload}\n").as_bytes())
        .map_err(|e| e.to_string())?;

    // If client requested subscription, spawn a thread to push notifications.
    if is_subscribe {
        let stream_clone = stream.try_clone().map_err(|e| e.to_string())?;
        let mut rx = notification_tx.subscribe();
        std::thread::spawn(move || {
            let mut writer = &stream_clone;
            loop {
                match rx.try_recv() {
                    Ok(notif) => {
                        if let Ok(payload) = serde_json::to_string(&notif) {
                            let _ = writer.write_all(format!("{payload}\n").as_bytes());
                        }
                    }
                    Err(broadcast::error::TryRecvError::Lagged(_)) => {
                        // Buffer full, skip this message
                    }
                    Err(broadcast::error::TryRecvError::Empty) => {
                        // No message available, sleep briefly
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(broadcast::error::TryRecvError::Closed) => {
                        // Broadcast channel closed, exit
                        break;
                    }
                }
            }
        });
    }

    Ok(())
}

fn main() {
    let socket_path =
        std::env::var("LOGIGUARD_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
    let db_path = std::env::var("LOGIGUARD_DB_PATH").unwrap_or_else(|_| {
        std::env::var("HOME")
            .map(|h| format!("{h}/{DEFAULT_DB_RELATIVE}"))
            .unwrap_or_else(|_| format!("/root/{DEFAULT_DB_RELATIVE}"))
    });
    // Ensure the parent directory exists before SQLite tries to open the file.
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("warning: could not create db directory {}: {e}", parent.display());
        }
    }
    let default_timeout_secs =
        parse_env_u64("LOGIGUARD_DEFAULT_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS);
    let tcp_timeout_secs = parse_env_u64("LOGIGUARD_TCP_TIMEOUT_SECS", default_timeout_secs);
    let udp_timeout_secs = parse_env_u64("LOGIGUARD_UDP_TIMEOUT_SECS", default_timeout_secs);
    let quic_timeout_secs = parse_env_u64("LOGIGUARD_QUIC_TIMEOUT_SECS", default_timeout_secs);
    let other_timeout_secs = parse_env_u64("LOGIGUARD_OTHER_TIMEOUT_SECS", default_timeout_secs);
    let route_mark_base: u32 = std::env::var(ROUTE_MARK_BASE_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(ROUTE_MARK_BASE);
    init_route_policy(route_mark_base);
    println!("route mark base: {route_mark_base} (table base: {})", 10000 + route_mark_base);

    let _ = fs::remove_file(&socket_path);
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("failed to bind socket at {socket_path}: {err}");
            std::process::exit(1);
        }
    };
    // Ensure non-root clients (GPUI/CLI) can connect even when daemon runs as root.
    // This avoids recurring "Permission denied (os error 13)" on /tmp/logiguard.sock.
    if let Err(err) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o666)) {
        eprintln!("failed to set socket permissions on {socket_path}: {err}");
        std::process::exit(1);
    }

    let mut repo = match SqliteRuleRepository::open(&db_path) {
        Ok(repo) => repo,
        Err(err) => {
            eprintln!("failed to open sqlite db at {db_path}: {err}");
            std::process::exit(1);
        }
    };

    // Bug 2: delete all UntilRestart rules on every startup.
    repo.purge_session_rules();

    // Ensure the system default egress exists; do not auto-seed per-interface egresses.
    // Interface availability is checked at routing time by first_available_target().
    if repo.get_egress("eg-default").is_none() {
        repo.upsert_egress(&Egress {
            id: "eg-default".to_string(),
            name: "Default Route".to_string(),
            color: "#6b7280".to_string(),
            targets: vec![],
            dns_servers: vec![],
            is_system_default: true,
            is_available: true,
        });
    }

    // On first run (no user-defined egresses exist yet), seed useful egresses:
    // one LAN egress for the default-route interface, plus one egress per TUN
    // interface found on the system (WireGuard, throne, etc.).
    let user_egresses: Vec<_> = repo.list_egresses().into_iter()
        .filter(|e| !e.is_system_default)
        .collect();
    if user_egresses.is_empty() {
        seed_initial_egresses(&mut repo);
    }

    let startup_now = now_secs();

    // Bug 5: restore pending decisions that haven't expired.
    let live_pending = repo.list_live_pending(startup_now);

    let decision_engine = DecisionEngine::new(
        DEFAULT_PENDING_LIMIT,
        default_timeout_secs,
        OverflowPolicy::DenyNew,
    )
    .with_protocol_timeouts(
        tcp_timeout_secs,
        udp_timeout_secs,
        quic_timeout_secs,
        other_timeout_secs,
    );

    // NEW: Create broadcast channel for push notifications (buffer 500 messages)
    let (notification_tx, _) = tokio::sync::broadcast::channel(500);

    let service = Arc::new(Mutex::new(ControlService::with_decision_engine_and_health(
        repo,
        decision_engine,
        HealthConfig {
            pending_limit: DEFAULT_PENDING_LIMIT,
            default_timeout_secs,
            tcp_timeout_secs,
            udp_timeout_secs,
            quic_timeout_secs,
            other_timeout_secs,
        },
        notification_tx.clone(),  // Pass sender to service
    )));

    {
        let mut svc = service.lock().expect("service lock");
        svc.restore_pending(live_pending);
        svc.set_route_mark_fn(|target| ensure_route_mark(target).ok());
    }

    let health = {
        let mut svc = service.lock().expect("service lock");
        svc.handle(ControlRequest::Health)
    };
    println!(
        "daemon listening on {socket_path}, db={db_path}, \
         timeouts(default={default_timeout_secs}, tcp={tcp_timeout_secs}, \
         udp={udp_timeout_secs}, quic={quic_timeout_secs}, \
         other={other_timeout_secs}) {health:?}"
    );

    // Bug 1: tick every second so expired pending decisions are cleaned up.
    let service_for_timer = Arc::clone(&service);
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(mut svc) = service_for_timer.lock() {
            svc.tick(now_secs());
        }
    });

    // Parse optional NFQUEUE config (set LOGIGUARD_NFQUEUE=<queue_num>).
    let nfqueue_num: Option<u16> = std::env::var("LOGIGUARD_NFQUEUE")
        .ok()
        .and_then(|s| s.trim().parse().ok());

    // Always install the nftables protection chains — they preserve our route
    // mark across other tools' marking chains (e.g. throne, sing-box) so that
    // device-routed relay connections actually leave via the requested NIC.
    // NFQUEUE rules are only added when LOGIGUARD_NFQUEUE is set.
    let bs: Arc<dyn NftablesBootstrap> = Arc::new(SystemNftablesBootstrap);
    let nftables_ready = match bs.setup(nfqueue_num, route_mark_base) {
        Ok(()) => {
            println!(
                "nftables rules applied (route_mark_base={route_mark_base}, nfqueue={nfqueue_num:?})"
            );
            true
        }
        Err(e) => {
            eprintln!("nftables setup failed (are you root?): {e}");
            false
        }
    };

    // Start the NFQUEUE processor if enabled and nftables came up.
    let bootstrap: Option<Arc<dyn NftablesBootstrap>> = if nftables_ready {
        if let Some(queue_num) = nfqueue_num {
            let dns_cache = SniDnsCache::new();
            let classifier = FlowClassifier::new(
                ProcProcessResolver::new(),
                dns_cache.clone(),
                FakeDeviceLabelResolver { result: None },
            );
            let registrar = SharedService(Arc::clone(&service));
            match NfqueueProcessor::open(queue_num, classifier, registrar, dns_cache) {
                Err(e) => {
                    eprintln!("nfqueue open failed (are you root?): {e}");
                    Some(Arc::clone(&bs))
                }
                Ok(mut processor) => {
                    println!("nfqueue processor running on queue {queue_num}");
                    std::thread::spawn(move || {
                        if let Err(e) = processor.run_loop() {
                            eprintln!("nfqueue processor stopped: {e}");
                        }
                    });
                    Some(Arc::clone(&bs))
                }
            }
        } else {
            Some(Arc::clone(&bs))
        }
    } else {
        None
    };

    let runtime = DaemonRuntime {
        bootstrap: bootstrap.clone(),
        nfqueue_num,
        route_mark_base,
    };

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) =
                    handle_client(stream, &service, &runtime, &notification_tx, &db_path)
                {
                    eprintln!("request handling error: {err}");
                }
            }
            Err(err) => {
                eprintln!("incoming socket error: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_rejected_when_bootstrap_missing() {
        // Daemon failed to install nftables at boot (e.g. not root). The
        // tray toggle must return a real error rather than silently flip
        // the flag, otherwise `Health` would lie about whether interception
        // is on.
        let action = plan_nfqueue_toggle(false, Some(0), true);
        assert!(matches!(action, NfqueueToggleAction::Reject(_)));
        let action = plan_nfqueue_toggle(false, None, false);
        assert!(matches!(action, NfqueueToggleAction::Reject(_)));
    }

    #[test]
    fn enable_rejected_when_no_queue_configured() {
        // No LOGIGUARD_NFQUEUE → no NfqueueProcessor draining the queue.
        // Adding `queue num N` rules now would drop every packet, so we
        // refuse with an actionable error message and leave nftables alone.
        let action = plan_nfqueue_toggle(true, None, true);
        match action {
            NfqueueToggleAction::Reject(msg) => {
                assert!(
                    msg.contains("LOGIGUARD_NFQUEUE"),
                    "error message must point operators at the env var, got: {msg}"
                );
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn disable_always_applies_with_no_queue() {
        // Disabling interception is always safe — even with no queue
        // configured we just re-apply nftables without `queue num` rules,
        // which is the same as the configured-off state.
        assert_eq!(
            plan_nfqueue_toggle(true, None, false),
            NfqueueToggleAction::Apply { queue: None }
        );
        assert_eq!(
            plan_nfqueue_toggle(true, Some(0), false),
            NfqueueToggleAction::Apply { queue: None }
        );
    }

    #[test]
    fn enable_applies_with_configured_queue() {
        // The happy path: production systemd unit sets LOGIGUARD_NFQUEUE=0.
        // Enabling re-applies nftables WITH `queue num 0` rules so the
        // already-running processor starts receiving packets again.
        assert_eq!(
            plan_nfqueue_toggle(true, Some(0), true),
            NfqueueToggleAction::Apply { queue: Some(0) }
        );
        assert_eq!(
            plan_nfqueue_toggle(true, Some(42), true),
            NfqueueToggleAction::Apply { queue: Some(42) }
        );
    }
}
