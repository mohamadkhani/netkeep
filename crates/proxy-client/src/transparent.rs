use std::io::{copy, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use core_types::ProxyConfig;
use flow_classifier::sni::{extract_http_host, extract_tls_sni};
use flow_classifier::SniDnsCache;
use socket2::{Domain, Protocol, Socket, Type};

use crate::{connect_via_proxy, ProxyClientError};

/// Linux `IP_TRANSPARENT` — required on the listener for nftables REDIRECT.
#[cfg(target_os = "linux")]
const IP_TRANSPARENT: libc::c_int = 19;

/// A minimal transparent SOCKS/HTTP proxy server.
///
/// Listens on a local port. The kernel redirects marked traffic to this port
/// via nftables REDIRECT. The server uses `SO_ORIGINAL_DST` to recover the
/// original destination, then connects through the configured SOCKS/HTTP proxy
/// and relays bytes bidirectionally.
pub struct TransparentProxy {
    listener: TcpListener,
    proxy: ProxyConfig,
    timeout: Duration,
    /// Fwmark stamped on upstream sockets before connect so nftables bypasses
    /// NFQUEUE for the daemon's own proxy connections (see `connect_via_proxy`).
    daemon_mark: u32,
    /// Shared IP→domain cache. Local DNS can be poisoned (censored networks
    /// hand out sinkhole IPs); for proxy CONNECT the **domain** is what must
    /// reach the proxy, so the CONNECT host is resolved in-band from the
    /// app's own ClientHello/Host when possible, falling back to the cache's
    /// most recent binding for the original destination IP.
    dns_cache: SniDnsCache,
}

impl TransparentProxy {
    /// Bind the transparent proxy on the given address.
    pub fn bind(
        listen_addr: &str,
        proxy: ProxyConfig,
        timeout: Duration,
        daemon_mark: u32,
        dns_cache: SniDnsCache,
    ) -> Result<Self, ProxyClientError> {
        let listener = bind_transparent_listener(listen_addr)?;
        Ok(Self {
            listener,
            proxy,
            timeout,
            daemon_mark,
            dns_cache,
        })
    }

    /// Return the local address the proxy is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, ProxyClientError> {
        self.listener.local_addr().map_err(ProxyClientError::Io)
    }

    /// Run the accept loop, spawning a thread per connection.
    /// Blocks until the listener is closed.
    pub fn run(self: Arc<Self>) {
        loop {
            match self.listener.accept() {
                Ok((client, peer)) => {
                    let sv = Arc::clone(&self);
                    std::thread::spawn(move || {
                        if let Err(e) = sv.handle_client(client) {
                            eprintln!("transparent proxy: relay error (from {peer}): {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("transparent proxy: accept failed: {e}");
                    break;
                }
            }
        }
    }

    fn handle_client(&self, mut client: TcpStream) -> Result<(), String> {
        let original_dst = get_original_dst(&client)?;
        let port = original_dst.port();

        // The app's own first bytes (TLS ClientHello SNI or HTTP Host header)
        // are the authoritative hostname — they name the host even when the
        // shared IP cache holds a *different* domain that resolves to the
        // same IP. Peek before choosing the CONNECT target; the peeked bytes
        // are then forwarded as-is.
        let (prefix, hint) = peek_client_hello(&mut client, self.timeout);
        let host = connect_host(hint, &original_dst.ip().to_string(), &self.dns_cache);

        eprintln!(
            "transparent proxy: {} -> {host}:{port} via {}:{}",
            client
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "?".into()),
            self.proxy.host,
            self.proxy.port
        );

        // Try the in-band hint host first. If the upstream proxy cannot
        // resolve or reach it, fall back to the pre-hint behavior (cache,
        // then raw IP) instead of killing the flow — a dead CONNECT surfaces
        // in browsers as ERR_HTTP2_PROTOCOL_ERROR / ERR_CONNECTION_RESET.
        let mut upstream =
            match connect_via_proxy(&self.proxy, &host, port, self.timeout, self.daemon_mark) {
                Ok(upstream) => upstream,
                Err(hint_err) => {
                    let fallback =
                        connect_host(None, &original_dst.ip().to_string(), &self.dns_cache);
                    if fallback == host {
                        return Err(format!("proxy connect to {host}:{port}: {hint_err}"));
                    }
                    eprintln!(
                        "transparent proxy: hint host {host} unreachable ({hint_err}), \
                     retrying CONNECT with {fallback}:{port}"
                    );
                    connect_via_proxy(&self.proxy, &fallback, port, self.timeout, self.daemon_mark)
                        .map_err(|e| format!("proxy connect to {fallback}:{port}: {e}"))?
                }
            };
        if !prefix.is_empty() {
            upstream
                .write_all(&prefix)
                .map_err(|e| format!("forward peeked bytes to {host}:{port}: {e}"))?;
        }

        relay_bidirectional(client, upstream)
    }
}

/// Read the first bytes from the redirected client connection and recover the
/// intended hostname from an in-band TLS ClientHello SNI or HTTP `Host`
/// header.
///
/// Returns `(peeked_bytes, host_hint)`. All failure modes (timeout while the
/// app waits for a server greeting, connection reset, payload without SNI or
/// Host) degrade to `(possibly-empty prefix, None)` — the caller then falls
/// back to the IP-keyed DNS cache and passes the prefix through unharmed.
///
/// One read of up to 4 KiB is performed with the given timeout. A ClientHello
/// split across TCP segments whose SNI lands beyond the first read falls back
/// to the cache — acceptable, since real ClientHellos are a few hundred bytes
/// and arrive in the first segment in practice.
fn peek_client_hello(client: &mut TcpStream, timeout: Duration) -> (Vec<u8>, Option<String>) {
    let _ = client.set_read_timeout(Some(timeout));
    let mut buf = [0u8; 4096];
    let n = client.read(&mut buf).unwrap_or(0);
    let _ = client.set_read_timeout(None);
    let chunk = &buf[..n];
    let hint = extract_tls_sni(chunk).or_else(|| extract_http_host(chunk));
    (chunk.to_vec(), hint)
}

/// Pick the hostname used for the upstream proxy CONNECT.
///
/// Order: in-band hint from the app's own traffic → most recent domain the
/// DNS cache holds for the original IP → the IP itself (pass-through).
fn connect_host(hint: Option<String>, ip: &str, dns_cache: &SniDnsCache) -> String {
    hint.filter(|h| !h.is_empty())
        .or_else(|| dns_cache.lookup(ip))
        .unwrap_or_else(|| ip.to_string())
}

/// Bind a listener with `IP_TRANSPARENT` so nftables REDIRECT can deliver connections.
fn bind_transparent_listener(listen_addr: &str) -> Result<TcpListener, ProxyClientError> {
    use std::net::ToSocketAddrs;

    let addr = listen_addr
        .to_socket_addrs()
        .map_err(ProxyClientError::Io)?
        .next()
        .ok_or_else(|| {
            ProxyClientError::Protocol(format!("no socket addresses for {listen_addr}"))
        })?;

    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket =
        Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(ProxyClientError::Io)?;
    socket
        .set_reuse_address(true)
        .map_err(ProxyClientError::Io)?;

    #[cfg(target_os = "linux")]
    {
        let enable: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_IP,
                IP_TRANSPARENT,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(ProxyClientError::Io(std::io::Error::last_os_error()));
        }
    }

    socket.bind(&addr.into()).map_err(ProxyClientError::Io)?;
    socket.listen(128).map_err(ProxyClientError::Io)?;
    Ok(socket.into())
}

fn relay_bidirectional(client: TcpStream, upstream: TcpStream) -> Result<(), String> {
    let mut c_read = client.try_clone().map_err(|e| e.to_string())?;
    let mut c_write = client;
    let mut u_read = upstream.try_clone().map_err(|e| e.to_string())?;
    let mut u_write = upstream;

    let t1 = std::thread::spawn(move || copy(&mut c_read, &mut u_write).map_err(|e| e.to_string()));
    let t2 = std::thread::spawn(move || copy(&mut u_read, &mut c_write).map_err(|e| e.to_string()));

    let _ = t1
        .join()
        .map_err(|_| "relay thread join failed".to_string())??;
    let _ = t2
        .join()
        .map_err(|_| "relay thread join failed".to_string())??;
    Ok(())
}

/// Retrieve the original destination address from a socket that was
/// transparently redirected via nftables REDIRECT.
///
/// Uses the `SO_ORIGINAL_DST` socket option (Linux-specific).
fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr, String> {
    match get_original_dst_level(stream, libc::SOL_IP) {
        Ok(addr) => Ok(addr),
        Err(ipv4_err) => get_original_dst_level(stream, libc::IPPROTO_IPV6).map_err(|ipv6_err| {
            format!("SO_ORIGINAL_DST failed (ipv4: {ipv4_err}; ipv6: {ipv6_err})")
        }),
    }
}

fn get_original_dst_level(stream: &TcpStream, level: libc::c_int) -> Result<SocketAddr, String> {
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut addr_len: libc::socklen_t =
        std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            level,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut addr_len,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    parse_sockaddr_storage(&addr)
}

fn parse_sockaddr_storage(addr: &libc::sockaddr_storage) -> Result<SocketAddr, String> {
    if addr.ss_family == libc::AF_INET as libc::sa_family_t {
        let addr_ptr: *const libc::sockaddr_in = addr as *const _ as *const _;
        let addr_in = unsafe { *addr_ptr };
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
        let port = u16::from_be(addr_in.sin_port);
        Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
    } else if addr.ss_family == libc::AF_INET6 as libc::sa_family_t {
        let addr_ptr: *const libc::sockaddr_in6 = addr as *const _ as *const _;
        let addr_in6 = unsafe { *addr_ptr };
        let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
        let port = u16::from_be(addr_in6.sin6_port);
        Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port))
    } else {
        Err(format!("unknown address family: {}", addr.ss_family))
    }
}

/// `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` — value 80 in both IPv4 and IPv6 headers.
const SO_ORIGINAL_DST: libc::c_int = 80;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn so_original_dst_constant() {
        assert_eq!(SO_ORIGINAL_DST, 80);
    }

    #[test]
    fn connect_host_prefers_inband_hint_over_cache() {
        let cache = SniDnsCache::new();
        cache.insert("10.10.34.36", "www.facebook.com");
        // In-band SNI wins even when the cache holds another domain that
        // resolves to the same shared IP.
        assert_eq!(
            connect_host(Some("a.example".into()), "10.10.34.36", &cache),
            "a.example"
        );
    }

    #[test]
    fn connect_host_falls_back_to_cache_then_ip() {
        let cache = SniDnsCache::new();
        cache.insert("10.10.34.36", "www.facebook.com");
        assert_eq!(
            connect_host(None, "10.10.34.36", &cache),
            "www.facebook.com"
        );
        // Unknown IP passes through unchanged.
        assert_eq!(connect_host(None, "1.2.3.4", &cache), "1.2.3.4");
        // Empty hint behaves like no hint.
        assert_eq!(
            connect_host(Some(String::new()), "10.10.34.36", &cache),
            "www.facebook.com"
        );
    }
}
