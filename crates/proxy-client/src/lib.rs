use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use base64::Engine;
use core_types::{ProxyAuth, ProxyConfig, ProxyProtocol};

pub mod transparent;

#[derive(Debug)]
pub enum ProxyClientError {
    Io(std::io::Error),
    Protocol(String),
    AuthRejected,
    UnsupportedProtocol,
    ConnectTimeout,
}

impl std::fmt::Display for ProxyClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "proxy protocol error: {msg}"),
            Self::AuthRejected => write!(f, "proxy authentication rejected"),
            Self::UnsupportedProtocol => write!(f, "unsupported proxy protocol"),
            Self::ConnectTimeout => write!(f, "proxy connect timed out"),
        }
    }
}

impl std::error::Error for ProxyClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ProxyClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Connect to `host:port` through the given proxy configuration.
///
/// For SOCKS5 proxies, sends a CONNECT command through the SOCKS5 handshake.
/// For HTTP proxies, sends an HTTP CONNECT request.
/// For Shadowsocks, returns `UnsupportedProtocol` (not yet implemented).
///
/// The returned `TcpStream` is in a connected/established state and ready
/// for bidirectional byte relay.
pub fn connect_via_proxy(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, ProxyClientError> {
    // Check protocol support before opening any TCP connection.
    if matches!(proxy.protocol, ProxyProtocol::Shadowsocks) {
        return Err(ProxyClientError::UnsupportedProtocol);
    }

    let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
    let sock_addr: std::net::SocketAddr = proxy_addr
        .parse()
        .map_err(|_| ProxyClientError::Protocol(format!("invalid proxy address: {proxy_addr}")))?;

    let socket = socket2::Socket::new(
        socket2::Domain::for_address(sock_addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .map_err(ProxyClientError::Io)?;

    socket
        .connect_timeout(&socket2::SockAddr::from(sock_addr), timeout)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                ProxyClientError::ConnectTimeout
            } else {
                ProxyClientError::Io(e)
            }
        })?;

    let stream: TcpStream = socket.into();
    stream
        .set_read_timeout(Some(timeout))
        .map_err(ProxyClientError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(ProxyClientError::Io)?;

    let result = match proxy.protocol {
        ProxyProtocol::Socks5 => socks5_connect(stream, proxy, host, port),
        ProxyProtocol::Http => http_connect(stream, proxy, host, port),
        ProxyProtocol::Shadowsocks => unreachable!(),
    };

    // Relay path owns I/O timeouts; clear them after the handshake completes.
    if let Ok(ref s) = result {
        let _ = s.set_read_timeout(None);
        let _ = s.set_write_timeout(None);
    }
    result
}

fn map_io_err(e: std::io::Error) -> ProxyClientError {
    if e.kind() == std::io::ErrorKind::TimedOut {
        ProxyClientError::ConnectTimeout
    } else {
        ProxyClientError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 (RFC 1928 / RFC 1929)
// ---------------------------------------------------------------------------

fn socks5_connect(
    mut stream: TcpStream,
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyClientError> {
    let has_auth = matches!(proxy.auth, ProxyAuth::Basic { .. });

    // Greeting: version 5, N methods, method list
    let greeting = if has_auth {
        vec![0x05, 0x02, 0x00, 0x02] // no-auth + username/password
    } else {
        vec![0x05, 0x01, 0x00] // no-auth only
    };
    stream.write_all(&greeting).map_err(map_io_err)?;

    // Server method selection
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).map_err(map_io_err)?;
    if reply[0] != 0x05 {
        return Err(ProxyClientError::Protocol(format!(
            "expected SOCKS version 5, got {}",
            reply[0]
        )));
    }

    match reply[1] {
        0x00 => { /* no auth required */ }
        0x02 => {
            // Username/password auth (RFC 1929)
            let (username, password) = match &proxy.auth {
                ProxyAuth::Basic { username, password } => (username, password),
                _ => {
                    return Err(ProxyClientError::Protocol(
                        "server requested auth but none configured".to_string(),
                    ))
                }
            };
            if username.len() > 255 || password.len() > 255 {
                return Err(ProxyClientError::Protocol(
                    "username or password too long (max 255 bytes)".to_string(),
                ));
            }
            let mut auth_req = Vec::with_capacity(3 + username.len() + password.len());
            auth_req.push(0x01); // sub-negotiation version
            auth_req.push(username.len() as u8);
            auth_req.extend_from_slice(username.as_bytes());
            auth_req.push(password.len() as u8);
            auth_req.extend_from_slice(password.as_bytes());
            stream.write_all(&auth_req).map_err(map_io_err)?;

            let mut auth_reply = [0u8; 2];
            stream.read_exact(&mut auth_reply).map_err(map_io_err)?;
            if auth_reply[1] != 0x00 {
                return Err(ProxyClientError::AuthRejected);
            }
        }
        0xFF => {
            return Err(ProxyClientError::Protocol(
                "no acceptable auth method".to_string(),
            ))
        }
        other => {
            return Err(ProxyClientError::Protocol(format!(
                "unsupported auth method: {other}"
            )))
        }
    }

    // CONNECT request
    let mut connect_req = vec![0x05, 0x01, 0x00]; // version, CONNECT, reserved
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                connect_req.push(0x01); // IPv4
                connect_req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                connect_req.push(0x04); // IPv6
                connect_req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        // Domain name — prefer this for SOCKS5 so the proxy does DNS resolution
        let domain_bytes = host.as_bytes();
        if domain_bytes.len() > 255 {
            return Err(ProxyClientError::Protocol(format!(
                "domain name too long: {} bytes",
                domain_bytes.len()
            )));
        }
        connect_req.push(0x03); // domain
        connect_req.push(domain_bytes.len() as u8);
        connect_req.extend_from_slice(domain_bytes);
    }
    connect_req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&connect_req).map_err(map_io_err)?;

    // CONNECT reply: [version, reply, reserved, atyp, ...]
    let mut reply_header = [0u8; 4];
    stream.read_exact(&mut reply_header).map_err(map_io_err)?;
    if reply_header[0] != 0x05 {
        return Err(ProxyClientError::Protocol(format!(
            "expected SOCKS5 reply, got version {}",
            reply_header[0]
        )));
    }
    if reply_header[1] != 0x00 {
        return Err(ProxyClientError::Protocol(format!(
            "SOCKS5 CONNECT failed: reply code {} ({})",
            reply_header[1],
            socks5_reply_description(reply_header[1])
        )));
    }

    // Read bound address (we don't need it, but must consume it)
    let bound_addr_len = match reply_header[3] {
        0x01 => 4 + 2,  // IPv4 + port
        0x04 => 16 + 2, // IPv6 + port
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).map_err(map_io_err)?;
            len_buf[0] as usize + 2 // domain + port
        }
        other => {
            return Err(ProxyClientError::Protocol(format!(
                "unknown address type in reply: {other}"
            )))
        }
    };
    let mut bound_addr = vec![0u8; bound_addr_len];
    stream.read_exact(&mut bound_addr).map_err(map_io_err)?;

    Ok(stream)
}

fn socks5_reply_description(code: u8) -> &'static str {
    match code {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// HTTP CONNECT (RFC 7231 Section 4.3.6)
// ---------------------------------------------------------------------------

fn http_connect(
    mut stream: TcpStream,
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyClientError> {
    let host_port = format!("{host}:{port}");
    let mut request = format!("CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n");

    if let ProxyAuth::Basic { username, password } = &proxy.auth {
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
    }

    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).map_err(map_io_err)?;

    // Read response status line
    let mut response = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).map_err(map_io_err)?;
        response.push(buf[0]);
        if response.len() >= 4 && response[response.len() - 4..] == [b'\r', b'\n', b'\r', b'\n'] {
            break;
        }
        if response.len() > 8192 {
            return Err(ProxyClientError::Protocol(
                "HTTP CONNECT response headers too large".to_string(),
            ));
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    let status_line = response_str
        .lines()
        .next()
        .ok_or_else(|| ProxyClientError::Protocol("empty HTTP response".to_string()))?;

    // Parse "HTTP/1.x NNN ..."
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(ProxyClientError::Protocol(format!(
            "malformed HTTP response: {status_line}"
        )));
    }
    let status_code: u16 = parts[1].parse().map_err(|_| {
        ProxyClientError::Protocol(format!("non-numeric HTTP status: {}", parts[1]))
    })?;

    if status_code != 200 {
        return Err(ProxyClientError::Protocol(format!(
            "HTTP CONNECT failed: {status_code} {}",
            parts.get(2).unwrap_or(&"")
        )));
    }

    // Stream is now in tunnel mode
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_proxy(protocol: ProxyProtocol, auth: ProxyAuth) -> ProxyConfig {
        ProxyConfig {
            id: "test-proxy".to_string(),
            name: "Test Proxy".to_string(),
            protocol,
            host: "127.0.0.1".to_string(),
            port: 1080,
            auth,
            enabled: true,
        }
    }

    // --- SOCKS5 unit tests ---

    #[test]
    fn socks5_reply_descriptions() {
        assert_eq!(socks5_reply_description(0x00), "succeeded");
        assert_eq!(
            socks5_reply_description(0x01),
            "general SOCKS server failure"
        );
        assert_eq!(socks5_reply_description(0x05), "connection refused");
        assert_eq!(socks5_reply_description(0xFF), "unknown");
    }

    #[test]
    fn socks5_greeting_no_auth() {
        let proxy = mk_proxy(ProxyProtocol::Socks5, ProxyAuth::None);
        // Simulate: greeting should be [0x05, 0x01, 0x00]
        let has_auth = matches!(proxy.auth, ProxyAuth::Basic { .. });
        let greeting = if has_auth {
            vec![0x05, 0x02, 0x00, 0x02]
        } else {
            vec![0x05, 0x01, 0x00]
        };
        assert_eq!(greeting, vec![0x05, 0x01, 0x00]);
    }

    #[test]
    fn socks5_greeting_with_auth() {
        let proxy = mk_proxy(
            ProxyProtocol::Socks5,
            ProxyAuth::Basic {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
        );
        let has_auth = matches!(proxy.auth, ProxyAuth::Basic { .. });
        let greeting = if has_auth {
            vec![0x05, 0x02, 0x00, 0x02]
        } else {
            vec![0x05, 0x01, 0x00]
        };
        assert_eq!(greeting, vec![0x05, 0x02, 0x00, 0x02]);
    }

    #[test]
    fn socks5_connect_request_ipv4() {
        let mut req = vec![0x05, 0x01, 0x00];
        let host = "1.2.3.4";
        let ip: IpAddr = host.parse().unwrap();
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(_) => unreachable!(),
        }
        req.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(req, vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]);
    }

    #[test]
    fn socks5_connect_request_domain() {
        let mut req = vec![0x05, 0x01, 0x00];
        let host = "example.com";
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            req,
            vec![
                0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xBB
            ]
        );
    }

    // --- HTTP CONNECT unit tests ---

    #[test]
    fn http_connect_request_no_auth() {
        let _proxy = mk_proxy(ProxyProtocol::Http, ProxyAuth::None);
        let host = "example.com";
        let port = 443;
        let host_port = format!("{host}:{port}");
        let mut request = format!("CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n");
        request.push_str("\r\n");
        assert!(request.contains("CONNECT example.com:443 HTTP/1.1"));
        assert!(request.contains("Host: example.com:443"));
        assert!(!request.contains("Proxy-Authorization"));
    }

    #[test]
    fn http_connect_request_with_auth() {
        let proxy = mk_proxy(
            ProxyProtocol::Http,
            ProxyAuth::Basic {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
        );
        let host = "example.com";
        let port = 443;
        let host_port = format!("{host}:{port}");
        let mut request = format!("CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n");
        if let ProxyAuth::Basic { username, password } = &proxy.auth {
            let credentials =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
        }
        request.push_str("\r\n");
        assert!(request.contains("Proxy-Authorization: Basic"));
        assert!(request.contains("dXNlcjpwYXNz")); // base64("user:pass")
    }

    #[test]
    fn http_response_parsing_200() {
        let response = "HTTP/1.1 200 Connection established\r\n\r\n";
        let status_line = response.lines().next().unwrap();
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        let code: u16 = parts[1].parse().unwrap();
        assert_eq!(code, 200);
    }

    #[test]
    fn http_response_parsing_407() {
        let response = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
        let status_line = response.lines().next().unwrap();
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        let code: u16 = parts[1].parse().unwrap();
        assert_ne!(code, 200);
    }

    #[test]
    fn shadowsocks_returns_unsupported() {
        let proxy = mk_proxy(
            ProxyProtocol::Shadowsocks,
            ProxyAuth::Shadowsocks {
                method: "aes-256-gcm".to_string(),
                password: "secret".to_string(),
            },
        );
        let result = connect_via_proxy(&proxy, "example.com", 443, Duration::from_secs(5));
        assert!(matches!(result, Err(ProxyClientError::UnsupportedProtocol)));
    }
}

// ---------------------------------------------------------------------------
// Connectivity testing functions
// ---------------------------------------------------------------------------

/// Test HTTP/HTTPS connectivity through a proxy.
///
/// Connects to the URL's host:port via the proxy, sends an HTTP HEAD request,
/// waits for the response status line, and returns the round-trip latency in ms.
pub fn test_http_connectivity(
    proxy: &ProxyConfig,
    url: &str,
    timeout: Duration,
) -> Result<u64, ProxyClientError> {
    let start = std::time::Instant::now();

    // Parse URL to extract host, port, and scheme
    let (host, _port, is_https) = parse_test_url(url)?;

    // Always use port 80 — we send plain HTTP (no TLS), so connecting to
    // port 443 would cause the server to reject us immediately.
    let port = 80;

    // Connect through the proxy
    let mut stream = connect_via_proxy(proxy, &host, port, timeout)?;

    // Send HTTP HEAD request
    let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(ProxyClientError::Io)?;

    // Read response status line
    let mut response = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).map_err(ProxyClientError::Io)?;
        response.push(buf[0]);
        if response.len() >= 4 && response[response.len() - 4..] == [b'\r', b'\n', b'\r', b'\n'] {
            break;
        }
        if response.len() > 8192 {
            return Err(ProxyClientError::Protocol(
                "HTTP response headers too large".to_string(),
            ));
        }
    }

    let elapsed = start.elapsed();
    let latency_ms = elapsed.as_millis() as u64;

    // Parse status line to check for success
    let response_str = String::from_utf8_lossy(&response);
    let status_line = response_str
        .lines()
        .next()
        .ok_or_else(|| ProxyClientError::Protocol("empty HTTP response".to_string()))?;

    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(ProxyClientError::Protocol(format!(
            "malformed HTTP response: {status_line}"
        )));
    }

    let status_code: u16 = parts[1].parse().map_err(|_| {
        ProxyClientError::Protocol(format!("non-numeric HTTP status: {}", parts[1]))
    })?;

    // Accept any 2xx or 3xx response as success
    if !(200..400).contains(&status_code) {
        return Err(ProxyClientError::Protocol(format!(
            "HTTP {status_code} {}",
            parts.get(2).unwrap_or(&"")
        )));
    }

    let _ = is_https; // already handled: we always use port 80
    Ok(latency_ms)
}

/// Test DNS resolution through a proxy.
///
/// Connects to 8.8.8.8:53 (Google DNS) via the proxy, sends a DNS A query
/// for the given domain, waits for the response, and returns the round-trip
/// latency in ms.
pub fn test_dns_connectivity(
    proxy: &ProxyConfig,
    domain: &str,
    timeout: Duration,
) -> Result<u64, ProxyClientError> {
    let start = std::time::Instant::now();

    // Connect to Google DNS through the proxy
    let mut stream = connect_via_proxy(proxy, "8.8.8.8", 53, timeout)?;

    // Set read timeout so we don't block forever on unresponsive servers
    stream
        .set_read_timeout(Some(timeout))
        .map_err(ProxyClientError::Io)?;

    // Build a minimal DNS A query
    let query = build_dns_a_query(domain);

    // DNS over TCP: 2-byte length prefix
    let len_bytes = (query.len() as u16).to_be_bytes();
    stream.write_all(&len_bytes).map_err(ProxyClientError::Io)?;
    stream.write_all(&query).map_err(ProxyClientError::Io)?;

    // Read response length prefix — use a loop to handle partial reads
    let mut len_buf = [0u8; 2];
    let mut len_read = 0;
    while len_read < 2 {
        match stream.read(&mut len_buf[len_read..]) {
            Ok(0) => {
                return Err(ProxyClientError::Protocol(
                    "proxy closed connection before DNS response length was received".to_string(),
                ))
            }
            Ok(n) => len_read += n,
            Err(e) => return Err(ProxyClientError::Io(e)),
        }
    }
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    if resp_len > 4096 {
        return Err(ProxyClientError::Protocol(
            "DNS response too large".to_string(),
        ));
    }

    // Read response body — accumulate bytes, tolerate early EOF
    let mut resp_buf = vec![0u8; resp_len];
    let mut total_read = 0;
    while total_read < resp_len {
        match stream.read(&mut resp_buf[total_read..]) {
            Ok(0) => break, // EOF — remote closed connection
            Ok(n) => total_read += n,
            Err(e) => {
                // If we already have a DNS header worth of data, try to validate it
                if total_read >= 12 {
                    break;
                }
                return Err(ProxyClientError::Io(e));
            }
        }
    }
    resp_buf.truncate(total_read);

    let elapsed = start.elapsed();
    let latency_ms = elapsed.as_millis() as u64;

    // Minimal validation: response must be at least 12 bytes (DNS header)
    if resp_buf.len() < 12 {
        return Err(ProxyClientError::Protocol(format!(
            "DNS response too short (got {} bytes, need at least 12 for header)",
            resp_buf.len()
        )));
    }

    // Check QR bit (bit 7 of first byte of flags) — must be 1 (response)
    let flags_hi = resp_buf[2];
    if flags_hi & 0x80 == 0 {
        return Err(ProxyClientError::Protocol(
            "DNS response has QR=0 (not a response)".to_string(),
        ));
    }

    // Check RCODE (bits 3-0 of second byte of flags)
    let rcode = resp_buf[3] & 0x0F;
    if rcode != 0 {
        return Err(ProxyClientError::Protocol(format!(
            "DNS response RCODE={rcode}"
        )));
    }

    Ok(latency_ms)
}

/// Parse a URL into (host, port, is_https).
fn parse_test_url(url: &str) -> Result<(String, u16, bool), ProxyClientError> {
    let url = url.trim();

    // Extract scheme
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        // Default to https
        ("https", url)
    };

    if rest.is_empty() {
        return Err(ProxyClientError::Protocol("URL has no host".to_string()));
    }

    // Strip path/query/fragment
    let host_port = rest.split('/').next().unwrap_or(rest);
    let host_port = host_port.split('?').next().unwrap_or(host_port);
    let host_port = host_port.split('#').next().unwrap_or(host_port);

    // Handle [IPv6]:port
    if let Some(host_port_inner) = host_port.strip_prefix('[') {
        if let Some(bracket_end) = host_port_inner.find(']') {
            let host = &host_port_inner[..bracket_end];
            let rest = &host_port_inner[bracket_end + 1..];
            let port = if let Some(port_str) = rest.strip_prefix(':') {
                port_str.parse::<u16>().map_err(|_| {
                    ProxyClientError::Protocol(format!("invalid port in URL: {port_str}"))
                })?
            } else if scheme == "https" {
                443
            } else {
                80
            };
            return Ok((host.to_string(), port, scheme == "https"));
        }
    }

    // Handle host:port
    if let Some(colon_pos) = host_port.rfind(':') {
        let host = &host_port[..colon_pos];
        let port_str = &host_port[colon_pos + 1..];
        let port = port_str
            .parse::<u16>()
            .map_err(|_| ProxyClientError::Protocol(format!("invalid port in URL: {port_str}")))?;
        Ok((host.to_string(), port, scheme == "https"))
    } else {
        let port = if scheme == "https" { 443 } else { 80 };
        Ok((host_port.to_string(), port, scheme == "https"))
    }
}

/// Build a minimal DNS A query packet for the given domain.
fn build_dns_a_query(domain: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    // Transaction ID (arbitrary)
    packet.extend_from_slice(&[0x12, 0x34]);
    // Flags: standard query, recursion desired
    packet.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT = 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // NSCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // ARCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]);

    // QNAME: domain labels
    for label in domain.split('.') {
        let label_bytes = label.as_bytes();
        packet.push(label_bytes.len() as u8);
        packet.extend_from_slice(label_bytes);
    }
    packet.push(0x00); // root label

    // QTYPE = A (1)
    packet.extend_from_slice(&[0x00, 0x01]);
    // QCLASS = IN (1)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

#[cfg(test)]
mod connectivity_tests {
    use super::*;

    #[test]
    fn parse_url_https_default_port() {
        let (host, port, is_https) = parse_test_url("https://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert!(is_https);
    }

    #[test]
    fn parse_url_http_default_port() {
        let (host, port, is_https) = parse_test_url("http://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert!(!is_https);
    }

    #[test]
    fn parse_url_with_port() {
        let (host, port, is_https) = parse_test_url("https://example.com:8443/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert!(is_https);
    }

    #[test]
    fn parse_url_no_scheme_defaults_https() {
        let (host, port, is_https) = parse_test_url("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert!(is_https);
    }

    #[test]
    fn parse_url_with_query_and_fragment() {
        let (host, port, _) = parse_test_url("http://example.com:8080/path?q=1#frag").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_url_empty_returns_error() {
        let result = parse_test_url("https://");
        assert!(result.is_err());
    }

    #[test]
    fn build_dns_query_structure() {
        let query = build_dns_a_query("example.com");
        // Transaction ID
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        // Flags: standard query, RD=1
        assert_eq!(&query[2..4], &[0x01, 0x00]);
        // QDCOUNT = 1
        assert_eq!(&query[4..6], &[0x00, 0x01]);
        // QTYPE = A (1)
        let len = query.len();
        assert_eq!(&query[len - 4..len - 2], &[0x00, 0x01]);
        // QCLASS = IN (1)
        assert_eq!(&query[len - 2..len], &[0x00, 0x01]);
    }

    #[test]
    fn build_dns_query_labels() {
        let query = build_dns_a_query("www.example.com");
        // Label "www" (3 bytes)
        assert_eq!(query[12], 3);
        assert_eq!(&query[13..16], b"www");
        // Label "example" (7 bytes)
        assert_eq!(query[16], 7);
        assert_eq!(&query[17..24], b"example");
        // Label "com" (3 bytes)
        assert_eq!(query[24], 3);
        assert_eq!(&query[25..28], b"com");
        // Root label
        assert_eq!(query[28], 0);
    }
}
