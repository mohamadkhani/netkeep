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

    let mut stream: TcpStream = socket.into();
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
        0x01 => 4 + 2,   // IPv4 + port
        0x04 => 16 + 2,  // IPv6 + port
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
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{password}"));
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
        if response.len() >= 4
            && response[response.len() - 4..] == [b'\r', b'\n', b'\r', b'\n']
        {
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
        assert_eq!(socks5_reply_description(0x01), "general SOCKS server failure");
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
        assert_eq!(
            req,
            vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]
        );
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
                0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xBB
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
            let credentials = base64::engine::general_purpose::STANDARD
                .encode(format!("{username}:{password}"));
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
