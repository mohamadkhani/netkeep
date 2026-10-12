//! In-band hostname extraction from TCP payloads.
//!
//! Shared by the NFQUEUE processor (per-packet domain hints) and the
//! transparent proxy (recovering the CONNECT host from the relayed
//! ClientHello / HTTP request). Previously private to `enforcer::nfqueue`.

/// Extract the SNI hostname from a TLS ClientHello payload.
///
/// Wire layout of the fields we walk (big-endian throughout):
/// ```text
/// TLS record header  (5): type(0x16) version(2) length(2)
/// handshake header   (4): type(0x01) length(3)
/// ClientHello header (34): version(2) random(32)
/// then: session id length (u8) + session id
///       cipher suites length (u16) + cipher suites
///       compression methods length (u8) + compression methods
///       extensions length (u16) + extensions
/// each extension: type (u16) + length (u16) + data
/// SNI extension (0x0000):
///       SNI list length (u16)
///       SNI entry type (u8, 0x00 = host_name) + name length (u16) + name bytes
/// ```
pub fn extract_tls_sni(payload: &[u8]) -> Option<String> {
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
pub fn extract_http_host(payload: &[u8]) -> Option<String> {
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
pub fn is_tls_clienthello_packet(payload: &[u8]) -> bool {
    payload.len() >= 43 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

/// HTTP/1.x request methods we care about. We only need a quick early-reject
/// for "this payload doesn't look like HTTP at all" — the full method set
/// isn't required for correctness, just for avoiding a `\r\nHost:` substring
/// search on arbitrary binary TCP payloads.
pub fn starts_with_http_method(payload: &[u8]) -> bool {
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

    fn build_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let name_len = sni_bytes.len() as u16;
        // SNI extension data: list_len(u16) + entry_type(u8) + name_len(u16) + name
        let sni_ext_data_len = (2 + 1 + 2 + sni_bytes.len()) as u16;
        // Full extension wire size: type(2) + len(2) + data
        let sni_ext_total = (4 + sni_ext_data_len) as usize;

        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]); // client version
        hello_body.extend_from_slice(&[0x42; 32]); // random
        hello_body.push(0x00); // session id length
        hello_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        hello_body.push(0x01); // compression methods length
        hello_body.push(0x00); // null compression
        hello_body.extend_from_slice(&(sni_ext_total as u16).to_be_bytes());
        hello_body.extend_from_slice(&[0x00, 0x00]); // ext type = SNI
        hello_body.extend_from_slice(&sni_ext_data_len.to_be_bytes());
        hello_body.extend_from_slice(&(1 + 2 + name_len).to_be_bytes()); // SNI list_len
        hello_body.push(0x00); // host_name type
        hello_body.extend_from_slice(&name_len.to_be_bytes());
        hello_body.extend_from_slice(sni_bytes);

        let mut payload = vec![0x16, 0x03, 0x01];
        let rec_len = (4 + hello_body.len()) as u16;
        payload.extend_from_slice(&rec_len.to_be_bytes());
        payload.push(0x01); // ClientHello
        let hello_len = hello_body.len() as u32;
        payload.extend_from_slice(&hello_len.to_be_bytes()[1..]); // 3-byte length
        payload.extend_from_slice(&hello_body);
        payload
    }

    #[test]
    fn sni_extracted() {
        let hello = build_client_hello("example.com");
        assert_eq!(extract_tls_sni(&hello), Some("example.com".to_string()));
    }

    #[test]
    fn sni_rejects_non_clienthello() {
        assert_eq!(extract_tls_sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(extract_tls_sni(&[]), None);
    }

    #[test]
    fn http_host_extracted_and_lowercased() {
        let payload = b"GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n";
        assert_eq!(extract_http_host(payload), Some("example.com".to_string()));
    }

    #[test]
    fn http_host_strips_port() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(extract_http_host(payload), Some("example.com".to_string()));
    }

    #[test]
    fn http_host_rejects_non_http() {
        assert_eq!(
            extract_http_host(b"\x00\x01\x02\r\nHost: tricked.com\r\n\x05"),
            None
        );
    }

    #[test]
    fn clienthello_detector() {
        let hello = build_client_hello("a.com");
        assert!(is_tls_clienthello_packet(&hello));
        assert!(!is_tls_clienthello_packet(b"GET / HTTP/1.1\r\n"));
    }
}
