//! Network-owner lookup (RDAP) for IP-only decision dialogs.
//!
//! The dialog is offline by default. When the user opts in, a destination IP
//! can be resolved to the network block that owns it, and the whole block can
//! be stored as one `Cidr` rule instead of forcing the user to know registry
//! ranges.
//!
//! Decisions never wait for this module: `decision_dialog` starts the lookup
//! on a background executor and renders the dialog first. The lookup has a
//! short timeout and falls back to a stale-but-cached answer when the network
//! part fails.
//!
//! The data source is RDAP over HTTPS. Nothing here makes the result
//! authoritative for policy: the range is registry data, not a resolver
//! answer, and the rule that gets written is still a plain CIDR.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// How long a cached answer is served without asking the registry again.
pub const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Per-connection timeout. The dialog is already on screen, so this only
/// bounds how long a chip may take to appear.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

const MAX_REDIRECTS: usize = 4;
const CACHE_FORMAT_VERSION: u32 = 1;

/// The network block that owns an address, as reported by RDAP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkOwner {
    /// Canonical prefix, e.g. `140.82.112.0/20`.
    pub prefix: String,
    /// Registry object name, e.g. `GITHUB`.
    #[serde(default)]
    pub name: String,
    /// Organisation shown to the user, e.g. `GitHub, Inc.`.
    pub org: String,
    /// Origin ASN when the registry response carries one.
    #[serde(default)]
    pub asn: Option<u32>,
}

impl NetworkOwner {
    /// Text used under the address: `GitHub, Inc. · 140.82.112.0/20 · AS36459`.
    pub fn display(&self) -> String {
        let mut parts = vec![self.org.clone(), self.prefix.clone()];
        if let Some(asn) = self.asn {
            parts.push(format!("AS{asn}"));
        }
        parts.join(" · ")
    }
}

/// Read the owner for `ip` from cache, refreshing a stale entry when possible.
///
/// Returns `None` when the address is not IPv4, the lookup fails, and no
/// usable cached entry exists.
pub fn lookup_owner(ip: &str) -> Option<NetworkOwner> {
    let ip: Ipv4Addr = ip.parse().ok()?;
    lookup_owner_with(ip, unix_now(), &cache_path()?, |ip| {
        fetch_rdap(ip, LOOKUP_TIMEOUT)
    })
}

fn lookup_owner_with<F>(ip: Ipv4Addr, now: u64, cache_path: &Path, fetch: F) -> Option<NetworkOwner>
where
    F: FnOnce(&str) -> Result<String, String>,
{
    let mut cache = Cache::load(cache_path);

    let cached = cache.lookup(ip, now);
    if let Some((owner, true)) = &cached {
        return Some(owner.clone());
    }

    match fetch(&ip.to_string())
        .ok()
        .and_then(|body| parse_rdap_response(ip, &body))
    {
        Some(owner) => {
            cache.insert(owner.clone(), now);
            let _ = cache.save(cache_path);
            Some(owner)
        }
        // A registry that cannot be reached must not erase what we displayed
        // yesterday. Prefer the stale answer; it is still better evidence
        // than an opaque /32.
        None => cached.map(|(owner, _)| owner),
    }
}

/// Where the per-user RDAP cache lives. `NETKEEP_RDAP_CACHE` overrides the
/// whole path so tests and unusual deployments never touch the real home.
pub fn cache_path() -> Option<PathBuf> {
    if let Ok(path) = env::var("NETKEEP_RDAP_CACHE") {
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    if let Ok(base) = env::var("XDG_CACHE_HOME") {
        if !base.is_empty() {
            return Some(PathBuf::from(base).join("netkeep").join("rdap.json"));
        }
    }
    env::var("HOME")
        .ok()
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".cache/netkeep/rdap.json"))
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a registry response into an owner for `ip`.
///
/// Prefers the `cidr0_cidrs` extension (already canonical) and falls back to
/// the minimal prefix covering `startAddress`..`endAddress`.
pub fn parse_rdap_response(ip: Ipv4Addr, body: &str) -> Option<NetworkOwner> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let prefix = prefix_from_cidr0(ip, &value).or_else(|| {
        let start = parse_v4(value.get("startAddress")?.as_str()?)?;
        let end = parse_v4(value.get("endAddress")?.as_str()?)?;
        prefix_from_range(start, end).ok()
    })?;

    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let handle = value
        .get("handle")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let org = organisation_name(&value)
        .or_else(|| non_empty(name.clone()))
        .or_else(|| non_empty(handle))
        .unwrap_or_else(|| prefix.clone());
    let asn = origin_asn(&value);

    Some(NetworkOwner {
        prefix,
        name,
        org,
        asn,
    })
}

fn parse_v4(text: &str) -> Option<Ipv4Addr> {
    text.parse().ok()
}

fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn prefix_from_cidr0(ip: Ipv4Addr, value: &serde_json::Value) -> Option<String> {
    let blocks = value.get("cidr0_cidrs")?.as_array()?;
    blocks.iter().find_map(|block| {
        let base = parse_v4(block.get("v4prefix")?.as_str()?)?;
        let length = block.get("length")?.as_u64()?;
        let length = u8::try_from(length).ok()?;
        let candidate = format!("{base}/{length}");
        prefix_covers(&candidate, ip).then_some(candidate)
    })
}

/// Minimal single prefix that covers the inclusive range. RDAP network
/// objects should be prefix-aligned; `startAddress`/`endAddress` is the
/// fallback when the `cidr0` extension is absent.
pub fn prefix_from_range(start: Ipv4Addr, end: Ipv4Addr) -> Result<String, ()> {
    let start = u32::from(start);
    let end = u32::from(end);
    if start > end {
        return Err(());
    }
    let length = (start ^ end).leading_zeros() as u8;
    let mask = if length == 0 {
        0
    } else {
        u32::MAX << (32 - length)
    };
    let base = Ipv4Addr::from(start & mask);
    Ok(format!("{base}/{length}"))
}

/// Does `prefix` (e.g. `140.82.112.0/20`) contain `ip`?
pub fn prefix_covers(prefix: &str, ip: Ipv4Addr) -> bool {
    let Some((base, length)) = parse_prefix(prefix) else {
        return false;
    };
    let Some(length) = prefix_length(length) else {
        return false;
    };
    if length == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - length);
    (u32::from(base) & mask) == (u32::from(ip) & mask)
}

fn parse_prefix(prefix: &str) -> Option<(Ipv4Addr, u8)> {
    let (base, length) = prefix.split_once('/')?;
    Some((base.parse().ok()?, length.parse().ok()?))
}

fn prefix_length(length: u8) -> Option<u8> {
    (length <= 32).then_some(length)
}

fn organisation_name(value: &serde_json::Value) -> Option<String> {
    let entities = value.get("entities")?.as_array()?;
    for role in ["registrant", "administrative", "technical"] {
        for entity in entities {
            let has_role = entity
                .get("roles")
                .and_then(|v| v.as_array())
                .is_some_and(|roles| roles.iter().any(|r| r.as_str() == Some(role)));
            if !has_role {
                continue;
            }
            if let Some(name) = vcard_fn(entity) {
                return Some(name);
            }
        }
    }
    entities.iter().find_map(vcard_fn)
}

fn vcard_fn(entity: &serde_json::Value) -> Option<String> {
    let card = entity.get("vcardArray")?.as_array()?;
    let properties = card.get(1)?.as_array()?;
    properties.iter().find_map(|property| {
        let fields = property.as_array()?;
        if fields.first()?.as_str()? != "fn" {
            return None;
        }
        let name = fields.get(3)?.as_str()?.trim();
        (!name.is_empty()).then(|| name.to_string())
    })
}

fn origin_asn(value: &serde_json::Value) -> Option<u32> {
    let numbers = value.get("arin_originas0_originautnums")?.as_array()?;
    numbers
        .iter()
        .find_map(|n| n.as_u64().and_then(|n| u32::try_from(n).ok()))
        .or_else(|| {
            value
                .get("asn")
                .and_then(|n| n.as_u64())
                .and_then(|n| u32::try_from(n).ok())
        })
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    entries: Vec<CacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    owner: NetworkOwner,
    fetched_at: u64,
}

#[derive(Default)]
pub struct Cache {
    entries: Vec<CacheEntry>,
}

impl Cache {
    pub fn load(path: &Path) -> Self {
        let entries = fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CacheFile>(&bytes).ok())
            .filter(|file| file.version == CACHE_FORMAT_VERSION || file.version == 0)
            .map(|file| file.entries)
            .unwrap_or_default();
        Self { entries }
    }

    /// Best (longest-prefix) entry containing `ip` and whether it is fresh.
    pub fn lookup(&self, ip: Ipv4Addr, now: u64) -> Option<(NetworkOwner, bool)> {
        self.entries
            .iter()
            .filter(|entry| prefix_covers(&entry.owner.prefix, ip))
            .filter_map(|entry| {
                let (_, length) = parse_prefix(&entry.owner.prefix)?;
                Some((entry, length))
            })
            .max_by_key(|(_, length)| *length)
            .map(|(entry, _)| {
                let fresh = now.saturating_sub(entry.fetched_at) < CACHE_TTL_SECS;
                (entry.owner.clone(), fresh)
            })
    }

    pub fn insert(&mut self, owner: NetworkOwner, now: u64) {
        self.entries
            .retain(|entry| entry.owner.prefix != owner.prefix);
        self.entries.push(CacheEntry {
            owner,
            fetched_at: now,
        });
        // The file is a cache, not a database. Keep it small enough to read
        // synchronously at dialog startup.
        const MAX_ENTRIES: usize = 256;
        if self.entries.len() > MAX_ENTRIES {
            let excess = self.entries.len() - MAX_ENTRIES;
            self.entries.drain(0..excess);
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create cache dir: {e}"))?;
        }
        let file = CacheFile {
            version: CACHE_FORMAT_VERSION,
            entries: self.entries.clone(),
        };
        let bytes = serde_json::to_vec(&file).map_err(|e| format!("serialize RDAP cache: {e}"))?;
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&tmp, bytes).map_err(|e| format!("write RDAP cache: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("replace RDAP cache: {e}")
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// HTTPS
// ---------------------------------------------------------------------------

fn fetch_rdap(ip: &str, timeout: Duration) -> Result<String, String> {
    let mut url = format!("https://rdap.org/ip/{ip}");
    for _ in 0..MAX_REDIRECTS {
        let response = https_get(&url, timeout)?;
        match response.status {
            200..=299 => return Ok(response.body),
            300..=399 => {
                let location = response
                    .location
                    .ok_or_else(|| format!("RDAP redirect without Location from {url}"))?;
                url = resolve_location(&url, &location)?;
            }
            status => return Err(format!("RDAP returned HTTP {status}")),
        }
    }
    Err("RDAP redirected too many times".to_string())
}

struct HttpResponse {
    status: u16,
    location: Option<String>,
    body: String,
}

fn https_get(url: &str, timeout: Duration) -> Result<HttpResponse, String> {
    let target = Url::parse(url)?;
    let config = tls_config()?;

    let mut last_error = None;
    let mut stream = None;
    for addr in (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {e}", target.host))?
    {
        match connect(addr, timeout) {
            Ok(sock) => {
                stream = Some(sock);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let stream = stream.ok_or_else(|| {
        format!(
            "connect {}:{}: {}",
            target.host,
            target.port,
            last_error.unwrap_or_else(|| "no address".to_string())
        )
    })?;

    let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
        .map_err(|e| format!("TLS server name: {e}"))?;
    let connection = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| format!("TLS setup: {e}"))?;
    let mut tls = rustls::StreamOwned::new(connection, stream);

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/rdap+json\r\nUser-Agent: netkeep/0.1\r\nConnection: close\r\n\r\n",
        target.path, target.host_header()
    );
    tls.write_all(request.as_bytes())
        .map_err(|e| format!("send RDAP request: {e}"))?;
    tls.flush()
        .map_err(|e| format!("flush RDAP request: {e}"))?;

    let mut raw = Vec::new();
    tls.read_to_end(&mut raw)
        .map_err(|e| format!("read RDAP response: {e}"))?;
    parse_http_response(&raw)
}

fn connect(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, String> {
    let stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("set write timeout: {e}"))?;
    Ok(stream)
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let native = rustls_native_certs::load_native_certs();
            if native.certs.is_empty() {
                return Err("no system root certificates available".to_string());
            }
            let mut roots = rustls::RootCertStore::empty();
            for cert in native.certs {
                let _ = roots.add(cert);
            }
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Ok(Arc::new(config))
        })
        .clone()
}

#[derive(Debug)]
struct Url {
    host: String,
    port: u16,
    path: String,
}

impl Url {
    fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| format!("only https URLs are followed: {url}"))?;
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(format!("URL has no host: {url}"));
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (host, tail) = v6
                .split_once(']')
                .ok_or_else(|| format!("unterminated IPv6 host: {url}"))?;
            let port = tail
                .strip_prefix(':')
                .map(|p| p.parse::<u16>())
                .transpose()
                .map_err(|e| format!("bad port in {url}: {e}"))?
                .unwrap_or(443);
            (host.to_string(), port)
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if host.contains(':') {
                (authority.to_string(), 443)
            } else {
                (
                    host.to_string(),
                    port.parse::<u16>()
                        .map_err(|e| format!("bad port in {url}: {e}"))?,
                )
            }
        } else {
            (authority.to_string(), 443)
        };
        Ok(Self {
            host,
            port,
            path: path.to_string(),
        })
    }

    fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn resolve_location(current: &str, location: &str) -> Result<String, String> {
    if location.starts_with("https://") {
        return Ok(location.to_string());
    }
    let current = Url::parse(current)?;
    if location.starts_with("//") {
        return Ok(format!("https:{location}"));
    }
    if location.starts_with('/') {
        return Ok(format!("https://{}{location}", current.host_header()));
    }
    let dir = current
        .path
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .unwrap_or("");
    Ok(format!(
        "https://{}{}/{location}",
        current.host_header(),
        dir.trim_start_matches('/')
    ))
}

fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response: no header terminator".to_string())?;
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|_| "malformed HTTP response: headers are not UTF-8".to_string())?;
    let body = &raw[split + 4..];

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "malformed HTTP response: no status line".to_string())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "malformed HTTP status line".to_string())?
        .parse::<u16>()
        .map_err(|_| "malformed HTTP status code".to_string())?;

    let mut location = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("location") {
            location = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    let body = String::from_utf8_lossy(&body).into_owned();
    Ok(HttpResponse {
        status,
        location,
        body,
    })
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = data.windows(2).position(|window| window == b"\r\n") else {
            return Err("truncated chunked response".to_string());
        };
        let size_text = std::str::from_utf8(&data[..line_end])
            .map_err(|_| "chunk size is not ASCII".to_string())?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| format!("bad chunk size: {size_text}"))?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size {
            return Err("truncated chunk body".to_string());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github_response() -> &'static str {
        r#"{
            "objectClassName": "ip network",
            "handle": "NET-140-82-112-0-1",
            "startAddress": "140.82.112.0",
            "endAddress": "140.82.127.255",
            "ipVersion": "v4",
            "name": "GITHUB",
            "type": "DIRECT ALLOCATION",
            "status": ["active"],
            "entities": [
                {
                    "handle": "GITHUB",
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "GitHub, Inc."]
                    ]]
                }
            ],
            "cidr0_cidrs": [{"v4prefix": "140.82.112.0", "length": 20}],
            "arin_originas0_originautnums": [36459]
        }"#
    }

    #[test]
    fn parses_prefix_organisation_and_asn() {
        let ip: Ipv4Addr = "140.82.121.4".parse().unwrap();
        let owner = parse_rdap_response(ip, github_response()).unwrap();
        assert_eq!(owner.prefix, "140.82.112.0/20");
        assert_eq!(owner.name, "GITHUB");
        assert_eq!(owner.org, "GitHub, Inc.");
        assert_eq!(owner.asn, Some(36459));
        assert_eq!(owner.display(), "GitHub, Inc. · 140.82.112.0/20 · AS36459");
    }

    #[test]
    fn falls_back_to_the_range_when_cidr0_is_absent() {
        let ip: Ipv4Addr = "140.82.121.4".parse().unwrap();
        let body = r#"{
            "startAddress": "140.82.112.0",
            "endAddress": "140.82.127.255",
            "name": "GITHUB"
        }"#;
        let owner = parse_rdap_response(ip, body).unwrap();
        assert_eq!(owner.prefix, "140.82.112.0/20");
        assert_eq!(owner.org, "GITHUB");
        assert_eq!(owner.asn, None);
    }

    #[test]
    fn ignores_a_cidr0_block_that_does_not_cover_the_address() {
        let ip: Ipv4Addr = "140.82.121.4".parse().unwrap();
        let body = r#"{
            "startAddress": "140.82.112.0",
            "endAddress": "140.82.127.255",
            "cidr0_cidrs": [{"v4prefix": "10.0.0.0", "length": 8}],
            "name": "GITHUB"
        }"#;
        let owner = parse_rdap_response(ip, body).unwrap();
        assert_eq!(owner.prefix, "140.82.112.0/20");
    }

    #[test]
    fn prefix_from_range_uses_the_minimal_covering_block() {
        let start: Ipv4Addr = "140.82.112.0".parse().unwrap();
        let end: Ipv4Addr = "140.82.127.255".parse().unwrap();
        assert_eq!(prefix_from_range(start, end).unwrap(), "140.82.112.0/20");
        let single: Ipv4Addr = "140.82.121.4".parse().unwrap();
        assert_eq!(
            prefix_from_range(single, single).unwrap(),
            "140.82.121.4/32"
        );
    }

    #[test]
    fn prefix_covers_only_its_block() {
        let inside: Ipv4Addr = "140.82.127.255".parse().unwrap();
        let outside: Ipv4Addr = "140.82.128.1".parse().unwrap();
        assert!(prefix_covers("140.82.112.0/20", inside));
        assert!(!prefix_covers("140.82.112.0/20", outside));
        assert!(!prefix_covers("not-a-prefix", inside));
    }

    #[test]
    fn cache_serves_the_longest_matching_prefix_and_marks_staleness() {
        let mut cache = Cache::default();
        let wide = NetworkOwner {
            prefix: "140.82.0.0/16".into(),
            name: "WIDE".into(),
            org: "Wide".into(),
            asn: None,
        };
        let narrow = NetworkOwner {
            prefix: "140.82.112.0/20".into(),
            name: "NARROW".into(),
            org: "Narrow".into(),
            asn: Some(1),
        };
        cache.insert(wide, 1_000);
        cache.insert(narrow, 2_000);
        let ip: Ipv4Addr = "140.82.121.4".parse().unwrap();

        let (owner, fresh) = cache.lookup(ip, 2_000 + CACHE_TTL_SECS - 1).unwrap();
        assert_eq!(owner.name, "NARROW");
        assert!(fresh);

        let (owner, fresh) = cache.lookup(ip, 2_000 + CACHE_TTL_SECS).unwrap();
        assert_eq!(owner.name, "NARROW");
        assert!(!fresh);
    }

    #[test]
    fn inserting_a_prefix_replaces_its_old_entry() {
        let mut cache = Cache::default();
        let first = NetworkOwner {
            prefix: "140.82.112.0/20".into(),
            name: "OLD".into(),
            org: "Old".into(),
            asn: None,
        };
        let second = NetworkOwner {
            name: "NEW".into(),
            org: "New".into(),
            ..first.clone()
        };
        cache.insert(first, 1);
        cache.insert(second, 2);
        assert_eq!(cache.entries.len(), 1);
        let ip: Ipv4Addr = "140.82.121.4".parse().unwrap();
        assert_eq!(cache.lookup(ip, 2).unwrap().0.name, "NEW");
    }

    #[test]
    fn parses_a_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let response = parse_http_response(raw).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "hello world");
    }

    #[test]
    fn parses_a_redirect_location() {
        let raw = b"HTTP/1.1 302 Found\r\nLocation: https://rdap.arin.net/registry/ip/140.82.121.4\r\nContent-Length: 0\r\n\r\n";
        let response = parse_http_response(raw).unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(
            response.location.as_deref(),
            Some("https://rdap.arin.net/registry/ip/140.82.121.4")
        );
    }

    fn temp_cache(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("netkeep-rdap-{}-{name}", std::process::id()))
            .join("rdap.json")
    }

    fn owner() -> NetworkOwner {
        NetworkOwner {
            prefix: "140.82.112.0/20".into(),
            name: "GITHUB".into(),
            org: "GitHub, Inc.".into(),
            asn: Some(36459),
        }
    }

    #[test]
    fn a_fresh_cache_entry_never_calls_the_registry() {
        let path = temp_cache("fresh");
        let now = 1_000_000u64;
        let mut cache = Cache::default();
        cache.insert(owner(), now);
        cache.save(&path).unwrap();

        let ip: Ipv4Addr = "140.82.121.4".parse().unwrap();
        let found = lookup_owner_with(ip, now + 60, &path, |_| {
            panic!("a fresh entry must not trigger a request")
        })
        .unwrap();
        assert_eq!(found, owner());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_stale_entry_is_returned_when_the_refresh_fails() {
        let path = temp_cache("stale");
        let now = 1_000_000u64;
        let mut cache = Cache::default();
        cache.insert(owner(), now);
        cache.save(&path).unwrap();

        let ip: Ipv4Addr = "140.82.121.4".parse().unwrap();
        let found = lookup_owner_with(ip, now + CACHE_TTL_SECS, &path, |_| {
            Err("registry is down".to_string())
        })
        .unwrap();
        assert_eq!(found, owner());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_successful_refresh_replaces_the_stale_entry() {
        let path = temp_cache("refresh");
        let now = 1_000_000u64;
        let mut cache = Cache::default();
        let mut stale = owner();
        stale.name = "OLD".into();
        cache.insert(stale, now);
        cache.save(&path).unwrap();

        let ip: Ipv4Addr = "140.82.121.4".parse().unwrap();
        let found = lookup_owner_with(ip, now + CACHE_TTL_SECS, &path, |_| {
            Ok(github_response().to_string())
        })
        .unwrap();
        assert_eq!(found.name, "GITHUB");

        let cached = Cache::load(&path);
        assert_eq!(
            cached.lookup(ip, now + CACHE_TTL_SECS).unwrap().0.name,
            "GITHUB"
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_unknown_address_without_cache_stays_empty() {
        let path = temp_cache("miss");
        let ip: Ipv4Addr = "203.0.113.9".parse().unwrap();
        assert!(lookup_owner_with(ip, 10, &path, |_| { Err("offline".to_string()) }).is_none());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn resolves_relative_redirects_against_the_current_host() {
        assert_eq!(
            resolve_location("https://rdap.org/ip/1.2.3.4", "/registry/ip/1.2.3.4").unwrap(),
            "https://rdap.org/registry/ip/1.2.3.4"
        );
        assert_eq!(
            resolve_location("https://rdap.org/ip/1.2.3.4", "https://rdap.arin.net/x").unwrap(),
            "https://rdap.arin.net/x"
        );
    }
}
