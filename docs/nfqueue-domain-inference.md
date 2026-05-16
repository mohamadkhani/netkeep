# Domain Inference in NFQUEUE-Based Packet Interception

This document captures the design decisions and gotchas encountered while implementing destination domain detection for NFQUEUE-intercepted flows.

## The Problem

When a packet arrives at the NFQUEUE, you have IP addresses and ports — not domain names. For a meaningful user-facing decision dialog ("Allow curl → api.example.com?"), you need to reverse-map the destination IP to a domain. Three approaches exist; understanding why two of them fail in this context is important.

## Why Reverse DNS Doesn't Work

`nslookup 1.2.3.4` is slow (network round-trip), unreliable (PTR records are rarely set correctly), and adds latency directly to the packet verdict path. Rule out immediately.

## Why a DNS Snoop Cache Alone Doesn't Work

The intuition: intercept DNS responses passing through NFQUEUE, parse A/AAAA answers, store `ip → domain`. Later, when a flow to that IP arrives, look it up.

The problem: **race condition**. The NFQUEUE decision is made on the first packet of a TCP connection — the SYN. That SYN arrives at nearly the same time as the DNS response. In practice, the DNS response may not yet be processed when the SYN is classified. The first connection gets `(unknown)`.

Additional blind spots:
- DNS over HTTPS (DoH): DNS traffic goes to `1.1.1.1:443` as encrypted HTTPS. NFQUEUE never sees the plaintext query/response.
- Apps that hardcode IPs: no DNS at all, no cache entry.
- Short-lived entries: cache needs TTL management or it grows unbounded.

The DNS snoop cache is still useful as a **fallback** for UDP/QUIC flows, but it cannot be the primary strategy for TCP.

## The Right Answer: TLS SNI from ClientHello

For TCP/HTTPS (the dominant case), the TLS ClientHello contains the **Server Name Indication (SNI)** extension — the hostname the client intends to connect to, in plaintext, regardless of whether DNS was used. It is always present in the first data packet of a TLS connection.

**Key property:** SNI is in the *application data* of the first TCP segment after the handshake, not in the SYN. This matters.

## The Timing Trap

Even with SNI extraction implemented, the domain shows as `(unknown)` if you classify on the **SYN packet**.

TCP connection setup:
```
Client → SYN          (no payload, no SNI)
Server → SYN-ACK      (no payload)
Client → ACK          (no payload)
Client → ClientHello  (has payload, has SNI)  ← this is what you want
```

If NFQUEUE intercepts the SYN and makes the verdict decision immediately:
- `tcp_payload.is_empty()` → true → SNI extraction returns `None` → domain is `(unknown)`
- The SYN is **dropped** (pending decision) → server never sends SYN-ACK → ClientHello never arrives → SNI never available

**Fix:** Accept TCP packets with empty payload without classifying them. Let the TCP handshake complete. The first packet with application data (the ClientHello) is the one to classify — at that point SNI is present and domain resolution works.

```rust
if is_loopback(&raw.dst_ip) || raw.tcp_payload_empty {
    Verdict::Accept
} else {
    // classify and decide
}
```

This is safe: accepting SYN/ACK/FIN control packets before a rule decision does not permit any application data through. The client cannot send data until the handshake completes, and the first data packet still goes through NFQUEUE classification.

## TLS ClientHello Wire Format

For implementors who need to parse SNI without a library:

```
TLS Record:
  [0]     content type:  0x16 (handshake)
  [1..2]  legacy version: 0x03 0x01 (TLS 1.0 compat) or 0x03 0x03
  [3..4]  record length (u16 big-endian)

Handshake header (starts at byte 5):
  [5]     handshake type: 0x01 (ClientHello)
  [6..8]  handshake length (u24 big-endian)

ClientHello body (starts at byte 9):
  [9..10]   client_version
  [11..42]  random (32 bytes)
  [43]      session_id length
  [44..]    session_id bytes

After session_id:
  cipher_suites_len (u16) + cipher_suites bytes
  compression_methods_len (u8) + compression_methods bytes
  extensions_len (u16)
  extensions...

Each extension:
  type (u16) + length (u16) + data bytes

SNI extension (type 0x0000):
  server_name_list_length (u16)
  name_type (u8): 0x00 = host_name
  name_length (u16)
  name (UTF-8 bytes)
```

Minimum sanity checks before parsing:
1. `payload.len() >= 43`
2. `payload[0] == 0x16` (handshake record)
3. `payload[1] == 0x03` (TLS major version)
4. `payload[5] == 0x01` (ClientHello)

All length fields must be bounds-checked before indexing. Use `payload.get(pos)?` rather than `payload[pos]` to safely return `None` on truncated packets.

## Domain Resolution Priority

`FlowClassifier::resolve_domain()` applies this priority order:

| Protocol | Priority |
|---|---|
| TCP | SNI > DNS cache (if same) > IP-only (if conflict) |
| QUIC | DNS cache only (SNI encrypted in QUIC v1) |
| UDP | DNS cache only |

When DNS and SNI disagree (possible spoofing or CDN routing), the domain is discarded and only the IP is shown. This is intentional — see design decision #3 in `architecture.md`.

## SNI Cache — Persisting the Domain Across Packets

**Problem:** SNI is only present in the TLS ClientHello — the very first data packet. Every subsequent encrypted packet in the same TLS session carries no SNI. Without caching, those packets classify with `destination_domain = None`, which fails to match domain-based rules and re-triggers pending decisions for the same connection.

**Solution:** `SniDnsCache` in `crates/flow-classifier/src/lib.rs`.

```rust
// In NfqueueProcessor::run_loop — before classify():
if let Some(sni) = &raw.sni_hint {
    self.dns_cache.insert(&raw.dst_ip, sni);
}
let flow = self.classifier.classify(&raw);
```

The cache stores `dst_ip → domain`. `FlowClassifier` uses it as its `DnsResolver` — so packets after the ClientHello call `dns_cache.resolve_dns(dst_ip)` and get the domain back, making the rule match on every subsequent packet.

**Thread safety:** `SniDnsCache` wraps `Arc<Mutex<HashMap<String, String>>>`. The daemon creates one instance and `.clone()`s it (cheap — just clones the `Arc`) into both the classifier (reader) and the processor (writer).

**Plaintext HTTP Host header fallback** (implemented 2026-05-13):

For plain HTTP/1.x traffic — `curl example.com`, captive-portal pages, package mirrors, old internal apps — there's no TLS ClientHello to read SNI from, and DNS is bypassed in nftables (`udp dport 53 accept`), so the daemon never sees the resolver response. Without a fallback, every HTTP flow shows IP-only in the decision dialog.

`extract_http_host` in `crates/enforcer/src/nfqueue.rs` parses the HTTP/1.x `Host:` header from plaintext TCP payloads and feeds the result into the same `sni_hint → SniDnsCache` pipeline:

```rust
let domain_hint = extract_tls_sni(payload).or_else(|| extract_http_host(payload));
```

The parser:
1. Early-rejects payloads that don't start with a known HTTP method (`GET `, `POST `, …) so we don't substring-search arbitrary binary TCP traffic.
2. Scans the first 4 KiB only — bounded cost, well above realistic HTTP request header sizes.
3. Searches for `\r\nhost:` case-insensitively (skipping the request line so an absolute-form URL like `GET http://example.com/ HTTP/1.1` doesn't shadow the actual `Host:` header).
4. Strips an optional `:port` suffix and bracketed IPv6 literals (`[2001:db8::1]:8443` → `2001:db8::1`).
5. Validates the result against a conservative hostname character set (alphanumeric + `.` `-` `:` `[` `]`) so coincidental `\r\nHost:` byte sequences in non-HTTP traffic don't generate false-positive domains.
6. Returns the lowercased host so wildcard rules match consistently.

Once `extract_http_host` populates `sni_hint`, the `SniDnsCache` records `dst_ip → host` and every subsequent connection to the same IP — HTTP or HTTPS — also resolves to a domain. The TLS SNI path still wins when present (TLS is more authoritative); HTTP is the fallback.

12 unit tests in `nfqueue::tests::http_host_*` cover the happy path, case-insensitivity, port stripping (both IPv4 and bracketed IPv6), CONNECT-method proxies, multi-header ordering, truncation safety, garbage rejection, and explicit no-match against TLS ClientHello / non-HTTP payloads.

**DNS snoop cache — third domain detection method (implemented 2026-05-16):**

For plain UDP services, QUIC/HTTP3 (encrypted SNI), and non-HTTP/non-TLS TCP, neither of the above methods produces a domain name. The solution is a passive DNS response snooper:

`crates/enforcer/src/dns_snoop.rs` — `DnsSnoopWorker` binds to a second NFQUEUE (queue number `= main_queue + 1`) on the **INPUT hook** with the `bypass` flag:

```
add chain inet logiguard input_dns { type filter hook input priority 0; policy accept; }
add rule inet logiguard input_dns udp sport 53 queue num {n+1} bypass
```

`bypass` means: if the worker is not running (daemon restarting, queue overflow), DNS responses pass through unaffected — no latency impact and no DNS failure risk.

The worker:
1. Receives raw IP + UDP + DNS response packets from the INPUT hook.
2. Parses the DNS wire format (`parse_dns_packet`): reads QNAME from the question section as the queried domain, then extracts A (type 1) and AAAA (type 28) RDATA as resolved IPs.
3. Writes `resolved_ip → queried_domain` into the shared `SniDnsCache`.
4. Always returns `Verdict::Accept` — it never blocks DNS traffic.

**Why QNAME, not the answer NAME field:** Using the question section's QNAME is correct even for CNAME chains. If an app queries `api.cursor.sh` which CNAMEs to `cursor-api.cloudfront.net` then resolves to `1.2.3.4`, we correctly store `1.2.3.4 → api.cursor.sh` because that is the domain the user-facing rule will name.

**Race condition for UDP:** DNS responses arrive just before the first UDP data packet. For interactive apps the DNS response typically precedes the data packet by at least one round-trip, so the cache is populated in time. For very fast back-to-back query+connect scenarios the first UDP packet still shows IP-only; subsequent connections to the same IP (which are common) resolve correctly.

8 unit tests in `dns_snoop::tests` cover A and AAAA records, query/response discrimination, NXDOMAIN, truncated input, zero-answer responses, domain lowercasing, and multiple round-robin A records.

## Testing Strategy

SNI extraction is pure byte parsing with no I/O — test it directly:

```rust
fn build_tls_client_hello(sni: &str) -> Vec<u8> { ... }

#[test]
fn sni_extracted_from_tls_client_hello() {
    let hello = build_tls_client_hello("example.com");
    assert_eq!(extract_tls_sni(&hello), Some("example.com".to_string()));
}
```

Build a minimal but structurally valid ClientHello manually. Do not use a TLS library for the test fixture — that would test the library, not your parser.

For the `tcp_payload_empty` path, test at the `parse_raw_packet` level using `etherparse::PacketBuilder` to construct real IP+TCP frames:

```rust
// TCP with no payload → tcp_payload_empty = true
PacketBuilder::ipv4(...).tcp(...).write(&mut buf, b"").unwrap();

// TCP with TLS payload → sni_hint populated, tcp_payload_empty = false
PacketBuilder::ipv4(...).tcp(...).write(&mut buf, &client_hello).unwrap();
```
