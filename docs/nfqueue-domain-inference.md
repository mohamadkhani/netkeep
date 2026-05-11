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

**Remaining gaps** (DNS snoop cache, not yet implemented):
- Plain UDP flows to non-HTTPS services
- QUIC/HTTP3 where SNI is encrypted in the packet payload
- Non-TLS TCP services

For these, a DNS snoop cache would be needed — intercept UDP packets where `src_port == 53`, parse the DNS response wire format (A/AAAA answers), and populate the same `SniDnsCache`. The race condition (DNS response racing with the first UDP packet) is less critical for UDP since UDP has no handshake and the first packet is already application data.

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
