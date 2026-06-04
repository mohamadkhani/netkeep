# DNS Forwarder Architecture

Read this before modifying any DNS-related code.

## Problem

When an app resolves a domain, the system DNS resolver is used — regardless of any routing rule that says the domain should go through a specific egress (proxy, tun, or device). The app therefore gets an IP that was resolved through the wrong path, and any subsequent TCP connection to that IP may fail or go through the wrong interface.

The correct behaviour is: **DNS for a domain must be resolved through the same egress target that the matching rule assigns to it.** If a rule says `youtube.com → proxy`, then the DNS query for `youtube.com` must be forwarded through that proxy's DNS servers.

## Solution Overview

A DNS forwarder on `127.0.0.1:53` intercepts all DNS queries from the system, identifies the source process via eBPF, matches the `(process, domain)` pair against the rule engine, and resolves through the egress's configured DNS servers.

If no rule matches, the query is forwarded to the system default DNS.

## Components

### 1. eBPF DNS Tracker

**Crates:** `crates/dns-tracker-ebpf/` (BPF bytecode) + `crates/dns-tracker/` (userspace)

**How it works:**

A kprobe on `udp_sendmsg` fires every time any process sends a UDP packet. The BPF program filters for `dport == 53` and captures:

- `pid` — via `bpf_get_current_pid_tgid()`
- `comm` — process name (16 bytes) via `bpf_get_current_comm()`
- `domain` — QNAME parsed from the DNS query payload

This is written into a BPF HashMap keyed by `(src_ip, src_port)`.

**Important:** The BPF program reads `skc_rcv_saddr` (the socket's **bound** address) as `src_ip`. For auto-bound UDP sockets, this is `0.0.0.0` — not the actual packet source IP. The userspace `lookup()` handles this by trying the specific IP first, then falling back to `0.0.0.0` (INADDR_ANY).

The userspace loader (`DnsTracker`) attaches the kprobe via `aya`, and exposes:

```rust
fn lookup(&self, src_ip: Ipv4Addr, src_port: u16) -> Option<DnsQueryInfo>
// DnsQueryInfo { pid: u32, comm: String, domain: String }
```

**Lookup strategy:** Tries `(src_ip, src_port)` first. If not found, retries with `(0.0.0.0, src_port)` to match auto-bound sockets.

**Fallback:** If the eBPF map entry has been evicted (rare), the forwarder falls back to `ProcProcessResolver` (SOCK_DIAG + `/proc` scan). The app's UDP socket is still open while blocked on `getaddrinfo()`, so SOCK_DIAG succeeds.

**Process name notes:** `bpf_get_current_comm()` gives the same 15-char kernel `task_comm_name` that `/proc/<pid>/comm` exposes. Shell wrappers, electron apps, etc. have the same name fixup requirements as the existing NFQUEUE path. The domain is parsed from the raw DNS wire format at probe time.

### 2. DNS Forwarder

**Crate:** `crates/dns-tracker/src/forwarder.rs` (part of the userspace dns-tracker crate)

**Per-query flow:**

```
1. recvfrom() — receive DNS query, note src_ip:src_port
2. eBPF lookup → (process_name, domain)
3. Rule match — (process, domain) against ControlService → egress
4. Resolve through egress's DNS servers:
     - Proxy   → SOCKS5 CONNECT to dns_server:53, send raw query, relay response
     - Tun     → UDP socket with SO_MARK, hickory-resolver to egress DNS servers
     - Device  → UDP socket with SO_BINDTODEVICE, hickory-resolver to egress DNS servers
5. No match  → forward raw query to system default DNS (read from /etc/resolv.conf before we overwrite it)
6. sendto()  → response back to app
7. Populate SniDnsCache: ip → domain (helps transparent proxy use hostnames for SOCKS CONNECT)
```

### 3. Daemon Integration

The daemon (`apps/daemon/src/main.rs`) starts both components at boot:

1. Load and attach eBPF kprobe → `DnsTracker`
2. Record original system DNS from `/etc/resolv.conf` (fallback upstream)
3. Bind `DnsForwarder` on `127.0.0.1:53`
4. Spawn both in background threads
5. Optionally rewrite `/etc/resolv.conf` to `nameserver 127.0.0.1` (or instruct user to do this)

## Build Infrastructure

The BPF crate **must** compile separately with nightly + `bpfel-unknown-none` target:

```bash
# One-time developer setup
rustup toolchain install nightly --component rust-src
rustup target add bpfel-unknown-none --toolchain nightly
cargo install bpf-linker

# Build order
cargo xtask build-ebpf    # compiles dns-tracker-ebpf → ELF object
cargo build --workspace    # compiles everything else; dns-tracker includes the object via include_bytes!
```

New workspace members:
- `crates/dns-tracker-ebpf/` — BPF bytecode; `#![no_std]`, nightly, `aya-ebpf` crate
- `crates/dns-tracker/` — userspace: eBPF loader + DNS forwarder + DNS-over-SOCKS5 resolver
- `xtask/` — build script (`cargo xtask build-ebpf`)

## Rule Matching for DNS

DNS rule matching uses the same `policy_engine::resolve_action` function used by NFQUEUE:

| Rule | DNS query | Result |
|---|---|---|
| `process=brave, domain=*.foo.com → Route → Proxy` | brave sends query for `sub.foo.com` | Resolve via proxy DNS |
| `process=brave, domain=None → Route → Proxy` | brave sends any query | Resolve via proxy DNS |
| `process=None, domain=*.foo.com → Route → Tun` | any process queries `sub.foo.com` | Resolve via tun DNS |
| No matching rule | anything | Forward to system DNS |

Process-only rules (no domain filter) match all DNS queries from that process. Domain-only rules match regardless of process. Both/neither follow the same specificity rules as NFQUEUE.

## DNS-over-SOCKS5

For proxy egresses, DNS resolution tunnels through SOCKS5:

```
SOCKS5 CONNECT to <egress_dns_server>:53
→ send raw DNS query bytes
→ read raw DNS response bytes
→ close tunnel
→ return response to app
```

This uses the existing `proxy_client::connect_via_proxy()`. The DNS server IP itself (e.g. `8.8.8.8`) is sent to the SOCKS5 proxy as a destination, so the proxy resolves the DNS query on the far side using its own network path.

## Relation to Transparent Proxy

The DNS forwarder and the transparent proxy complement each other:

- DNS forwarder: app gets a **real IP** from the correct egress DNS → NFQUEUE routes TCP to transparent proxy using hostname from SniDnsCache
- Transparent proxy: when DNS forwarder was used, `SniDnsCache` already has `ip → domain` → SOCKS5 CONNECT uses the domain name, not the IP

## UDP Retry Behavior

`forward_udp()` retries DNS queries on timeout (EAGAIN / WouldBlock):

- **Per-attempt timeout:** 3 seconds
- **Max retries:** 2 (3 total attempts: initial + 2 retries)
- **Total max wait:** ~9 seconds
- **Behavior:** On timeout, the query is resent to the upstream DNS server. On any other error (network unreachable, etc.), it fails immediately without retrying.
- **Logging:** Each retry logs `dns-forwarder: retry N/2 to <upstream>`.

This is standard DNS client behavior — UDP is unreliable, and resending is the correct recovery strategy.

## Notes for Future Work

- TCP DNS (length-prefixed) for DNS-over-TCP clients
- Response caching in the forwarder to reduce upstream round-trips
- GPUI settings to configure DNS servers per egress (currently DB-only)
- Auto-configure `/etc/resolv.conf` or NetworkManager on start
- IPv6 DNS forwarder: add debug log for dropped queries (eBPF probe filters `AF_INET` only)
- eBPF BTF: runtime validation of hardcoded `struct sock_common` offsets
- EDNS0: bump `DNS_BUF` from 512 to 4096 bytes
- Socket pooling in `forward_udp()` to reduce per-query syscall overhead
