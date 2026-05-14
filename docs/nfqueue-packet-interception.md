# Packet Interception with NFQUEUE

This document explains how NFQUEUE works, how LogiGuard uses it, the full path a packet travels from kernel to userspace verdict, and why this approach is Linux-only.

---

## What Is NFQUEUE?

NFQUEUE (Netfilter Queue) is a Linux kernel mechanism that lets a userspace process make accept/drop decisions on individual network packets. Instead of the kernel applying a static firewall rule, it puts a packet in a queue, blocks until userspace replies with a verdict, then enforces that verdict.

It is part of the **Netfilter** subsystem — the same framework that powers `iptables` and `nftables`.

---

## The Packet Path

```
Application (e.g. curl)
  │
  │  write() / connect()
  ▼
Kernel TCP/IP stack
  │
  │  packet assembled, ready to send
  ▼
nftables OUTPUT hook  (hook priority -150)
  │
  ├─ loopback? → accept immediately
  ├─ relay socket (fwmark ≥ base)? → accept, restore routing mark
  └─ everything else → QUEUE to NFQUEUE num N
         │
         │  kernel holds packet in queue
         │  blocks application retransmission
         ▼
  logiguard-daemon (userspace)
    │  recv() from /dev/nfnetlink_queue
    │  parse IP packet bytes
    │  FIN or RST flag? → evict 5-tuple verdict cache, Accept
    │  empty TCP payload (SYN, pure ACK)? → return cached verdict or Accept
    │  SNI present? → populate SniDnsCache (ip → domain)
    │  5-tuple in verdict cache? → return cached verdict
    │  classify flow (SniDnsCache lookup, process, IP)
    │  query decision engine (rule match / pending)
    │  definitive verdict (Allow/Deny)? → insert into 5-tuple verdict cache
    ▼
  verdict: Accept or Drop
         │
         ▼
  kernel receives verdict via netlink socket
    ├─ Accept → packet continues to NIC driver → wire
    └─ Drop   → packet discarded; application retransmits after user decides
```

---

## nftables Setup

LogiGuard programs nftables on startup via `nft` (shelled out). The rules use the `inet` family to cover both IPv4 and IPv6 in one table.

### Chains and priorities

| Chain | Type | Hook | Priority | Purpose |
|---|---|---|---|---|
| `output_nat` | nat | output | -199 | Save relay fwmark to conntrack; set throne bypass mark |
| `output_early` | filter | output | -150 | Restore relay mark; queue everything else |
| `forward` | filter | forward | 0 | Queue forwarded packets (gateway mode) |
| `output_late` | filter | output | +10 | (reserved for future post-proxy mark restore) |

### Key rules (simplified)

```nftables
table inet logiguard {

  # Save our routing mark into conntrack before proxy tools overwrite it.
  # Only for traffic going to physical NICs (not through throne-tun).
  chain output_nat {
    type nat hook output priority -199; policy accept;
    meta mark >= 20000 oifname != "throne-tun" ct mark set meta mark  \
        meta mark set 0x2024 return
  }

  chain output_early {
    type filter hook output priority -150; policy accept;

    # Relay sockets: restore routing mark from conntrack, skip NFQUEUE.
    ct mark >= 20000 meta mark set ct mark accept

    # Loopback bypass (defense-in-depth).
    oifname "lo" accept
    ip daddr 127.0.0.0/8 accept
    ip6 daddr ::1 accept
    ip6 daddr ::ffff:7f00:0000/104 accept

    # DNS must bypass NFQUEUE — queuing it would block name resolution.
    udp dport 53 accept
    tcp dport 53 accept

    # All other output goes to NFQUEUE. The userspace daemon maintains a
    # per-5-tuple verdict cache so that already-decided connections are
    # fast-pathed in Rust rather than being re-classified every packet.
    queue num 0
  }

  chain forward {
    type filter hook forward priority 0; policy accept;
    oifname "lo" accept
    queue num 0
  }
}
```

The `queue num N` statement puts the packet in NFQUEUE number N and **blocks** it until userspace replies. The kernel will not forward or transmit the packet until a verdict arrives.

---

## Userspace Side: the `nfq` Crate

LogiGuard uses the pure-Rust [`nfq`](https://crates.io/crates/nfq) crate (no libnetfilter_queue dependency).

```rust
let mut queue = Queue::open()?;
queue.bind(queue_num)?;

loop {
    let mut msg = queue.recv()?;      // blocks until a packet arrives
    let payload = msg.get_payload();  // raw IP-layer bytes
    // ... classify, decide ...
    msg.set_verdict(Verdict::Accept); // or Verdict::Drop
    queue.verdict(msg)?;              // send verdict back to kernel
}
```

`queue.recv()` parks the thread — no busy-waiting. One dedicated thread handles the queue. The loop is intentionally synchronous: one packet in, one verdict out, before the next packet is processed.

---

## What the Daemon Receives

NFQUEUE delivers the **IP layer** of the packet — no Ethernet header. For IPv4 the buffer starts with the IP header (`version=4`, IHL, total_length…). For IPv6 it starts with the IPv6 fixed header.

LogiGuard uses `etherparse::SlicedPacket::from_ip()` to parse the IP and transport headers from raw bytes. The `transport.payload()` field gives the TCP/UDP application data.

---

## Verdict Semantics

| Verdict | Kernel action | Effect |
|---|---|---|
| `Accept` | Forwards packet to next hook / NIC | Connection proceeds |
| `Drop` | Discards packet silently | Application sees timeout / retransmit |

There is no "reject with ICMP" option in NFQUEUE verdicts — only accept or drop. LogiGuard drops unknown flows; the application retransmits after the user makes a decision. When the user allows, subsequent packets match an allow rule and are accepted immediately.

---

## TCP Packet Handling in the Verdict Cache

Because the nftables rule sends **all** output packets to NFQUEUE (no `ct state new` filter), the userspace daemon receives SYNs, pure ACKs, data packets, FINs, and RSTs alike. Each kind is handled differently.

### FIN / RST — connection closing

```rust
if raw.tcp_fin || raw.tcp_rst {
    self.decided.remove(&key);  // evict 5-tuple cache
    return (Verdict::Accept, None);
}
```

FIN or RST signals the connection is ending. The cached verdict for this 5-tuple is evicted so a future connection that reuses the same port gets a fresh decision rather than inheriting the old one.

### SYN and pure ACKs — empty payload, no classification

```rust
if raw.tcp_payload_empty {
    // return cached verdict if present, else Accept without classifying
    if let Some(cached) = self.decided.get(&key) { ... }
    return (Verdict::Accept, None);
}
```

A SYN has no application payload — no SNI can be extracted and no domain hint is available. If the SYN were dropped the TCP handshake would never complete and the TLS ClientHello would never arrive. Pure ACKs (client acknowledging server data) are similarly content-free.

**Crucially**, pure ACKs do *not* evict the verdict cache — they consult it (returning the cached verdict for denied connections) or fall through to Accept. Evicting on ACK was an earlier bug: every client ACK for a server response would clear the cache and force full re-classification of the next request, re-running the `/proc` resolver and risking `process_name = None` when the fd scan raced a Electron network-service fork/exec. Fixing this (2026-05-15) eliminated the most common source of duplicate process attributions for multi-process apps.

### Data packets — classification + caching

The first data packet per connection (e.g. TLS ClientHello) misses the verdict cache, runs the full classification pipeline (SNI extraction → domain lookup → `/proc` resolver → decision engine), and, if the result is a definitive Allow or Deny, inserts into the cache. All subsequent data packets for the same 5-tuple hit the cache directly.

This is safe: accepting SYN/ACK does not let application data through; the client cannot send the ClientHello until the 3-way handshake succeeds.

---

## Routing Mark Coexistence

Logiguard uses `SO_MARK` on its own relay sockets to force them through specific routing tables (for VPN/device routing). These marks must survive other tools (e.g. throne, sing-box) that also use `SO_MARK` or `iptables -j MARK`.

The solution uses **conntrack marks** as stable per-connection storage:

1. `output_nat` (priority -199, runs first): saves LogiGuard's fwmark into `ct mark` before any proxy can overwrite it.
2. Proxy runs at priority 0, overwrites `meta mark`.
3. `output_early` (priority -150): reads `ct mark`, restores `meta mark`, accepts the packet so it is not re-queued.

The routing decision therefore sees LogiGuard's mark, not the proxy's. The `LOGIGUARD_ROUTE_MARK_BASE` env var (default 20000) sets the threshold — any mark ≥ this value belongs to LogiGuard.

---

## Is NFQUEUE Available on macOS or Windows?

**No.** NFQUEUE is Linux-only. It is part of the Linux Netfilter subsystem and does not exist on other platforms.

### macOS equivalent: Network Extension / PF

macOS provides the **Network Extension** framework (since macOS 10.15 Catalina) for packet filtering and flow inspection. Two relevant provider types:

- `NEFilterDataProvider` — inspect and allow/deny individual flows (DNS, TCP, UDP) at the application level. No raw packet access.
- `NEPacketTunnelProvider` — full TUN device; read and write raw IP packets. Used by VPNs.

There is no direct raw-packet intercept equivalent to NFQUEUE. The closest is `NEFilterDataProvider`, which works at the flow level — you get host/port/process, but not raw bytes. For raw bytes you need the TUN approach.

macOS also has **PF** (Packet Filter, ported from OpenBSD), accessible via `/dev/pf`. PF supports a `divert` socket for userspace packet processing, but it is low-level, undocumented for app use, and restricted by SIP.

macOS network extensions require:
- Apple Developer account
- Entitlements signed by Apple (`com.apple.developer.network-extension.filter-data`)
- Installation via MDM or System Preferences (no root-only daemon model)

### Windows equivalent: WFP / WinDivert

Windows provides the **Windows Filtering Platform (WFP)**, a kernel-mode framework for packet inspection and modification. Userspace access goes through the `FwpmFilter` API.

The most practical userspace option is **WinDivert** — an open-source driver that exposes a simple API for intercepting and re-injecting packets. It is the closest analog to NFQUEUE on Windows:

```c
HANDLE handle = WinDivertOpen("outbound and !loopback", WINDIVERT_LAYER_NETWORK, 0, 0);
WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr);
// ... inspect, modify ...
WinDivertSend(handle, packet, packet_len, &send_len, &addr);
```

WinDivert requires a signed kernel driver (or test-signing mode). In production, the driver must be code-signed with an EV certificate and submitted to Microsoft for WHQL attestation.

### Summary

| Feature | Linux (NFQUEUE) | macOS (NE) | Windows (WFP/WinDivert) |
|---|---|---|---|
| Raw packet access | Yes | TUN only | Yes (WinDivert) |
| Flow-level intercept | Yes | Yes (NEFilter) | Yes (WFP) |
| Kernel driver required | No (netlink socket) | No (framework) | Yes (WinDivert driver) |
| Root required | Yes | No (entitlement) | Yes (admin) |
| SNI extraction | Yes (raw TCP payload) | No (API provides host) | Yes (raw bytes) |
| Code signing required | No | Yes (Apple entitlement) | Yes (EV cert + WHQL) |
| Userspace Rust crate | `nfq` | None (Swift/ObjC API) | `windivert` (bindings exist) |

### Cross-platform strategy

A cross-platform firewall daemon would need:

- **Linux:** NFQUEUE via `nfq` crate + nftables
- **macOS:** `NEFilterDataProvider` for flow-level control (host/port/process, no raw bytes); or a TUN-based approach for raw packet access
- **Windows:** WinDivert for raw packets; or WFP callout driver for deep kernel integration

LogiGuard currently targets Linux only. Platform abstractions would live behind the `NftablesBootstrap`, `PacketSource`, and `VerdictSink` traits in the `enforcer` crate — the decision engine and policy layer are already platform-agnostic.
