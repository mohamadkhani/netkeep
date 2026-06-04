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
| `output_early` | **route** | output | -150 | Restore relay mark from ct; loopback/DNS/ICMP bypass; queue everything else to NFQUEUE |
| `output_save_mark` | filter | output | -125 | After NFQUEUE: copy `meta mark → ct mark`, then clear `meta mark` |
| `output_reroute` | **route** | output | -100 | Restore `meta mark` from `ct mark` *inside the chain*; the inside-chain change triggers `ip_route_me_harder()` |
| `forward` | filter | forward | 0 | Queue forwarded packets (gateway mode) |
| `input_dns` | filter | input | 0 | Queue DNS responses (queue N+1) for the SNI cache snoop |
| `postrouting` | nat | postrouting | 100 (srcnat) | Masquerade routed-mark traffic so source IP matches the actual egress interface |

### Why three OUTPUT chains for one routing decision

A naïve `type route` chain that *itself* hosts the NFQUEUE rule does not trigger a reroute when userspace stamps a verdict-mark. The kernel's `nf_route_table_hook4`:

```c
mark = skb->mark;                       // capture
ret  = nft_do_chain(&pkt, priv);
if (ret != NF_DROP && ret != NF_STOLEN &&
    (skb->mark != mark || ...))
    err = ip_route_me_harder(...);      // reroute check
```

runs the reroute check on the *return path* of `nft_do_chain`. When the chain returns `NF_QUEUE`, the function exits there. After `nf_reinject()` later resumes iteration with the userspace-applied mark, it resumes at the *next* hook entry — the route chain that queued the packet never gets a chance to compare pre- vs post-marks. Result: no reroute, packet exits whichever interface the original (unmarked) routing decision chose. Typically the VPN.

The three-chain dance works around this by putting the mark write **inside a later route chain's** `nft_do_chain`:

1. `output_early` (route, -150) queues the packet. NFQUEUE stamps `meta mark = X` via the verdict. Chain exits via reinject. No reroute (as described).
2. `output_save_mark` (filter, -125) sees `meta mark = X`, copies it into `ct mark`, then clears `meta mark` to 0. The chain is `filter` so no reroute check runs here.
3. `output_reroute` (route, -100) enters with `meta mark = 0`, fires `ct mark >= base meta mark set ct mark`, and exits with `meta mark = X`. The kernel's post-chain check sees `0 != X` and calls `ip_route_me_harder()` with the new mark. The route lookup now hits the fwmark policy rule and lands the packet on the right egress interface.

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
    type route hook output priority -150; policy accept;

    # Relay sockets: restore routing mark from conntrack, skip NFQUEUE.
    ct mark >= 20000 meta mark set ct mark accept
    meta mark >= 20000 ct mark set meta mark accept

    # Daemon bypass mark — daemon's own sockets (DNS forwarder, relay
    # connects, proxy connects) carry this mark to skip NFQUEUE.
    # Uses a dedicated mark BELOW 20000 so it does NOT trigger policy
    # routing rules (the daemon's own connections follow the default route).
    meta mark 19998 accept

    # Loopback / DNS / ICMP / ICMPv6 bypass.
    oifname "lo" accept
    ip daddr 127.0.0.0/8 accept
    ip6 daddr ::1 accept
    ip6 daddr ::ffff:7f00:0000/104 accept
    udp dport 53 accept
    tcp dport 53 accept
    meta l4proto icmp accept
    meta l4proto icmpv6 accept

    # All other output goes to NFQUEUE. The userspace daemon maintains a
    # per-5-tuple verdict cache so that already-decided connections are
    # fast-pathed in Rust rather than being re-classified every packet.
    queue num 0
  }

  # After NFQUEUE: stash the verdict-mark in ct mark and clear meta mark
  # so the next chain can produce a real mark-change inside its own
  # nft_do_chain (the only thing that triggers ip_route_me_harder).
  chain output_save_mark {
    type filter hook output priority -125; policy accept;
    meta mark >= 20000 ct mark set meta mark meta mark set 0
  }

  # Restore meta mark from ct mark. Pre-mark is 0 (just cleared), post-mark
  # is X — the kernel sees the change and reroutes via the fwmark table.
  chain output_reroute {
    type route hook output priority -100; policy accept;
    ct mark >= 20000 meta mark set ct mark
  }

  # POSTROUTING masquerade — rewrite source IP to match the rerouted
  # egress interface. Necessary because ip_route_me_harder updates the
  # destination route but does NOT redo source-address selection: without
  # this, the packet leaves the new interface still carrying whichever
  # source IP the original (pre-mark) routing decision picked — typically
  # a non-routable VPN address, which ISP egress filters drop (BCP38).
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    meta mark >= 20000 oifname != "lo" masquerade
    ct mark   >= 20000 oifname != "lo" masquerade
  }

  chain forward {
    type filter hook forward priority 0; policy accept;
    oifname "lo" accept
    queue num 0
  }
}
```

The `queue num N` statement puts the packet in NFQUEUE number N and **blocks** it until userspace replies. The kernel will not forward or transmit the packet until a verdict arrives.

### Daemon bypass mark (`DAEMON_BYPASS_MARK = 19998`)

The daemon itself makes outbound network connections:

- **DNS forwarder** — system DNS fallback (`forward_udp`), device-egress DNS (`resolve_via_bindtodevice`), proxy-egress DNS (`dns_over_socks`).
- **TCP relay** — proxy connects (`connect_via_proxy_target`), device fallback connects (`connect_plain`).

Without a bypass mark, these connections pass through `output_early` unmarked, hit the `queue num N` rule, and get intercepted by NFQUEUE. The process resolver correctly identifies them as belonging to `logiguard-daemon` — but that's the wrong attribution. The real application that triggered the connection is hidden behind the relay.

The fix stamps `SO_MARK(DAEMON_BYPASS_MARK)` on all daemon-originated sockets. The nftables `output_early` chain has an explicit accept rule for this mark value, placed before `queue num N`, so the daemon's own traffic bypasses NFQUEUE entirely.

**Why not use `ROUTE_MARK_BASE` (20000)?** Marks ≥ 20000 trigger policy routing rules (`ip rule add fwmark N lookup T`), which would force the daemon's own connections through a specific egress interface instead of the system default route. `DAEMON_BYPASS_MARK` (19998) is intentionally below this threshold so the daemon's connections follow normal routing.

**Already-covered paths** (no `DAEMON_BYPASS_MARK` needed):
- `connect_via_tun()` and `connect_via_device()` — already set `SO_MARK` with `ensure_route_mark()` (≥ `ROUTE_MARK_BASE`) for egress-specific routing.
- `resolve_via_so_mark()` — already sets `SO_MARK` with egress-specific fwmark for TUN DNS.

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

### Pure ACK (mid-connection) — empty payload, cached-or-accept

```rust
if raw.tcp_payload_empty && !raw.tcp_syn {
    if let Some(cached) = self.decided.get(&key) { ... }
    return (Verdict::Accept, None);
}
```

Pure ACKs (client acknowledging server data, mid-connection) carry no application payload — there's nothing new to classify and re-running the `/proc` resolver risks `process_name = None` when the fd scan races an Electron network-service fork/exec. They consult the verdict cache and fall through to Accept on miss. They do *not* evict the cache (evicting on ACK was an earlier bug — see 2026-05-15).

### SYNs — classified, NOT short-circuited

SYNs *also* have `tcp_payload_empty = true`, but they take the slow path. The short-circuit condition is `tcp_payload_empty && !tcp_syn`, so a SYN falls through to full classification.

The reason is **conntrack-NAT lifecycle**. NAT decisions (DNAT in OUTPUT, SNAT/masquerade in POSTROUTING) are made *once*, at the conntrack-NEW packet. The decision is then frozen for the lifetime of the connection. If the SYN exits the kernel unmarked:

1. Initial routing decision uses `main` table → typically VPN. Source address picks the VPN's IP.
2. Conntrack-NEW packet hits POSTROUTING. Our masquerade rule's condition (`meta mark >= base`) is false → no SNAT recorded.
3. Conntrack permanently records "no NAT" for this connection.
4. A later data packet (TLS ClientHello) gets classified, mark-stamped, rerouted to the right interface — but the recorded "no NAT" means it leaves carrying the VPN's source IP. ISP egress filters drop it (BCP38), connection wedges, application times out.

Classifying SYNs lets the rule match on packet 1, stamps the mark, fires the reroute *and* the masquerade at the same NEW packet, and conntrack records the correct SNAT for the rest of the connection. The trade-off is that flows without an explicit Allow rule will have their SYN dropped while a `Pending` dialog is open — the application retransmits SYNs (~1s intervals on Linux) and resumes once the user decides. This matches OpenSnitch / Little Snitch interactive-firewall behavior.

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

## End-to-end Route Action Flow

What happens when a rule says `action = Route via egress eg-lan-enp3s0` and a user app (e.g. curl) opens a connection to `185.x.x.x:443`:

```text
curl creates socket; kernel route lookup with no mark → main table
                                                       → typically VPN
                                                       → source IP = VPN
                                                       
SYN ──▶ output_nat (-199)        meta mark=0 → no-op
        │
        ▼
        output_early (-150, route)
        │   rules 4-13 do not match
        │   queue num 0 ──▶ NFQUEUE
        │                    │
        │                    │  userspace classifies:
        │                    │  process=curl, domain=www.digikala.com (DNS-snoop cache hit)
        │                    │  rule matches Route via eg-lan-enp3s0
        │                    │  route_mark(Device(enp3s0)) = 0x4e20 (lazily installs table 30000)
        │                    │  verdict = Accept, NFQA_MARK = 0x4e20
        │                    │
        ◀──── reinject; skb->mark = 0x4e20 ──
        │
        ▼
        output_save_mark (-125, filter)
        │   meta mark=0x4e20 ≥ 20000 → ct mark = 0x4e20; meta mark = 0
        │
        ▼
        output_reroute (-100, route)
        │   pre-mark = 0
        │   ct mark=0x4e20 → meta mark = ct mark = 0x4e20
        │   post-mark = 0x4e20  →  ip_route_me_harder(mark=0x4e20)
        │                          → lookup table 30000
        │                          → default via 192.168.7.253 dev enp3s0
        │                          → skb->dst updated
        ▼
        (other LOCAL_OUT chains)
        │
        ▼
POSTROUTING
        │
        ▼
        postrouting (srcnat=100, nat)
        │   meta mark=0x4e20 ≥ 20000, oifname = enp3s0 → masquerade
        │   source IP rewritten 10.34.158.72 → 192.168.7.7
        │   conntrack records SNAT mapping for the lifetime of the connection
        ▼
NIC → enp3s0 → wire
        ▼
        SYN+ACK comes back to 192.168.7.7
        → conntrack reverse-NAT → curl's socket receives at its original tuple
```

Subsequent packets on the same flow short-circuit at NFQUEUE via the 5-tuple verdict cache (`Accept`, `fwmark=0x4e20`) and ride the same path. The connection lives entirely on `enp3s0` with the correct ISP-routable source IP, even though the user app never set `SO_MARK` on its socket.

---

## Fail-closed Routing Tables

Each `(target, fwmark)` policy table installed by `SystemRouteManager` contains **two** routes:

```sh
ip route replace default      via <gw> dev <iface> table <T> metric  100
ip route replace unreachable  default              table <T> metric 1000
```

Lower metric wins, so under normal conditions traffic uses the primary route. If the primary install fails (e.g. interface is down), or the rule lookup hits the table before the primary is in place, the `unreachable` default takes effect and the kernel returns `EHOSTUNREACH` — packets are *not* allowed to fall through to `main`.

This matters because on systems where another tool has poisoned the `main` table (e.g. a VPN-tun proxy app installing scope-link routes covering the entire IPv4 space), fall-through silently routes via the wrong interface instead of failing. The in-table `unreachable` keeps the failure boundary inside one table and avoids the global pref-ordering trap of using a separate `type unreachable` policy rule.

`SystemRouteManager::add_route` is itself transactional: if the primary route install fails, the lookup rule and any in-progress unreachable installs are rolled back, and `ensure_route_mark` in the daemon only advances `next_mark` after success — so transient install failures don't burn marks.

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

---

## NFQUEUE Error Recovery

The netlink socket between the kernel and `NfqueueProcessor` / `DnsSnoopWorker` can return errors from `recv()`. These fall into three categories with different recovery strategies:

### Error classification

| Error | errno | Meaning | Strategy |
|---|---|---|---|
| `ENOENT` | 2 | Queue binding invalidated (nftables table flushed, interface removed) | Re-apply nftables + reopen socket |
| `EINTR` | 4 | Interrupted by signal | Retry on same socket |
| `ENOBUFS` | 105 | Kernel queue overflow | Retry on same socket |
| `EWOULDBLOCK` | 11 | No data (non-blocking) | Retry on same socket |
| `EBADF` etc. | 9+ | Socket is dead | Terminate loop |

### ENOENT recovery flow

`ENOENT` means the kernel no longer has a queue configuration matching our binding — typically because someone (systemd, network manager, or the user) flushed the `inet logiguard` nftables table, or the TUN interface that the INPUT chain referenced was removed.

Retrying `recv()` on the same socket is useless — the kernel won't deliver packets to a dead binding. The `run_loop()` method takes a `recover(queue_num)` callback that:

1. Re-applies nftables via `NftablesBootstrap::setup()` (idempotent — tears down then re-creates the full chain set including `queue num N` rules)
2. Reopens the netlink socket: `queue.unbind()` → `Queue::open()` → `queue.bind(queue_num)`

The unbind-before-open ordering is critical: the kernel only allows one binding per queue number. Opening a new socket while the old one still holds the binding returns `EPERM`.

If recovery fails (e.g. nftables temporarily broken), it retries with exponential backoff (100ms → 200ms → ... → 30s cap) instead of terminating.

```text
ENOENT on recv()
  │
  ├─ log: "queue binding lost, re-applying nftables in 100ms"
  ├─ sleep(backoff)
  ├─ recover(queue_num)  ──▶  nftables setup()
  │   │
  │   ├─ Ok ──▶ unbind old socket
  │   │          Queue::open() + bind(queue_num)
  │   │          log: "queue recovered successfully"
  │   │          reset backoff to 100ms
  │   │
  │   └─ Err ──▶ log: "recovery failed, retrying"
  │              double backoff (cap 30s)
  │              retry from top
```

### Where recovery is wired

- **`NfqueueProcessor::run_loop(queue_num, recover)`** — `crates/enforcer/src/nfqueue.rs`
- **`DnsSnoopWorker::run_loop(queue_num, recover)`** — `crates/enforcer/src/dns_snoop.rs`
- **Daemon** — `apps/daemon/src/main.rs` passes `|q| bootstrap.setup(Some(q), route_mark_base)` as the recover callback for both processors
