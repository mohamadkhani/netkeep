# LogiGuard Architecture

Network flow authorization system for Linux: intercept unknown flows, prompt user, enforce rules.

**Repository:** https://github.com/mohammadreza-khani/logiguard
**Language:** Rust
**Platforms:** Linux desktop first
**Status:** Phase 4+ (GPUI UI + settings window with Table/Dialog + proxy support)

## System Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    User Desktop                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ logiguard-gpui (GPUI app)                              │  │
│  │  - Displays pending decisions                          │  │
│  │  - Countdown timer with auto-deny                     │  │
│  │  - Allow/Deny buttons with scope toggle               │  │
│  │  - Segmented pill: THIS SESSION / PERMANENTLY         │  │
│  └────────────────────────────────────────────────────────┘  │
│             ▲                                                 │
│             │ Unix socket JSON RPC                           │
│             │ /tmp/logiguard.sock                            │
│             ▼                                                 │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ logiguard-cli (terminal CLI)                           │  │
│  │  - add-rule, list-rules, delete-rule                  │  │
│  │  - list-pendings, resolve-pending                     │  │
│  │  - health, unlock (console-only)                      │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
             ▲
             │ systemd user/system daemon
             │
┌────────────────────────────────────────────────────────────────┐
│ Root Context (logiguardd daemon)                               │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ ControlService                                           │ │
│  │  - Unix socket server                                   │ │
│  │  - Request routing (AddRule, ListPending, etc.)        │ │
│  │  - Response formatting                                 │ │
│  │  - Health/config endpoint                              │ │
│  │  - Routed TCP relay endpoint (OpenRoutedTcp)           │ │
│  └──────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ PacketProcessor (NFQUEUE)                               │ │
│  │  - Receives packets from nftables                       │ │
│  │  - Classifies flows (process, domain, IP)              │ │
│  │  - Queries decision engine                             │ │
│  │  - Issues verdicts (allow/deny/pending)                │ │
│  └──────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ DecisionEngine                                           │ │
│  │  - Rule matching & precedence                          │ │
│  │  - Pending queue management                            │ │
│  │  - Timeout state machine                               │ │
│  │  - Pending decision creation                           │ │
│  └──────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ StateStore (SQLite)                                     │ │
│  │  - Rules persistence                                   │ │
│  │  - Flow history                                        │ │
│  │  - Pending decisions                                   │ │
│  │  - Migrations & journaling                             │ │
│  └──────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ nftables integration                                     │ │
│  │  - Kernel policy programming (QUEUE target)           │ │
│  │  - Verdict feedback to kernel                          │ │
│  │  - Fail-close gate (block on daemon unhealthy)        │ │
│  └──────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

## Workspace Structure

```
logiguard/
├── crates/
│   ├── core-types/            # Shared types (Rule, Flow, etc.)
│   ├── policy-engine/         # Rule matching & precedence
│   ├── decision-engine/       # Pending queue + timeout state
│   ├── flow-classifier/       # Process & domain attribution
│   ├── enforcer/              # nftables + NFQUEUE integration
│   ├── state-store/           # SQLite repositories
│   ├── control-api/           # Unix socket protocol schema
│   ├── proxy-client/          # SOCKS5/HTTP CONNECT proxy client
│   ├── dns-tracker-ebpf/      # eBPF kprobe for DNS query process attribution (BPF bytecode)
│   ├── dns-tracker-common/    # Shared structs between BPF and userspace
│   └── dns-tracker/           # Userspace eBPF loader + map reader + DNS forwarder
├── apps/
│   ├── daemon/                # logiguardd (root systemd service)
│   ├── cli/                   # logiguard-cli (operator interface)
│   └── gpui/                  # logiguard-gpui (GPUI decision UI)
├── design/                    # HTML design reference files
├── docs/                      # Architecture and API documentation
├── Cargo.toml                 # Workspace root
├── rust-toolchain.toml        # Pinned Rust version + components
├── justfile                   # Task runner
└── develop.md                 # This implementation guide
```

## Core Crates

### `core-types`

Shared data models, no dependencies on other crates.

**Key Types:**
- `Rule` — policy rule with action, scope, duration
- `FlowContext` — network flow metadata (process, IPs, domain, protocol, direction, port)
- `PendingDecision` — user decision queue item
- `FlowEvent` — audit log entry
- `RuleAction` — {Allow, Deny, Ask, Route}
- `RouteTarget` — {Tun(name), Device(name), Proxy(id)} — concrete routing target resolved from an Egress at enforcement time
- `ProxyConfig` — proxy endpoint (SOCKS5/HTTP/Shadowsocks) with host, port, auth
- `ProxyProtocol` — {Socks5, Http, Shadowsocks}
- `ProxyAuth` — {None, Basic{username, password}, Shadowsocks{method, password}}
- `Egress` — named route entity with an ordered list of `RouteTarget`s; the first available target is used at enforcement time. Bound to a `Rule` via `Rule.egress_id`.
- `RuleDuration` — {UntilRestart, Permanent}
- `DestinationMatcher` — {IpExact, Cidr, DomainExact, DomainWildcard}
- `TransportProtocol` — {Tcp, Udp, Quic, Other}

**Serialization:** All types derive `Serialize`/`Deserialize` for JSON RPC.

### `policy-engine`

Rule matching and precedence logic.

**Key Functions:**
- `resolve_action(rules: &[Rule], flow: &FlowContext) -> Option<ResolvedRule>` — pick best matching enabled rule
- Specificity ranking: process + exact IP > process + wildcard > exact IP > wildcard > global
- Action precedence: Deny > Allow > Ask (`Allow` and `Route` share action rank **2**). If two rules tie on both specificity and action rank, **greater** `rule.id` wins.
- Tie-break: when specificity **and** action rank are equal, lexicographically greater `rule.id` wins (deterministic; avoids ambiguous SQLite row order)
- Wildcard matching: `*.example.com` matches subdomains, not apex

**Traits:**
- `RuleRepository` — mock-friendly interface for rule lookups

**Tests:** Exact match, CIDR, domain, wildcard, precedence, deny vs allow, overlapping Route tie-break, disabled rules, unknown-process fallback against specific destinations (with safety negatives for `Any` / `Cidr` / `Wildcard`).

**Unknown-process fallback in `process_matches`:** when the rule pins `process_name=Some(P)` but the live flow has `process_name=None` (proc attribution lost the `/proc` race), the rule still matches **only if** the rule's destination is `IpExact` or `DomainExact`. Broad destinations (`Any`, `Cidr`, `DomainWildcard`) still require a strict process match so a wildcard "allow X" rule cannot be silently piggy-backed on by an unattributed packet. Rationale and tests in [`docs/process-attribution-races.md`](process-attribution-races.md).

### `decision-engine`

Pending queue and timeout state machine.

**Key Behaviors:**
- Unknown flow (no rule match) → create `PendingDecision`
- Pending decision lifetime: created → user resolves (Allow/Deny) OR timeout expires → auto-deny
- Queue cap: 100 items (configurable)
- Timeout: default 100s (configurable per protocol: TCP/UDP/QUIC/Other)
- UntilRestart rules: expire on daemon startup
- **Flow deduplication:** `register_unknown_flow` keeps a `FlowKey → pending_id` reverse index. Subsequent packets for an already-pending flow (retransmits, post-SYN data) return the existing `PendingDecision` instead of creating a new one. The index is cleaned up on resolve and on timeout expiry.
- **Symmetric `(dst_ip, dst_port, protocol)` fallback** for cases where two packets of the *same* connection disagree on the process name (the `/proc` race in `ProcProcessResolver`). The fallback triggers when at least one side has `process_name = None`:
  - new packet has a name, existing pending was "unknown" → **upgrade** the pending in place (rewrite the index key, patch the stored flow's name + any newly-learned domain/device label), return the (upgraded) pending;
  - new packet is None, existing pending has a name → return the existing pending verbatim.
  Two pendings with *distinct, known* process names stay separate (e.g. chrome and firefox simultaneously connecting to the same host:port). See [`docs/process-attribution-races.md`](process-attribution-races.md) for why this exists and how it interacts with the resolver cache and the policy engine.

**FlowKey** (dedup identity): `(process_name, destination_ip, destination_port, protocol)` — stable across retransmits and domain-inference variance (SNI only present on ClientHello, not on subsequent packets).

**Traits:**
- `Clock` — deterministic time (system clock in prod, fake in tests)
- `PendingRepository` — persistence interface

**Functions:**
- `register_unknown_flow()` → existing or new pending ID
- `resolve_pending(id, action, egress_id)` → apply user decision, stores `(action, egress_id)` for later polling, clears flow index entry
- `take_resolved(id)` → `Option<(RuleAction, Option<egress_id>)>` — consumed once; callers use `egress_id` to call `resolve_route_target()` before returning `PendingResolved`
- `expire_timeouts()` → auto-deny expired pendings, clears flow index entries
- `purge_session_rules()` → delete UntilRestart rules

**Tests:** Unknown flow, dedup returns existing pending, separate port = new pending, resolve clears index, expire clears index, timeout, queue overflow, user resolve, protocol-specific behavior.

### `flow-classifier`

Process and domain attribution.

**Key Functions:**
- Determine source process (via SOCK_DIAG netlink → `/proc/net` fallback → inode → `/proc/*/fd/` scan)
- Determine destination domain (via DNS or SNI hints)
- Handle domain resolution: SNI/Host is authoritative; DNS cache is fallback
- QUIC best-effort domain inference

**Traits:**
- `ProcessResolver` — lookup process by src IP:port
- `DnsResolver` — lookup domain by IP (from DNS cache)
- `SniResolver` — lookup domain from SNI
- `DeviceLabelResolver` — attach device labels (e.g., "vpn-work")

**Implementation:**
- `ProcProcessResolver` queries the kernel's `SOCK_DIAG` netlink interface for `(inode, uid)` synchronously, then falls back to `/proc/net/{tcp,tcp6,udp,udp6}` when netlink is unavailable. The inode is mapped to a pid via `/proc/*/fd/*` → `/proc/<pid>/exe`/`comm`, with a UID-filtered first pass and a parent-exe fallback for known shell wrappers (`sh/bash/dash/zsh/fish`). Successful resolutions are cached by `(src_ip, src_port, protocol)` (60 s TTL, 4096-entry cap) so retransmits do not re-race the kernel.
  - **SOCK_DIAG primary:** `sock_diag::query_socket_inode` sends `InetRequest` via `NETLINK_SOCK_DIAG`, returning `(inode, uid)` from the kernel's internal socket structures without reading `/proc/net`. No TOCTOU race.
  - **Dual-file /proc fallback:** both the IPv4 and IPv6 `/proc/net` files are checked for any src_ip. Modern apps using `AF_INET6` sockets with `IPV6_V6ONLY=0` appear only in `/proc/net/tcp6` even for IPv4 destinations (as `::ffff:a.b.c.d`). `parse_hex_addr()` normalises 8-char and 32-char hex, collapsing IPv4-mapped addresses to `IpAddr::V4`. `parse_proc_net` performs cross-family comparison (V4↔V4, V6↔V6, V4↔V6 via `to_ipv4_mapped()`).
  - **Retry policy:** 4 attempts at `[0, 5, 15, 40]ms` (60 ms worst case) for the `/proc/net` fallback path. SOCK_DIAG needs no retry — it is synchronous. Only the first SYN of each connection reaches NFQUEUE, so this latency is paid at most once per connection.
  - See [`docs/process-resolver.md`](process-resolver.md) and [`docs/process-attribution-races.md`](process-attribution-races.md).
- TLS SNI extraction is in `enforcer::nfqueue::extract_tls_sni`; domains discovered from SNI populate the shared `SniDnsCache` consumed by `FlowClassifier`. QUIC SNI is not yet parsed.

### `enforcer`

nftables programming and NFQUEUE packet handling.

**Key Components:**
- `NftablesBootstrap` trait — program nftables rules (SystemNftablesBootstrap shells to `nft`)
- `PacketProcessor` — parse NFQUEUE packets, classify flows, query decision engine
- `parse_raw_packet()` — IPv4/IPv6, TCP/UDP, QUIC detection from raw bytes
- `NfqueueProcessor` — accepts packets from `nfq` crate, feeds to PacketProcessor
- Loopback bypass (defense-in-depth): localhost traffic is accepted without prompting in both nftables and userspace (`127.0.0.0/8`, `::1`, and IPv4-mapped `::ffff:127.0.0.0/104`)

**Data Flow:**
1. nftables kernel module sends packet to NFQUEUE
2. `NfqueueProcessor` reads from queue
3. `PacketProcessor` parses, classifies, queries decision engine
4. `VerdictSink` writes verdict back to kernel (accept/drop)

**Tests:** Packet parsing, verdict paths, nftables programming (with FakeBootstrap).

### `state-store`

SQLite-backed persistence.

**Key Repositories:**
- `RuleRepository` — CRUD rules, `purge_session_rules()` on startup
- `FlowRepository` — append flow events, list with limit
- `PendingRepository` — create/delete pending decisions, restore on startup
- `EgressRepository` — CRUD egresses, targets, and per-egress DNS servers

**Schema:**

- `rules` table — id, enabled, action, duration, process_name, destination, egress_id, created_at, updated_at
- `flow_events` table — id, process_name, device_label, destination_ip, destination_domain, protocol, state, timestamp_secs
- `pending_decisions` table — id, flow_id, created_at, deadline_at, default_action
- `egresses` table — id, name, color, is_system_default
- `egress_targets` table — target kind/value, priority, enabled per egress
- `egress_dns_servers` table — DNS resolver IPs per egress
- `proxies` table — id, name, protocol, host, port, auth_type, auth_data (JSON), enabled

**Migrations:** Auto-run on startup via schema versioning.

### `control-api`

Unix socket protocol schema (JSON-RPC style).

**Requests:**
```
AddRule(Rule)
ListRules
DeleteRule { id }
ListPending
ListFlows { limit }
RegisterUnknownFlow { flow, now_secs }
AwaitPendingDecision { pending_id }
ResolvePending { pending_id, action }
ResolvePendingWithRule { pending_id, action, rule }   ← atomic: installs rule before resolving
Health
Unlock
OpenRoutedTcp { host, port, target }
UpsertEgress(Egress)
DeleteEgress { id }
ListEgresses
UpsertProxy(ProxyConfig)
DeleteProxy { id }
ListProxies
SetNfqueueEnabled { enabled }
```

**Responses:**
```
Ok
RuleList(Vec<Rule>)
PendingList(Vec<PendingDecision>)
FlowList(Vec<FlowEvent>)
PendingCreated { pending_id, created_at, deadline_at, protocol }
ImmediateVerdict { action, route_target: Option<RouteTarget> }
PendingStillWaiting { pending_id }
PendingResolved { action, route_target: Option<RouteTarget> }
Health { ready, fail_close_active, timeout_secs, ... }
Unlocked
RoutedTcpReady { listen_addr }
EgressList(Vec<Egress>)
ProxyList(Vec<ProxyConfig>)
Error(String)
```

**Transport:** JSON lines (newline-delimited JSON) over Unix socket.

## Data Flow

### Rule Creation (User → Daemon)

```
User (CLI/GPUI)
  │ add-rule / AddRule request
  ├─→ ControlService (Unix socket)
        │ validate request
        ├─→ RuleRepository::insert()
              │ write to SQLite
              └─ return Ok
        └─→ send ControlResponse::Ok
  └─ return result
```

### Unknown Flow Decision

```
Kernel packet → nftables QUEUE
    │ (to userspace)
    ├─→ NfqueueProcessor
          │ parse packet bytes
          ├─→ PacketProcessor::process()
                │ classify (flow context)
                ├─→ Classifier::classify() (DnsResolver, ProcessResolver)
                ├─→ DecisionEngine::decide()
                      │ lookup rule match (RuleRepository)
                      ├─→ RuleAction::Allow → VerdictSink::accept()
                      ├─→ RuleAction::Deny → VerdictSink::drop()
                      └─→ RuleAction::Ask → PendingRepository::insert()
                                             FlowRepository::append()
                └─→ VerdictSink (send verdict back to kernel)
```

### Pending Decision Resolution

```
GPUI polls ListPending every 1s
  │
  └─→ ControlService::list_pending()
        │ query PendingRepository
        ├─→ DecisionEngine::expire_timeouts() (auto-deny expired)
        └─→ return PendingList
            │
            └─→ GPUI renders decision cards with countdown
                  │ User clicks Allow or Deny
                  └─→ ControlRequest::ResolvePendingWithRule { pending_id, action, rule }
                        │  (single atomic request — rule installed first to close race window)
                        └─→ ControlService::handle()
                              │ upsert_rule(rule)         ← rule active immediately
                              │ resolve_pending(id)       ← pending removed
                              │ delete_pending(repo)
                              └─→ return PendingResolved { action }
```

## Testing Strategy

**Non-negotiable principle:** All logic testable without OS dependencies.

### Trait-Based Abstraction

Every system effect behind a trait:

- `RuleRepository` — mock with Vec<Rule>
- `FlowRepository` — mock with Vec<FlowEvent>
- `PendingRepository` — mock with HashMap<id, PendingDecision>
- `Clock` — mock with FakeClock (step time manually)
- `ProcessResolver` — mock with FakeProcessResolver
- `DnsResolver` — mock with fake lookups
- `NftablesBootstrap` — FakeBootstrap (with success/failure modes)
- `VerdictSink` — FakeVerdictSink (capture verdicts for assertions)

### Unit Test Coverage

**policy-engine:** 10+ tests (matching, precedence, disabled)  
**decision-engine:** 8+ tests (pending lifecycle, timeout, queue overflow)  
**flow-classifier:** 7+ tests (process attribution, domain inference, conflicts)  
**enforcer:** 8+ tests (packet parsing, verdict paths, nftables programming)  
**state-store:** 8+ tests (CRUD, persistence, migrations)  
**control-api:** 5+ tests (request validation)

**Current:** 77 tests passing.

### Integration Tests

Planned (Phase 2 onward):
- Flow with allow rule → passes
- Flow with deny rule → blocked
- Unknown flow → pending, user approves → passes
- Unknown flow → timeout → denied
- TCP pending flow before deadline → passes
- UDP pending flow timeout → denied
- Rule creation from decision → persists
- Restart with permanent rule → rule survives
- Boot gate → blocks traffic until daemon ready
- Queue overflow → default denies

## Key Design Decisions

1. **Fail-close:** Default deny on any decision engine error. Traffic blocked until daemon recovers.

2. **Wildcard semantics:** `*.example.com` does NOT match `example.com`. Apex requires explicit rule.

3. **SNI is authoritative over DNS cache:** SNI (and HTTP Host) come directly from the packet being classified and always take precedence. The DNS cache is a 1:1 `IP → domain` map that cannot represent CDN multi-tenancy (multiple domains sharing one IP). When the cache is stale due to a different domain overwriting it, the per-packet SNI is the correct source. DNS cache is only used as a fallback when no SNI/Host is present in the packet (SYNs, pure ACKs, UDP).

4. **Protocol-specific timeouts:** Different defaults for TCP (may retry) vs UDP (fire-and-forget).

5. **UntilRestart expiry:** Automatic cleanup on daemon startup. Prevents leaking session rules across boots.

6. **Permanent rule on scope toggle:** User decision + "PERMANENTLY" scope → new Permanent rule with inferred destination. Applies to both Allow and Deny.

7. **SQLite for state:** ACID transactions, journaling, simple schema. No external DB dependency.

8. **Unix socket + JSON:** Local IPC, no network exposure. Simple text protocol for debugging.

9. **Daemon-owned routed connect:** Emulator stays unprivileged; daemon accepts `OpenRoutedTcp`, installs **managed** policy-routing (`ip rule fwmark … table …`) via `SystemRouteManager`, sets **`SO_MARK`** on the outbound socket to hit that table, and relays bytes. **Tun:** `default dev <tun>` in the managed table only—do **not** reuse WireGuard’s existing fwmark when that mark means split-tunnel bypass (traffic would leave via `main`/LAN). **Device:** optional Linux **`SO_BINDTODEVICE`** on the iface plus source-IP bind + same fwmark pattern. Diagnostics log both unmarked `ip route get` (follows default route) and **`ip route get … mark …`** (shows the marked policy path). The managed table also installs an in-table `unreachable default metric 1000` fallback so that if the primary route is missing or its interface goes down the kernel returns `EHOSTUNREACH` instead of silently falling through to `main` (where a VPN-tun proxy app's poisoned scope-link routes would otherwise re-route via the wrong interface). `SystemRouteManager::add_route` is transactional: on failure both the lookup rule and any partial route installs are rolled back, and `ensure_route_mark` only advances `next_mark` after success — transient install failures don't burn marks.

10. **Per-egress DNS resolution:** Daemon resolves hostnames with egress-specific DNS servers when configured, with fallback to system resolver.
11. **NFQUEUE-stamped routing marks — three-chain reroute + POSTROUTING masquerade:** A direct application connection (e.g. `curl`, no `SO_MARK` set on its socket) needs the kernel to (a) reroute the SYN to the egress interface the policy rule chose, and (b) rewrite the source IP to match that interface, before conntrack-NAT freezes the no-NAT decision at the conntrack-NEW packet. The naïve approach — putting the NFQUEUE rule in a `type route` chain — does not work: the kernel's route-chain hook only runs its mark-change check on the *return path* of `nft_do_chain`, and `NF_QUEUE` exits there. After `nf_reinject()` the iterator resumes at the *next* hook entry, so the chain that queued the packet never sees the verdict-mark. The actual layout (lib.rs):
    - `output_nat` (nat, -199): saves SO_MARK relay marks to `ct mark` before throne's redirect at priority 0; sets throne's `0x2024` bypass cookie. Does nothing for NFQUEUE traffic (mark is 0 at this priority).
    - `output_early` (route, -150): NFQUEUE rule. Userspace stamps `meta mark = X`. Chain exits via `NF_QUEUE` → reinject; no reroute fires here.
    - `output_save_mark` (filter, -125): for packets with `meta mark >= base`, copy to `ct mark` and **clear** `meta mark`. After this chain `meta mark = 0`.
    - `output_reroute` (route, -100): restore `meta mark` from `ct mark`. The chain captures pre-mark `0`, sets post-mark `X` inside its own `nft_do_chain` — kernel sees the change and calls `ip_route_me_harder()`, which finally consults the fwmark rule and lands the packet on the right egress interface.
    - `postrouting` (nat, srcnat=100): `meta mark >= base oifname != "lo" masquerade` (plus a `ct mark >= base` twin for relay-path traffic where `output_nat` overwrote `meta mark` with `0x2024`). Rewrites source IP to the actual egress interface's primary IP — necessary because `ip_route_me_harder` updates the route but does NOT redo source-address selection. Conntrack records the SNAT once at conntrack-NEW and reverses it on the inbound path, transparent to the application.
    - **SYNs are classified, not short-circuited.** `nfqueue.rs:decide()` short-circuits on `tcp_payload_empty && !tcp_syn` — pure ACKs mid-connection consult the verdict cache and fall through to Accept, but SYNs run full classification. The reason is the conntrack-NAT lifecycle: NAT decisions are made once, at the conntrack-NEW packet (the SYN). If the SYN exits unmarked, conntrack records "no NAT" and a later data-packet's mark cannot change that — the connection is permanently nailed to the wrong source IP. Trade-off: flows without a matching Allow rule have their SYN dropped while `Pending` is open; the application retransmits at ~1s intervals and resumes once the user decides. Matches OpenSnitch / Little Snitch interactive-firewall behavior.
    - Configurable `ROUTE_MARK_BASE` (default: 20000) via `LOGIGUARD_ROUTE_MARK_BASE` env var.
    - See [`docs/nfqueue-packet-interception.md`](nfqueue-packet-interception.md) "Why three OUTPUT chains for one routing decision" and "End-to-end Route Action Flow" for the full path.
12. **Single-decision window gating in monitor mode:** Tray monitor allows only one decision dialog at a time and clears the open-window gate after the spawned `--pending-id` child exits (parent waits on child). Deferred pendings are retried on subsequent polls.

13. **Egress-bound rules; target resolved at enforcement time:** `Rule.egress_id` references a named `Egress` entity rather than embedding a concrete `RouteTarget`. At enforcement time `control-service::first_available_target()` walks the egress's ordered target list and returns the first usable one — Device/Tun checked via `/sys/class/net/<name>/operstate`, Proxy checked via `ProxyRepository.enabled`. This enables failover (e.g. primary VPN down → backup proxy) without touching the rule. `ImmediateVerdict` and `PendingResolved` carry the resolved `route_target: Option<RouteTarget>` so the enforcer still gets a concrete target even though `RuleAction::Route` no longer embeds one. **`AwaitPendingDecision` also resolves the target** — `DecisionEngine.resolved` stores `(action, egress_id)` so any poller (emulator, CLI) receives the same concrete target that the UI received via `ResolvePendingWithRule`. Without this, the first request after a dialog resolution would route to the wrong interface; subsequent requests (which hit the persisted rule directly) would route correctly.

14. **Daemon does not auto-seed per-interface egresses:** On startup the daemon only ensures the `eg-default` system egress exists. It does not create one Egress per local network interface. Interface availability is checked at routing time by `first_available_target()`, not stored in the DB. The "Route via" selector in the decision dialog therefore shows only user-defined named egresses plus the default route.

15. **First-run egress seeding (LAN + TUN):** On the very first startup against a fresh DB (i.e. no user-defined egresses beyond `eg-default`), the daemon runs `seed_initial_egresses()` to provide a usable set of routing options out of the box:
    - **LAN egress** — detected via `ip route get 8.8.8.8`; the `dev <iface>` field identifies the default-route interface. Creates one `RouteTarget::Device(iface)` egress (blue `#3b82f6`).
    - **TUN egresses** — scanned from `/sys/class/net/*/type`; any interface whose `type` file reads `65534` (the kernel TUN/TAP constant, shared with WireGuard) gets its own egress named after the interface (purple `#8b5cf6`).
    Seeding is skipped entirely once any user egress is present, so it never overwrites user configuration. The DB path defaults to `~/.config/logiguard/logiguard.db`, resolved from `$HOME` at runtime (Rust does not expand shell tildes); the parent directory is created automatically.

    **Gotcha:** if the daemon is first started while a VPN is up, `ip route get 8.8.8.8` returns the VPN tun device, so the seeded "LAN" egress ends up pointing at the VPN interface, not the actual physical NIC. The user then picks "Route via LAN" and gets the VPN. Fix is the user's: delete and recreate the egress (or edit its targets via the per-target list editor in Settings) once the VPN is down. A future enhancement could prefer `/sys/class/net/<iface>/type == 1` (ethernet) over `65534` (tun) when seeding the LAN row.

## Systemd Integration

**Daemon unit file (packaged / reference):** `resources/linux/systemd/logiguardd.service`  
Installs as `/usr/lib/systemd/system/logiguardd.service` with `ExecStart=/usr/bin/logiguardd`, `RuntimeDirectory=logiguard` (socket under `/run/logiguard/`), and `StateDirectory=logiguard` (SQLite under `/var/lib/logiguard/`). Override or drop-in to set `LOGIGUARD_NFQUEUE` when using kernel interception.

**Boot Gate:** nftables rules block all traffic until daemon signals readiness (health check).

**Arch Linux:** see `packaging/archlinux/README.md` and `packaging/archlinux/PKGBUILD`.

## Environment Variables

- `LOGIGUARD_SOCKET_PATH` — Unix control socket (daemon default: `/tmp/logiguard.sock`)
- `LOGIGUARD_ROUTE_MARK_BASE` — Base value for routing fwmark allocation (default: 20000). Used to avoid conflicts with other tools (sing-box, xray, throne).
- `LOGIGUARD_DB_PATH` — SQLite database file (daemon default: `~/.config/logiguard/logiguard.db`; directory is created automatically)
- `LOGIGUARD_DEVICE_ROUTE_FALLBACK` — if `1`/`true`/`yes`, routed **device** connect may fall back to unmarked `connect` after failures (escape hatch; not fail-close strict)
- `LOGIGUARD_NFQUEUE` — NFQUEUE number to listen on (default: 0)
- `LOGIGUARD_DEFAULT_TIMEOUT_SECS` — default pending timeout in seconds (default: 100)
- `LOGIGUARD_TCP_TIMEOUT_SECS` — TCP-specific pending timeout (falls back to default when unset)
- `LOGIGUARD_UDP_TIMEOUT_SECS` — UDP-specific pending timeout
- `LOGIGUARD_QUIC_TIMEOUT_SECS` — QUIC-specific pending timeout
- `LOGIGUARD_OTHER_TIMEOUT_SECS` — other protocols pending timeout

## Recovery

**Fail-close boot gate:** nftables rule blocks all traffic until daemon health endpoint returns ready=true.

**Physical console unlock:** `logiguard unlock` command checks:
1. Peer credential (SO_PEERCRED)
2. Peer process stdin is /dev/console (from /proc/<pid>/fd/0)
3. If both check, tear down nftables policy

Prevents remote unlock attempts.

## Performance Characteristics

- **Rule matching:** O(n) linear scan (n=rules). For <100 rules, acceptable.
- **Pending queue:** O(1) insert/lookup (HashMap-backed). Cap at 100 to bound memory.
- **Timeout expiry:** O(m) scan (m=pending). Called every 1s, max 100 pendings = fast.
- **Packet processing:** O(n) rule lookup per packet. Expect <100 µs per verdict.
- **SQLite writes:** Async journaling. Should not block packet processing.

## Desktop Compatibility

The GPUI tray icon uses `tray-icon` (via `libappindicator`), which implements the freedesktop **StatusNotifierItem** (SNI) / **DBusMenu** protocol. This is the same standard used by KDE Plasma's system tray.

| Desktop Environment | Status | Notes |
|---|---|---|
| **KDE Plasma** | Works out of the box | Native SNI support |
| **GNOME** | Requires extension | Install "AppIndicator and KStatusNotifierItem Support" (or KStatusNotifierItem) from extensions.gnome.org |
| **XFCE** | Works out of the box | Uses `xfce4-statusnotifier-plugin` |
| **Cinnamon** | Works out of the box | Built-in AppIndicator support |
| **Sway / Hyprland** | Partial | Requires a tray bar like `waybar` with SNI support |

**Known issue:** `libayatana-appindicator` prints a deprecation warning at startup (`libayatana-appindicator is deprecated. Please use libayatana-appindicator-glib`). This is cosmetic and does not affect functionality. The migration to `libayatana-appindicator-glib` (or the modern `ksni` approach) is tracked as a future enhancement pending upstream crate stabilization.

**GTK requirement:** On Linux, `gtk::init()` must be called before creating the tray icon and menu. GPUI does not run a GTK main loop, so the app manually drains pending GTK events via `gtk::events_pending()` / `gtk::main_iteration_do()` on a 50ms polling timer. This ensures the AppIndicator menu updates correctly.

## Settings Window Architecture

The settings window (`--settings` flag) runs as a separate GPUI process. It uses gpui-component's `Table` and `Dialog` components for data management.

### Process Model

```
Tray icon (main process)
  │ --settings flag → spawn separate process
  └→ settings process (independent lifecycle)
       │ gpui_component::init()
       │ Root::new(view, window, cx)  // Required for Dialog support
       └→ SettingsApp (Render)
            ├── TabBar (Rules / Egress / Proxies)
            ├── Table<RulesDelegate>
            ├── Table<EgressDelegate>
            └── Table<ProxiesDelegate>
```

### Table + Delegate Pattern

Each tab uses a `TableDelegate` implementation:

| Delegate | Columns | Actions |
|----------|---------|---------|
| `RulesDelegate` | ID, Action, Destination, Route, Controls | Toggle enabled, Delete |
| `EgressDelegate` | Name, Type, Targets, DNS, Status, Controls | Delete |
| `ProxiesDelegate` | Name, Protocol, Address, Auth, Status, Controls | Toggle enabled, Delete |

**Data flow:**
1. `SettingsState` entity holds raw data (rules, egresses, proxies)
2. `SettingsApp::sync_tables()` copies data into each delegate on state change
3. `cx.observe(&state, ...)` triggers sync on state updates
4. `fetch_and_apply()` async task loads data from daemon via Unix socket

### Dialog Pattern

Double-clicking a table row opens a detail dialog:

```rust
cx.subscribe_in(&egress_table, window, |this, _table, event, window, cx| {
    if let TableEvent::DoubleClickedRow(row_ix) = event {
        // Open dialog with egress details
        window.open_dialog(cx, |dialog, _, _| {
            dialog.title("Egress: ...").w(px(500.)).child(...)
        });
    }
});
```

**Key constraint:** Dialog closure is `Fn` (not `FnOnce`). Use `.clone()` for non-Copy types consumed in conditional branches.

### File Structure

```
apps/gpui/src/settings/
├── mod.rs           # SettingsApp, SettingsState, tab switching, dialog handlers
├── rules_tab.rs     # RulesDelegate (TableDelegate)
├── egress_tab.rs    # EgressDelegate (TableDelegate)
├── proxies_tab.rs   # ProxiesDelegate (TableDelegate)
└── helpers.rs       # fetch_and_apply, parse_dns_csv, route_summary
```

### Window Configuration

- Size: 960×720 pixels
- TitleBar: gpui-component TitleBar with drag support
- Root wrapper: Required for Dialog support
- Single-instance guard: `Arc<AtomicBool>` prevents duplicate windows

## Future Enhancements (Out of MVP Scope)

- Real ProcessResolver (netstat, /proc/net integration)
- SNI extraction from QUIC Initial packets
- DNS query interception (collect domain hints)
- Route rule conflict warnings in UI when multiple rules match the same flow
- Rule templates and groups
- Web UI (phase 5)
- Integration with systemd user services
- Config file support (TOML/YAML)
- Rate limiting / anomaly detection
- Audit logging (syslog integration)
