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
│   └── control-api/           # Unix socket protocol schema
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
- `RuleAction` — {Allow, Deny, Ask, Route{target}}
- `RouteTarget` — {Tun(name), Device(name), Proxy(id)}
- `ProxyConfig` — proxy endpoint (SOCKS5/HTTP/Shadowsocks) with host, port, auth
- `ProxyProtocol` — {Socks5, Http, Shadowsocks}
- `ProxyAuth` — {None, Basic{username, password}, Shadowsocks{method, password}}
- `EgressTarget` — target + priority + enabled flag
- `Egress` — named route destination with prioritized targets, availability, and optional `dns_servers`
- `RuleDuration` — {UntilRestart, Permanent}
- `DestinationMatcher` — {IpExact, Cidr, DomainExact, DomainWildcard}
- `TransportProtocol` — {Tcp, Udp, Quic, Other}

**Serialization:** All types derive `Serialize`/`Deserialize` for JSON RPC.

### `policy-engine`

Rule matching and precedence logic.

**Key Functions:**
- `resolve_action(rules: &[Rule], flow: &FlowContext) -> Option<ResolvedRule>` — pick best matching enabled rule
- Specificity ranking: process + exact IP > process + wildcard > exact IP > wildcard > global
- Action precedence: Deny > Allow > Ask (`Allow` and `Route { .. }` share action rank **2**). If two rules tie on both specificity and action rank, **greater** `rule.id` wins.
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
- `resolve_pending()` → apply user decision, clears flow index entry
- `expire_timeouts()` → auto-deny expired pendings, clears flow index entries
- `purge_session_rules()` → delete UntilRestart rules

**Tests:** Unknown flow, dedup returns existing pending, separate port = new pending, resolve clears index, expire clears index, timeout, queue overflow, user resolve, protocol-specific behavior.

### `flow-classifier`

Process and domain attribution.

**Key Functions:**
- Determine source process (via netstat/procfs lookup)
- Determine destination domain (via DNS or SNI hints)
- Handle DNS/SNI conflict (fallback to IP-only)
- QUIC best-effort domain inference

**Traits:**
- `ProcessResolver` — lookup process by src IP:port
- `DnsResolver` — lookup domain by IP (from DNS cache)
- `SniResolver` — lookup domain from SNI
- `DeviceLabelResolver` — attach device labels (e.g., "vpn-work")

**Implementation:**
- `ProcProcessResolver` reads `/proc/net/{tcp,tcp6,udp,udp6}` → inode → `/proc/*/fd/*` → `/proc/<pid>/exe`/`comm`, with a UID-filtered first pass and a parent-exe fallback for short generic names. Successful resolutions are cached by `(src_ip, src_port, protocol)` (60 s TTL, 4096-entry cap) so retransmits of the same socket do not re-race the kernel. See [`docs/process-resolver.md`](process-resolver.md) and [`docs/process-attribution-races.md`](process-attribution-races.md).
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
- `rules` table — id, enabled, action, duration, process_name, destination, created_at, updated_at
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
ImmediateVerdict { action }
PendingStillWaiting { pending_id }
PendingResolved { action }
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

3. **DNS/SNI conflict:** Discard domain inference. Treat as IP-only. Prevents spoofing.

4. **Protocol-specific timeouts:** Different defaults for TCP (may retry) vs UDP (fire-and-forget).

5. **UntilRestart expiry:** Automatic cleanup on daemon startup. Prevents leaking session rules across boots.

6. **Permanent rule on scope toggle:** User decision + "PERMANENTLY" scope → new Permanent rule with inferred destination. Applies to both Allow and Deny.

7. **SQLite for state:** ACID transactions, journaling, simple schema. No external DB dependency.

8. **Unix socket + JSON:** Local IPC, no network exposure. Simple text protocol for debugging.

9. **Daemon-owned routed connect:** Emulator stays unprivileged; daemon accepts `OpenRoutedTcp`, installs **managed** policy-routing (`ip rule fwmark … table …`) via `SystemRouteManager`, sets **`SO_MARK`** on the outbound socket to hit that table, and relays bytes. **Tun:** `default dev <tun>` in the managed table only—do **not** reuse WireGuard’s existing fwmark when that mark means split-tunnel bypass (traffic would leave via `main`/LAN). **Device:** optional Linux **`SO_BINDTODEVICE`** on the iface plus source-IP bind + same fwmark pattern. Diagnostics log both unmarked `ip route get` (follows default route) and **`ip route get … mark …`** (shows the marked policy path).

10. **Per-egress DNS resolution:** Daemon resolves hostnames with egress-specific DNS servers when configured, with fallback to system resolver.
11. **Throne transparent proxy compatibility:** Device-routed connections bypass throne's TCP redirect via `output_nat` chain:
    - Saves routing mark to conntrack mark, sets throne's bypass mark (0x2024)
    - Throne skips redirect for bypassed packets
    - Bypass only applies when output device is NOT throne-tun
    - Routing mark restored before routing decision via conntrack
    - Configurable `ROUTE_MARK_BASE` (default: 20000) via `LOGIGUARD_ROUTE_MARK_BASE` env var
12. **Single-decision window gating in monitor mode:** Tray monitor allows only one decision dialog at a time and clears the open-window gate after the spawned `--pending-id` child exits (parent waits on child). Deferred pendings are retried on subsequent polls.

## Systemd Integration

**Daemon unit file (packaged / reference):** `resources/linux/systemd/logiguardd.service`  
Installs as `/usr/lib/systemd/system/logiguardd.service` with `ExecStart=/usr/bin/logiguardd`, `RuntimeDirectory=logiguard` (socket under `/run/logiguard/`), and `StateDirectory=logiguard` (SQLite under `/var/lib/logiguard/`). Override or drop-in to set `LOGIGUARD_NFQUEUE` when using kernel interception.

**Boot Gate:** nftables rules block all traffic until daemon signals readiness (health check).

**Arch Linux:** see `packaging/archlinux/README.md` and `packaging/archlinux/PKGBUILD`.

## Environment Variables

- `LOGIGUARD_SOCKET_PATH` — Unix control socket (daemon default: `/tmp/logiguard.sock`)
- `LOGIGUARD_ROUTE_MARK_BASE` — Base value for routing fwmark allocation (default: 20000). Used to avoid conflicts with other tools (sing-box, xray, throne).
- `LOGIGUARD_DB_PATH` — SQLite database file (daemon default: `/tmp/logiguard.db`; override for production paths)
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
