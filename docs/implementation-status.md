# LogiGuard Current Implementation State

**Test Status:** 87 tests passing (`cargo test --workspace`)
**Phase:** 4 / 5 (GPUI UI complete, rule scope selection implemented)
**Last Updated:** 2026-05-12

## Completed Work

### Phase 0: Foundation ✓

- [x] Rust workspace created with 7 crates + 3 apps
- [x] Cargo workspace configuration
- [x] `rust-toolchain.toml` pinned (stable + clippy + rustfmt)
- [x] CI task runner (`justfile`) with fmt/lint/test/check/ci targets
- [x] `core-types` schema defined (Rule, Flow, PendingDecision, etc.)
- [x] Test infrastructure with trait-based mocking (RuleRepository, Clock, etc.)

### Phase 1: Policy + Decision Core ✓

- [x] `policy-engine` — rule matching, precedence logic, wildcard semantics
- [x] `decision-engine` — pending queue, timeout state machine, protocol-specific behavior
- [x] Full unit test suites (16+ tests covering all decision paths)
- [x] Fixed Bug 2: Added `purge_session_rules()` to delete UntilRestart rules on daemon startup

### Phase 2: Enforcement Path (Partial) ✓

- [x] `enforcer` crate with nftables + NFQUEUE integration
- [x] `NftablesBootstrap` trait + SystemNftablesBootstrap implementation
- [x] `PacketProcessor` — parse packets, classify flows, query decision engine
- [x] `parse_raw_packet()` — IPv4/IPv6, TCP/UDP, QUIC detection
- [x] `NfqueueProcessor` using pure-Rust `nfq` crate
- [x] Packet parsing tests (IPv4/TCP, IPv4/UDP, IPv6, QUIC detection)
- [x] Verdict path tests (allow/deny)
- [x] TLS SNI extraction from ClientHello (`extract_tls_sni` in `enforcer::nfqueue`)
- [x] TCP control packets (SYN/ACK/FIN) accepted immediately so handshake completes before classification
- [x] `RawPacket::tcp_payload_empty` flag to distinguish control packets from data packets
- [x] Real ProcessResolver via `/proc/net/{tcp,tcp6,udp,udp6}` → inode → `/proc/<pid>/fd` → `/proc/<pid>/comm`
- [ ] **Not done:** DNS snoop cache for UDP/QUIC domain inference (SNI covers TCP/HTTPS)
- [ ] **Not done:** Integration tests with actual kernel NFQUEUE

### Phase 3: Persistence + CLI ✓

- [x] `state-store` crate with SQLite repositories
- [x] RuleRepository (insert/read/update/delete)
- [x] FlowRepository (append flow events, list with limit)
- [x] PendingRepository (create/delete/restore on startup)
- [x] `control-api` with Unix socket JSON-RPC protocol
- [x] CLI binary with commands:
  - [x] `add-rule [--action Allow|Deny|Ask] [--duration UntilRestart|Permanent] [--process NAME] DESTINATION`
  - [x] `list-rules [--json]`
  - [x] `delete-rule ID`
  - [x] `list-flows [--limit N] [--json]`
  - [x] `list-pendings [--json]`
  - [x] `resolve-pending PENDING_ID [allow|deny]`
  - [x] `show-config [--json]` (health + config output)
  - [x] `unlock` (console-only recovery command)
  - [x] `health` (daemon status)
- [x] Daemon initialization of SQLite DB on startup
- [x] ControlService handling all request types
- [x] Health endpoint with timeout configuration
- [x] Egress persistence with route targets
- [x] Per-egress DNS persistence (`egress_dns_servers` table)
- [ ] **Not done:** Migrations and schema versioning (manual for now)

### Phase 4: GPUI Interface ✓

- [x] New `logiguard-gpui` GPUI app
- [x] Imported gpui 0.2.2 and gpui-component 0.5.1 from crates.io
- [x] Modular architecture with separate files:
  - `colors.rs` — Material Design 3 dark theme color constants (from HTML design spec)
  - `daemon.rs` — socket IPC helpers (send_request, unix_now, fetch_pending, detect_egresses)
  - `fonts.rs` — custom font loading (Inter, SpaceGrotesk)
  - `monitor.rs` — background monitor mode (polls daemon, spawns GUI per pending)
  - `state.rs` — AppState entity (item, now_secs, make_permanent, pending_count)
  - `app.rs` — DecisionApp root view + Render impl + 1-second countdown ticker
  - `components/header.rs` — security icon, CONNECTION INTERCEPTED title, circular countdown ring, AUTO-DENY label
  - `components/flow_info.rs` — grid layout with colored badges (teal protocol, IP/direction chips)
  - `components/action_footer.rs` — rule scope section (process toggle, destination scope selector, CIDR octet picker, rule summary line), duration pill, egress chips, Allow/Deny buttons with broad-rule validation
  - `components/status_bar.rs` — centered footer with LogiGuard branding and queue status
  - `settings/mod.rs` — SettingsApp with Table/Dialog, tab switching, data sync
  - `settings/rules_tab.rs` — RulesDelegate (TableDelegate) with toggle/delete actions
  - `settings/egress_tab.rs` — EgressDelegate (TableDelegate) with type badges, delete
  - `settings/proxies_tab.rs` — ProxiesDelegate (TableDelegate) with protocol badges, toggle/delete
  - `settings/helpers.rs` — fetch_and_apply, parse_dns_csv, route_summary
- [x] Material Design 3 dark theme matching HTML design spec (`design/decision_dialog_window.html`)
- [x] Segmented pill toggle for scope selection (THIS SESSION / PERMANENTLY)
- [x] Custom outlined buttons (green border ALLOW, error border DENY) replacing gpui-component buttons
- [x] Grid layout flow info with colored badges for protocol/IP/direction
- [x] Reactive rendering (observe AppState, notify on changes)
- [x] Allow and Deny button flows with optional permanent rule creation
- [x] 1-second countdown ticker with auto-exit on timeout
- [x] Async event handlers with weak entity references
- [x] Monitor mode: polls daemon every 1s, spawns GUI window per new pending decision
- [x] Monitor reliability fixes:
  - `shown_ids` tracks only successfully spawned dialogs (deferred/failed spawns retry)
  - decision-window gate is cleared in tray process after child window exits
- [x] Decision window exits immediately after action (removed transient "Closing..." state and artificial delay)
- [x] Settings window with Rules, Egress, Proxies tabs using gpui-component Table
- [x] TableDelegate pattern for each tab with custom cell rendering
- [x] Dialog for egress detail and proxy edit (double-click to open)
- [x] Proxy support: ProxyConfig, ProxyProtocol, ProxyAuth types
- [x] Proxy CRUD: control-api, state-store SQLite, daemon, CLI
- [x] RouteTarget::Proxy(id) replaces RouteTarget::Socks
- [x] Rule scope selection UI implemented (process toggle, domain/CIDR destination scope, rule summary line)
- [x] `DestinationMatcher::Any` variant added (allows "specific process, any destination" rules)
- [x] `ProcessScope` / `DestScope` state in `AppState` initialized from flow at startup
- [x] Too-broad rule validation: Allow/Deny buttons disabled for "all processes + any destination"
- [x] CIDR octet picker: fixed-width clickable chips, active_octets drives prefix computation
- [x] Warning banner when both process and destination unknown

### Routed Relay + Per-Egress DNS (2026-05-08) ✓

- [x] Added daemon runtime API: `OpenRoutedTcp { host, port, target }`
- [x] Emulator now requests daemon-managed routed relay for `RuleAction::Route`
- [x] Daemon owns privileged connect: **`SO_MARK`** + **`SystemRouteManager`** tables; **Tun** uses **daemon-allocated** fwmark only (never reuse WireGuard “bypass” fwmark—would egress LAN while default route is VPN). **Device** uses **`SO_BINDTODEVICE`** (Linux) + bind + mark where supported.
- [x] Added routed connect timeout (`8s`) to avoid long hangs
- [x] Added socket permission auto-fix (`/tmp/logiguard.sock` -> `0666`)
- [x] Added per-egress DNS host resolution in daemon routed connect path
- [x] Added fallback to system DNS when no egress DNS is configured
- [x] Route probes in logs: unmarked `ip route get` vs `ip route get … mark …` for debugging policy vs default route
- [x] Policy tie-break on `rule.id` when specificity and action rank tie (`policy-engine::resolve_action`)
- [x] `RuleRepository::list_rules` returns stable **ORDER BY id**
- [x] Loopback interception hardening: skip localhost in both nftables and userspace, including IPv4-mapped IPv6 localhost (`::ffff:127.0.0.0/104`)

## Bug Fixes (Session 3, 2026-05-06)

**Bug 1:** Pending timeouts never expire  
- **Fix:** Added `ControlService::tick()` timer thread that calls `expire_timeouts()` every second

**Bug 2:** UntilRestart rules leak across daemon restarts  
- **Fix:** Added `purge_session_rules()` method to RuleRepository, called in daemon init

**Bug 3:** CLI add-rule requires full rule struct, lacks auto-detection  
- **Fix:** Added flags to `add-rule`: `--action`, `--duration`, `--process`. Destination auto-detected.

**Bug 4:** No flow event history  
- **Fix:** Added FlowEvent/FlowState types, FlowRepository, flow recording on every verdict

**Bug 5:** Pending decisions lost on daemon restart  
- **Fix:** Added PendingRepository (SQLite persistence), restore on daemon startup

**Bug 6:** Unlock command acceptable from any context  
- **Fix:** Added SO_PEERCRED check + /proc/<pid>/fd/0 console validation

## Bug Fixes (Session 4-5, 2026-05-07/08)

**Bug 7:** GPUI UI did not match design spec  
- **Fix:** Redesigned all components to match Material Design 3 dark theme from `design/decision_dialog_window.html`
  - Replaced ad-hoc colors with Material Design 3 palette
  - Replaced checkbox with segmented pill scope toggle
  - Replaced filled buttons with custom outlined buttons with icons
  - Added grid layout flow info with colored badges
  - Added status bar footer
  - Reduced window size to 420x488

**Bug 8:** Countdown timer frozen (never ticking)  
- **Fix:** Added 1-second async timer loop in `DecisionApp::new()` that updates `now_secs` and calls `cx.notify()` each tick. Auto-exits when countdown reaches 0.

**Bug 9:** Deny button does not create permanent rule when PERMANENTLY scope selected  
- **Fix:** Added `make_permanent` and `flow` parameters to `deny_button()`, mirroring the allow button's `AddRule` logic with `RuleAction::Deny`.

## Bug Fixes (routing, 2026-05-09)

**Bug 10:** SOCKS `Route` → Tun exited via LAN (Digikala saw Iranian IP / HTTP 200 instead of VPN/geo edge). Daemon reused WireGuard’s discovered fwmark from `ip rule`; that mark often means **split-tunnel bypass**, so marked packets followed **`main`** → **`wlp`**, not the tunnel.

- **Fix:** Tun upstream sockets use only **`ensure_route_mark(RouteTarget::Tun)`** (managed `default dev <tun>` table). Removed heuristic fwmark discovery for Tun connects.

**Bug 11:** Two equally specific `Route` rules (e.g. demo tun + demo wifi rows) produced **non-deterministic** winners depending on SQLite iteration order.

- **Fix:** `resolve_action` compares `(specificity, action_rank, rule.id)`; greater `id` wins when the first two tie.

## Critical Data Structures

### Rule

```rust
struct Rule {
    pub id: String,                    // Unique identifier (user-set or UUID)
    pub enabled: bool,
    pub action: RuleAction,            // Allow | Deny | Ask
    pub duration: RuleDuration,        // UntilRestart | Permanent
    pub process_name: Option<String>,  // Process name matcher (e.g., "firefox", "ssh")
    pub destination: DestinationMatcher, // IpExact | Cidr | DomainExact | DomainWildcard | Any
}
```

### PendingDecision

```rust
struct PendingDecision {
    pub id: String,              // Unique ID
    pub flow: FlowContext,       // The intercepted flow
    pub created_at_secs: u64,    // Timestamp
    pub deadline_at_secs: u64,   // Timeout timestamp (created + timeout_secs)
}
```

### FlowContext

```rust
struct FlowContext {
    pub process_name: Option<String>,      // e.g., "firefox"
    pub destination_ip: String,            // e.g., "142.251.33.46"
    pub destination_port: u16,             // e.g., 443
    pub destination_domain: Option<String>, // e.g., "google.com" (from DNS or SNI)
    pub protocol: TransportProtocol,       // Tcp | Udp | Quic | Other
    pub direction: FlowDirection,          // Outbound | Inbound
    pub device_label: Option<String>,      // e.g., "vpn-work" (gateway device label)
}
```

## Database Schema

### rules table

```sql
CREATE TABLE rules (
    id TEXT PRIMARY KEY,
    enabled BOOLEAN NOT NULL,
    action TEXT NOT NULL,        -- 'Allow', 'Deny', 'Ask'
    duration TEXT NOT NULL,      -- 'UntilRestart', 'Permanent'
    process_name TEXT,
    destination_type TEXT NOT NULL,  -- 'IpExact', 'Cidr', 'DomainExact', 'DomainWildcard'
    destination_value TEXT NOT NULL, -- The actual IP/domain/CIDR
    created_at_secs INTEGER NOT NULL,
    updated_at_secs INTEGER NOT NULL
);
```

### flow_events table

```sql
CREATE TABLE flow_events (
    id TEXT PRIMARY KEY,
    process_name TEXT,
    device_label TEXT,
    destination_ip TEXT NOT NULL,
    destination_domain TEXT,
    protocol TEXT NOT NULL,      -- 'Tcp', 'Udp', 'Quic', 'Other'
    state TEXT NOT NULL,         -- 'Pending', 'Allowed', 'Denied', 'Expired'
    timestamp_secs INTEGER NOT NULL
);
```

### pending_decisions table

```sql
CREATE TABLE pending_decisions (
    id TEXT PRIMARY KEY,
    flow_id TEXT NOT NULL,       -- Reference to flow context
    created_at_secs INTEGER NOT NULL,
    deadline_at_secs INTEGER NOT NULL
);
```

## Test Coverage

| Crate | Tests | Key Coverage |
|-------|-------|--------------|
| policy-engine | 6 | Matching, precedence, disabled rules |
| decision-engine | 8 | Pending lifecycle, timeout, overflow |
| flow-classifier | 7 | Process/domain attribution |
| enforcer | 8 | Packet parsing, verdict paths |
| state-store | 8 | CRUD, persistence |
| control-api | 5 | Request validation |
| control-service | 12 | RPC handlers, pending lifecycle |
| cli | 17 | Command parsing, output formatting |
| **Total** | **77** | |

## CLI Commands

All commands support `--json` flag for structured output.

### Rule Management

```bash
logiguard add-rule --action Allow --duration Permanent --process firefox 8.8.8.8
logiguard add-rule --action Deny 1.1.1.1/24
logiguard list-rules --json
logiguard delete-rule my-rule-id
```

### Decision Management

```bash
logiguard list-pendings
logiguard resolve-pending pending-123 allow
logiguard resolve-pending pending-123 deny
```

### System

```bash
logiguard health
logiguard show-config --json   # Detailed config + timeouts
logiguard unlock               # Console-only recovery
```

## Environment Variables

Currently used by the daemon (see also `apps/daemon/src/main.rs`):

- `LOGIGUARD_SOCKET_PATH` — Unix socket path (default `/tmp/logiguard.sock`)
- `LOGIGUARD_DB_PATH` — SQLite DB location (default `/tmp/logiguard.db`)
- `LOGIGUARD_NFQUEUE` — NFQUEUE number when packet interception enabled (optional)
- `LOGIGUARD_DEFAULT_TIMEOUT_SECS` — Default pending timeout (default 100)
- `LOGIGUARD_TCP_TIMEOUT_SECS`, `LOGIGUARD_UDP_TIMEOUT_SECS`, `LOGIGUARD_QUIC_TIMEOUT_SECS`, `LOGIGUARD_OTHER_TIMEOUT_SECS` — protocol overrides (fall back to default timeout when unset)
- `LOGIGUARD_DEVICE_ROUTE_FALLBACK` — set to `1`/`true`/`yes` to allow routed device path to fall back to plain connect after failure (diagnostics only; weakens strict routing)

## Next Steps (Priority Order)

### Immediate (Session 5+)

1. **DNS Snoop Cache:** Intercept plaintext DNS responses (UDP src port 53) to populate an ip→domain cache for UDP/QUIC flows where SNI is unavailable.
   - Affects: flow-classifier crate (new `DnsSnoopCache` impl of `DnsResolver`), enforcer crate (detect + parse DNS response packets)
   - Tests: 2-3 DNS parsing tests, 1 cache lookup test
   - Risk: Medium — race condition possible (first UDP packet may arrive before DNS response processed); DoH traffic is invisible

3. **Phase 2 Integration Tests:** Test entire flow (unknown flow → pending → timeout → denied) with real NFQUEUE.
   - Requires: Linux kernel NFQUEUE support
   - Affects: enforcer crate
   - Tests: 5-8 end-to-end tests
   - Risk: Medium (kernel dependency, may need VM)

### Medium-Term (Session 6+)

4. **Boot Gate:** Implement nftables rule that blocks all traffic until daemon health endpoint returns ready=true.
   - Affects: enforcer, daemon
   - Tests: 1 boot gate integration test
   - Risk: Medium (kernel safety)

5. **Config File Support:** Allow TOML/YAML config instead of env vars only.
   - Affects: daemon, control-api
   - Tests: 2-3 config parsing tests
   - Risk: Low

### Phase 5 (Later)

6. **Systemd User Service Unit:** Package daemon as user-installable systemd service.
   - Risk: Low
   - Affects: packaging, not core logic

7. **Web UI:** GPUI app covers desktop. Web UI for remote/admin access (stretch goal).

## Known Limitations

1. **ProcessResolver on high-churn systems:** `/proc/*/fd` scan is O(processes×fds). Adequate for desktop use; would need an inode→pid index for server-scale traffic.

2. **SNI — TCP/HTTPS only:** TLS ClientHello SNI extraction works for TCP. QUIC encrypts its Initial packets in newer versions; SNI hint is None for QUIC flows. DNS snoop cache (not yet implemented) would fill this gap.

3. **No DNS Snoop Cache:** For UDP/QUIC flows the destination shows as IP-only. Plaintext DNS response interception would provide domain hints, but DoH traffic is invisible to this approach.

4. **Queue Overflow Policy:** Hardcoded to deny on overflow. User cannot change at runtime (only via env var).

5. **Boot Gate:** Not implemented. Traffic not blocked until daemon ready. Potential security window.

6. **No Rate Limiting:** User can spam requests, pending queue could grow unchecked (mitigated by 100-item cap).

7. **No Audit Syslog:** Flow decisions not logged to syslog. Only in-memory + SQLite.

8. **Per-egress DNS in UI:** DNS servers are persisted and can be edited manually in SQLite, but GPUI DNS management views are not yet implemented.

## Build and Run

### Build All Crates

```bash
cargo build --all
```

### Run Tests

```bash
cargo test --all
```

### Run Daemon (Requires root)

```bash
LOGIGUARD_DB_PATH=/var/lib/logiguard/db.sqlite \
LOGIGUARD_NFQUEUE=0 \
  sudo ./target/debug/logiguard-daemon
```

### Run CLI

```bash
./target/debug/logiguard list-rules
./target/debug/logiguard add-rule --action Allow --process firefox 8.8.8.8
./target/debug/logiguard resolve-pending my-pending-id allow
```

### Run GPUI App

```bash
# Monitor mode (default): polls daemon, spawns dialog per pending
./target/debug/logiguard-gpui

# Single decision mode: show one pending and exit
./target/debug/logiguard-gpui --pending-id <pending-id>
```

## CI/CD Status

### Current

- Workspace compiles without warnings
- 93 tests passing
- No CI pipeline set up yet

### Planned

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Coverage thresholds: policy/decision ≥95%, rest ≥85%

## Key Metrics

- **Lines of code (Rust):** ~6,000 (crates + apps)
- **Test code:** ~2,500 (unit + integration)
- **Test count:** 77 passing
- **Crates:** 7 (core, policy, decision, flow, enforcer, state, control)
- **Apps:** 3 (daemon, CLI, GPUI)
- **Database tables:** 6 (rules, flow_events, pending_decisions, egresses, egress_targets, egress_dns_servers, proxies)
- **Unix socket path:** `/tmp/logiguard.sock`
- **Default timeouts:** 100s (default), 5s (UDP/QUIC), 3s (other)
- **Queue cap:** 100 pending decisions
- **GPUI components:** Table (TableDelegate), Dialog, TabBar, Button, Checkbox, Root

## Conclusion

LogiGuard is feature-complete for MVP (Phase 1-4). Core logic tested extensively. Settings window uses gpui-component Table and Dialog for data management. Proxy support fully implemented across all crates. Enforcement path fully wired: real ProcessResolver reads `/proc`, TLS SNI extraction populates destination domain. Ready for Phase 2 integration testing and real-world deployment.
