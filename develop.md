# LogiGuard Development Plan and Progress

## 1) Product Scope (Locked)

- Platform: Linux desktop first
- Language: Rust
- UI: GPUI + gpui-component
- Service model: local-only, root systemd daemon
- Security posture: fail-close
- Interactive behavior:
  - Unknown flow -> hold and ask user
  - Default timeout -> auto-deny after 100s (configurable)
  - Pending queue cap -> 100
  - Queue overflow default -> auto-deny (configurable)
- Rules:
  - App/process
  - Domain
  - Subdomain
  - Wildcard domain pattern (e.g. `*.example.com`)
  - IP
  - CIDR/netmask
  - Wildcard does not match apex by default (`*.example.com` != `example.com`)
  - Optional route target (e.g. specific TUN or network device)
- Protocol coverage in v1:
  - TCP + UDP
  - Best-effort domain inference for QUIC/HTTP3
  - On DNS/SNI conflict, treat as IP-only
- Rule duration:
  - Quick action default: until restart
  - Permanent rules available only by explicit user choice
- Non-host device identity in v1:
  - Manual device labels
- Storage:
  - SQLite
- Recovery:
  - Physical-console-only emergency unlock
  - Boot sequence blocks traffic until daemon healthy

## 2) Core Architecture

### 2.1 Runtime Components

- `logiguardd` (root daemon)
  - Owns netfilter/nftables programming
  - Owns pending decision queue
  - Owns enforcement cache and fail-close gates
  - Exposes local Unix socket API
- `logiguard-cli`
  - Rule CRUD
  - Pending decision actions
  - Health/recovery commands
- `logiguard-gpui` (GPUI app, phase 4)
  - Decision dialog with Material Design 3 dark theme
  - Segmented pill scope toggle (THIS SESSION / PERMANENTLY)
  - Countdown timer with auto-deny
  - Monitor mode: polls daemon, spawns dialog per pending

### 2.2 Suggested Rust Workspace

- `crates/core-types`
  - Shared data models and errors
- `crates/policy-engine`
  - Rule match and precedence logic
- `crates/flow-classifier`
  - Process/device identity + DNS/SNI attribution
- `crates/decision-engine`
  - `allow/deny/ask` with pending and timeout state machine
- `crates/enforcer`
  - nftables/NFQUEUE integration + kernel verdict bridge
- `crates/state-store`
  - SQLite repositories, migrations, journaling
- `crates/control-api`
  - Unix socket protocol + request/response schema
  - Bidirectional push notifications via Tokio broadcast
- `apps/daemon`
  - Systemd-ready daemon binary
- `apps/cli`
  - Operator/user command-line interface
- `apps/gpui`
  - Desktop GUI with real-time push subscription

### 2.3 Daemon-UI Communication Protocol

**Architecture:** Bidirectional Unix socket with Tokio broadcast channel for real-time push notifications.

**Broadcast Channel:**
- Buffer size: 500 notifications (holds pending decisions until timeout)
- In-memory only (no persistence across restart needed)
- Auto-drops messages when pending decisions expire (5-100s window)

**Protocol Flow:**

1. **Client Subscription (GPUI startup):**
   ```
   GPUI: send ControlRequest::SubscribeToPending
   Daemon: respond with ControlResponse::SubscriptionAck
   GPUI: receive buffered PushNotifications from channel
   ```

2. **Real-time Notifications (when pending changes):**
   ```
   Daemon: send PushNotification::PendingCreated { decision }
   Daemon: send PushNotification::PendingResolved { pending_id, action }
   Daemon: send PushNotification::PendingExpired { pending_id }
   GPUI: receive immediately (or from buffer if reconnected)
   ```

3. **Request-Response (existing, unchanged):**
   ```
   GPUI: send ControlRequest::ListPending (fallback, optional periodic)
   Daemon: respond with ControlResponse::PendingList
   ```

**Message Types (New):**
```rust
enum PushNotification {
  PendingCreated { decision: PendingDecision },
  PendingResolved { pending_id: String, action: RuleAction },
  PendingExpired { pending_id: String },
}
```

**Guarantees:**
- Real-time delivery (<1ms latency when GPUI connected)
- Buffered delivery (up to 500 notifications) if GPUI temporarily offline
- No loss of pending notifications until timeout expires
- No persistence across daemon restart (acceptable: pending decisions in SQLite as source of truth)

## 3) Data Model (MVP)

### 3.1 Rule

- `id`
- `enabled`
- `action` (`Allow | Deny | Ask`)
- `scope`:
  - process matcher (name/path/uid)
  - domain exact
  - domain wildcard
  - ip exact
  - cidr
  - protocol/port optional
  - optional route target identifier (e.g. `tun0`, `vpn-work`, `eth1`)
- `duration` (`UntilRestart | Permanent`)
- `priority` (derived from specificity + explicit tie-break)
- `created_at`, `updated_at`

### 3.2 Flow

- `flow_id` (stable tuple key)
- source/destination IP + port + protocol
- process metadata (host traffic)
- device label metadata (gateway traffic)
- dns hints, sni hints, confidence
- first_seen, last_seen
- state (`Pending | Allowed | Denied | Expired`)

### 3.3 Pending Decision

- `pending_id`
- `flow_id`
- created_at
- deadline_at (`created + timeout`)
- snapshot context for UI/CLI prompt
- default fallback action (`Deny`)

## 4) Rule Resolution and Precedence

- Action precedence: `Deny > Allow > Ask`
- Specificity precedence (high -> low):
  1. process + exact IP/host
  2. process + CIDR/domain wildcard
  3. exact IP/host
  4. CIDR/domain wildcard
  5. global/default
- Wildcard rule semantics:
  - `*.example.com` matches only subdomains
  - apex must be explicit `example.com`
- DNS/SNI conflict:
  - discard domain inference
  - evaluate flow as IP-only

## 4.1 In-Flight Hold Behavior (Ask Mode)

- Goal:
  - Keep new unmatched flows pending until user decision when feasible.
- Default behavior:
  - First packets of unknown flow enter pending state.
  - User is prompted with countdown.
  - No decision before deadline => auto-deny (default 100s, configurable).
- Protocol expectations:
  - TCP:
    - Best support for pending decision on connection setup packets.
    - Long waits can still fail if application-level timeout is shorter than decision window.
  - UDP:
    - Best-effort hold only; no connection state guarantees.
    - Time-sensitive traffic may fail while pending.
  - QUIC/HTTP3:
    - Treated as UDP with best-effort hold.
    - Domain attribution can be uncertain; fallback to IP/CIDR logic.
- Queue safety:
  - Maximum pending count: 100 (configurable).
  - On queue overflow: default auto-deny for new unmatched flows (configurable).
- Reliability constraints:
  - "No breakage" is not guaranteed for all applications/protocols when user delays decisions.
  - UX must emphasize countdown and default action to avoid silent stalls.

## 5) Testability Strategy (Non-Negotiable)

- Every unit is testable in isolation
- All OS/system effects behind traits
- No rule logic coupled to netfilter code
- Deterministic time via `Clock` trait
- Deterministic persistence tests with temp SQLite DB

### 5.1 Core Traits for Dependency Injection

- `PacketSource`
- `VerdictSink`
- `RuleRepository`
- `FlowRepository`
- `Clock`
- `Notifier`
- `ProcessResolver`
- `DnsSniResolver`

## 6) Unit Test Matrix (Create Tests for Each Unit)

## 6.1 `policy-engine`

- [ ] exact IP match
- [ ] CIDR match positive/negative cases
- [ ] exact domain match
- [ ] wildcard subdomain match
- [ ] wildcard does not match apex
- [ ] process + destination combined match
- [ ] precedence: specific beats general
- [ ] action precedence: deny beats allow for same specificity
- [ ] disabled rule ignored
- [ ] invalid rule rejected by validator

## 6.2 `decision-engine`

- [x] unknown flow creates pending decision
- [x] pending decision resolved by user allow
- [x] pending decision resolved by user deny
- [x] pending timeout -> auto-deny at 100s default
- [x] custom timeout respected
- [x] queue cap at 100 enforced
- [x] queue overflow default -> deny new flow
- [x] overflow policy configurable
- [x] until-restart decision expires on restart
- [ ] permanent decision persists
- [x] protocol-specific pending behavior (TCP vs UDP/QUIC) follows configured policy
- [x] pending countdown/deadline metadata surfaced for UI/CLI

## 6.3 `flow-classifier`

- [x] host process attribution success
- [x] host process attribution missing fallback behavior
- [x] DNS-derived domain association positive
- [x] SNI-derived domain association positive
- [x] DNS/SNI conflict -> IP-only classification
- [x] QUIC best-effort domain inference fallback to IP/CIDR
- [x] gateway flow device label attachment

## 6.4 `enforcer`

- [x] nftables programming success path (SystemNftablesBootstrap + FakeBootstrap)
- [x] nftables apply failure handled fail-close (FakeBootstrap fail=true)
- [x] NFQUEUE message parsing valid packet (parse_raw_packet IPv4/TCP/UDP)
- [x] invalid queue packet safely denied (malformed payload returns None → Drop)
- [x] verdict commit allow path (PacketProcessor allow test)
- [x] verdict commit deny path (PacketProcessor deny test)
- [ ] daemon-not-ready blocks traffic (boot gate)

## 6.5 `state-store`

- [ ] migration bootstrap on empty DB
- [x] rule insert/read/update/delete
- [x] flow event append/read
- [x] pending decision persistence
- [ ] transaction rollback on failure
- [ ] concurrent access behavior

## 6.6 `control-api` and `cli`

- [ ] local socket auth/permission checks
- [ ] add/list/delete rules command flow
- [ ] resolve pending decision command flow
- [ ] health status command output contract
- [ ] malformed request handling

## 6.7 recovery and fail-close behavior

- [ ] boot blocks network until daemon healthy
- [ ] daemon crash keeps fail-close policy
- [ ] physical-console unlock command path
- [ ] unlock denied from non-console context

## 7) Integration Test Matrix

- [ ] flow with matching allow rule passes
- [ ] flow with matching deny rule blocked
- [ ] unknown flow prompts and pauses
- [ ] unknown flow timeout denies
- [ ] TCP pending flow accepted before deadline continues successfully
- [ ] UDP/QUIC pending flow behavior follows best-effort policy and timeout fallback
- [ ] rule creation from decision path works
- [ ] restart preserves permanent rules only
- [ ] conflict domain/IP behavior follows IP-only policy
- [ ] queue overflow scenario follows configured policy
- [ ] fail-close boot gate enforced in startup race

## 8) CI Quality Gates

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] coverage threshold:
  - policy and decision crates: >= 95%
  - rest of workspace: >= 85%

## 9) Implementation Phases

## Phase 0: Foundation

- [ ] Create Rust workspace and crate skeleton
- [ ] Define `core-types` schema
- [ ] Add trait interfaces and test fakes
- [ ] Add CI pipeline for fmt/clippy/test

## Phase 1: Policy + Decision Core

- [ ] Implement rule parser/validator
- [ ] Implement matcher and precedence
- [ ] Implement pending queue + timeout state machine
- [ ] Pass full unit suite for policy/decision crates

## Phase 2: Enforcement Path

- [x] Implement nftables bootstrap and health gate
- [x] Integrate queue packet ingestion
- [x] Connect decision engine to verdict sink
- [ ] Add integration tests for allow/deny/pending timeout

## Phase 3: Persistence + CLI

- [ ] SQLite migrations and repositories
- [ ] CLI for rules and pending decisions
- [ ] Recovery command (console-only)
- [ ] Persistence and restart behavior tests

## Phase 4: GPUI Interface

- [x] Build pending decisions view
- [x] Build decision dialog with scope options (segmented pill: THIS SESSION / PERMANENTLY)
- [x] Material Design 3 dark theme matching HTML design spec
- [x] Grid layout flow info with colored badges
- [x] Custom outlined action buttons (ALLOW/DENY) with icons
- [x] Circular countdown ring with auto-deny label
- [x] Status bar footer
- [x] 1-second countdown ticker with auto-exit
- [x] Monitor mode: polls daemon, spawns GUI per pending
- [x] Connect UI to local control API via Unix socket
- [ ] Build rule management views (future)

## 10) Progress Log

Use this section as a running journal. Keep entries short and dated.

### 2026-05-05

- [x] Requirements clarified and locked
- [x] Architecture and test strategy drafted
- [x] Initial development tracker created (`develop.md`)
- [x] Rust workspace skeleton created (manual scaffold)
- [x] `core-types`, `policy-engine`, `decision-engine` crates added
- [x] Initial unit tests added for wildcard matching, precedence, queue overflow, and timeout expiry
- [x] Toolchain pinned with `rust-toolchain.toml` (stable + clippy + rustfmt)
- [x] Added `justfile` for fmt/lint/test/check/ci and run commands
- [x] Scaffolded `state-store` and `control-api` with initial unit tests
- [x] Implemented initial CLI commands (`add-rule`, `list-rules`, `delete-rule`) with tests
- [x] Added `control-service` daemon-side request handler with pending decision lifecycle tests
- [x] Wired CLI through `control-service` and added `register-flow`/`resolve-pending` command parsing tests
- [x] Added Unix socket JSON transport between daemon and CLI (`/tmp/logiguard.sock`)
- [x] Added SQLite-backed `RuleRepository` and wired daemon persistence (`LOGIGUARD_DB_PATH`)
- [x] Added protocol metadata (`TCP/UDP/QUIC/Other`) to flows and pending decision responses
- [x] Added protocol-specific pending timeout policy support in `decision-engine`
- [x] Wired daemon env-based protocol timeout configuration into `ControlService`
- [x] Extended health response to expose active pending/timeout runtime configuration
- [x] Added `show-config` CLI command with JSON health/config output for scripting
- [x] Added global `--json` CLI output mode for structured command responses
- [x] Added SOCKS5 emulator app for proxy-based testing without system-wide interception
- [x] Added pending polling API (`AwaitPendingDecision`) and wait-state response
- [x] Added CLI pending introspection command (`list-pendings`)
- [x] Implemented emulator wait-until-decision behavior for pending flows
- [x] Added integration tests for both immediate-allow relay and pending-then-allow relay
- [x] Added `enforcer` crate skeleton with dry-run mark allocation and verdict sink tests

### 2026-05-06 (session 2)

- [x] Added `flow-classifier` crate with `ProcessResolver`, `DnsResolver`, `DeviceLabelResolver` traits and `FlowClassifier`
- [x] Added `Classifier` trait to `flow-classifier` for use by `PacketProcessor`
- [x] Extended `FlowContext` with `device_label: Option<String>` across all construction sites
- [x] Added `FlowRegistrar` trait + `FlowDecision` enum to `enforcer` crate
- [x] Added `PacketProcessor<PS, C, VS, FR>` — wires source → classifier → registrar → sink
- [x] Implemented `FlowRegistrar` for `ControlService` and `SharedService<R>` (Arc<Mutex> wrapper)
- [x] Added `NftablesBootstrap` trait + `SystemNftablesBootstrap` (shells to `nft -f -`)
- [x] Added `NfqueueProcessor` using pure-Rust `nfq` crate (no libnetfilter_queue required)
- [x] Added `parse_raw_packet` with IPv4/IPv6, TCP/UDP, and best-effort QUIC detection
- [x] Wired nfqueue processor into daemon via `LOGIGUARD_NFQUEUE=<queue_num>` env var
- [x] 74 tests passing across workspace

### 2026-05-06 (session 3)

- [x] Fixed Bug 1: `expire_timeouts()` now called every second via daemon timer thread (`ControlService::tick`)
- [x] Fixed Bug 2: `purge_session_rules()` added to `RuleRepository`; daemon deletes `UntilRestart` rules on every startup
- [x] Fixed Bug 3: CLI `add-rule` extended with `--action`, `--duration`, `--process` flags; destination type auto-detected (`*.x` → DomainWildcard, `/` → Cidr, IP → IpExact, else DomainExact)
- [x] Fixed Bug 4: `FlowEvent`/`FlowState` types added; `FlowRepository` trait + SQLite impl; `list-flows [--limit N]` CLI command; flow events recorded on every verdict
- [x] Fixed Bug 5: `PendingRepository` trait + SQLite impl; pending decisions persisted on register, deleted on resolve/expire; restored on daemon startup via `restore_pending()`
- [x] Fixed Bug 6: `unlock` CLI command added; daemon checks SO_PEERCRED + `/proc/<pid>/fd/0` to require physical console; tears down nftables on success
- [x] `NftablesBootstrap` made `Send + Sync`; `FakeBootstrap` switched from `Cell<u32>` to `AtomicU32`
- [x] `ControlService` now generic over `Repository` supertrait (Rule + Flow + Pending)
- [x] 93 tests passing across workspace

### 2026-05-06 (session 4)

- [x] Added `logiguard-gpui` GPUI app with `gpui = "0.2"` + `gpui-component = "0.5"` from crates.io
- [x] Implemented `AppState` entity holding pending decisions + daemon connection status + make-permanent checkbox
- [x] Implemented `DecisionApp` root view with reactive re-render via `cx.observe()`
- [x] Background polling task: `ListPending` every 1s via `cx.background_executor().spawn()` (non-blocking)
- [x] Decision card: amber header with countdown, APPLICATION section, DESTINATION section, "Remember" checkbox, DENY/ALLOW footer
- [x] Allow action optionally creates `Permanent` rule via `AddRule` when "Remember" checkbox is checked
- [x] Deep Slate dark theme applied via `Theme::change(ThemeMode::Dark, None, cx)`
- [x] 93 workspace tests still passing

### 2026-05-07/08 (session 8)

- [x] Redesigned GPUI decision dialog to match Material Design 3 dark theme from `design/decision_dialog_window.html`
- [x] Replaced ad-hoc color palette with Material Design 3 dark theme colors (`#081425` bg, `#adc6ff` primary, etc.)
- [x] Redesigned header: security shield icon, "CONNECTION INTERCEPTED" title, circular countdown ring, red "AUTO-DENY" label on `surface-container-high` background
- [x] Redesigned flow info: grid layout (label/value columns) with colored badges (teal protocol chip, bordered IP/direction chips)
- [x] Replaced "Remember" checkbox with segmented pill toggle for scope selection (THIS SESSION / PERMANENTLY)
- [x] Replaced filled `gpui-component` buttons with custom outlined buttons (green border ALLOW, error border DENY) with shield/prohibited icons
- [x] Added status bar footer with centered LogiGuard branding and queue status
- [x] Added 1-second countdown ticker in `DecisionApp::new()` using `cx.spawn()` with `AsyncWindowContext`; auto-exits on timeout
- [x] Reduced window size to 420x488 to fit content without excess space
- [x] Added monitor mode: polls daemon every 1s, spawns GUI window per new pending decision (`--pending-id` for single-decision mode)
- [x] Fixed deny button: now creates permanent rule when PERMANENTLY scope selected (was missing `AddRule` call)
- [x] Fixed session scope: both THIS SESSION and PERMANENTLY now create rules; THIS SESSION uses `UntilRestart` duration, PERMANENTLY uses `Permanent`
- [x] Added `components/status_bar.rs` module
- [x] Updated docs: `architecture.md`, `implementation-status.md`, `gpui-components.md`, `gpui-api.md`
- [x] Added `design/` folder with HTML design reference (`decision_dialog_window.html`)
- [x] 93 workspace tests still passing

### 2026-05-06 (session 5)

- [x] Window lifecycle: Check if pending decisions exist before opening window
- [x] Window closes (app exits cleanly) when decision queue becomes empty
- [x] Initial check done synchronously before Application::new().run()
- [x] Polling task monitors queue state and calls std::process::exit(0) when empty
- [x] All 78 workspace tests passing with updated GPUI app
- [x] Wrote comprehensive documentation: GPUI guide, gpui-component guide, Unix sockets, async patterns, architecture

### 2026-05-06 (session 6)

- [x] Refactored window lifecycle: App always runs, window shows/hides based on pending state
- [x] Added `should_show_window` flag to AppState (default false)
- [x] Window displays "Connecting..." until pending decisions arrive
- [x] When first pending decision received → window shows with decision dialog
- [x] When all decisions resolved → window returns to "Connecting..." state (stays open)
- [x] Polling task automatically triggers window display on pending arrival
- [x] No need to manually restart app when new decisions arrive
- [x] All 78 tests still passing

### 2026-05-06 (session 7)

- [x] Analyzed OpenSnitch architecture and rules model for comparison
- [x] Created comprehensive OPENSNITCH_COMPARISON.md document
- [x] Compared GUI-to-daemon communication strategies
- [x] Decided on bidirectional socket push using Tokio broadcast channel
- [ ] Extend `ControlRequest` enum with `SubscribeToPending`
- [ ] Add `PushNotification` enum to `core-types`
- [ ] Extend `ControlResponse` with push variants (or separate type)
- [ ] Add broadcast channel to `ControlService`
- [ ] Implement subscriber tracking in daemon connection handler
- [ ] Modify daemon socket reader to handle `tokio::select!` for requests + pushes
- [ ] Modify GPUI to subscribe on startup and handle incoming push notifications
- [ ] Remove 1-second polling loop from GPUI (use push instead)
- [ ] Add tests for push notification lifecycle
- [ ] Verify 93 tests still passing

## 11) Definition of Done (MVP)

- [ ] Unknown flows are held, surfaced to user, and default-denied after timeout
- [ ] Rules for app/domain/wildcard/IP/CIDR work with precedence guarantees
- [ ] Fail-close behavior enforced at boot and runtime failures
- [ ] CLI supports operational flow for decisions and rules
- [ ] Unit tests implemented for each core unit listed in this document
- [ ] Integration tests pass for end-to-end critical paths
- [ ] CI gates pass on main branch
