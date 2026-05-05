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
- `logiguard-ui` (GPUI app, phase 2)
  - Rich decision dialog
  - Rule editor
  - Pending queue and history views

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
- `apps/daemon`
  - Systemd-ready daemon binary
- `apps/cli`
  - Operator/user command-line interface
- `apps/gpui`
  - Desktop GUI

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

- [ ] unknown flow creates pending decision
- [ ] pending decision resolved by user allow
- [ ] pending decision resolved by user deny
- [ ] pending timeout -> auto-deny at 100s default
- [ ] custom timeout respected
- [ ] queue cap at 100 enforced
- [ ] queue overflow default -> deny new flow
- [ ] overflow policy configurable
- [ ] until-restart decision expires on restart
- [ ] permanent decision persists
- [ ] protocol-specific pending behavior (TCP vs UDP/QUIC) follows configured policy
- [ ] pending countdown/deadline metadata surfaced for UI/CLI

## 6.3 `flow-classifier`

- [ ] host process attribution success
- [ ] host process attribution missing fallback behavior
- [ ] DNS-derived domain association positive
- [ ] SNI-derived domain association positive
- [ ] DNS/SNI conflict -> IP-only classification
- [ ] QUIC best-effort domain inference fallback to IP/CIDR
- [ ] gateway flow device label attachment

## 6.4 `enforcer`

- [ ] nftables programming success path
- [ ] nftables apply failure handled fail-close
- [ ] NFQUEUE message parsing valid packet
- [ ] invalid queue packet safely denied
- [ ] verdict commit allow path
- [ ] verdict commit deny path
- [ ] daemon-not-ready blocks traffic (boot gate)

## 6.5 `state-store`

- [ ] migration bootstrap on empty DB
- [ ] rule insert/read/update/delete
- [ ] flow event append/read
- [ ] pending decision persistence
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

- [ ] Implement nftables bootstrap and health gate
- [ ] Integrate queue packet ingestion
- [ ] Connect decision engine to verdict sink
- [ ] Add integration tests for allow/deny/pending timeout

## Phase 3: Persistence + CLI

- [ ] SQLite migrations and repositories
- [ ] CLI for rules and pending decisions
- [ ] Recovery command (console-only)
- [ ] Persistence and restart behavior tests

## Phase 4: GPUI Interface

- [ ] Build pending decisions view
- [ ] Build decision dialog with scope options
- [ ] Build rule management views
- [ ] Connect UI to local control API

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

## 11) Definition of Done (MVP)

- [ ] Unknown flows are held, surfaced to user, and default-denied after timeout
- [ ] Rules for app/domain/wildcard/IP/CIDR work with precedence guarantees
- [ ] Fail-close behavior enforced at boot and runtime failures
- [ ] CLI supports operational flow for decisions and rules
- [ ] Unit tests implemented for each core unit listed in this document
- [ ] Integration tests pass for end-to-end critical paths
- [ ] CI gates pass on main branch
