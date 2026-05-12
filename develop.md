# LogiGuard Development Guide

## Documentation Reference Rules

Read the relevant doc **before** writing code in that area. These docs record learned patterns, gotchas, and decisions not obvious from code.

| Area | Read first |
|---|---|
| Any GPUI UI code | [`docs/gpui-components.md`](docs/gpui-components.md) — import paths, h_flex/v_flex/Label rules, ds.rs design system |
| Settings dialogs/tables | [`docs/gpui-settings.md`](docs/gpui-settings.md) — Table/Dialog/delegate patterns, form patterns |
| NFQUEUE / packet interception | [`docs/nfqueue-packet-interception.md`](docs/nfqueue-packet-interception.md) — queue lifecycle, verdicts, gotchas |
| Domain inference (SNI/DNS) | [`docs/nfqueue-domain-inference.md`](docs/nfqueue-domain-inference.md) — SNI timing, TLS wire format |
| Process resolution | [`docs/process-resolver.md`](docs/process-resolver.md) — /proc lookup chain, byte encoding, per-socket cache |
| Proc-attribution races / dedup / policy fallback | [`docs/process-attribution-races.md`](docs/process-attribution-races.md) — the three layers that keep duplicate dialogs from leaking out |
| Architecture / crate boundaries | [`docs/architecture.md`](docs/architecture.md) — components, data flow, design decisions |
| GPUI async / entity model | [`docs/gpui-async.md`](docs/gpui-async.md) — spawn, background_executor, WeakEntity |
| Unix socket protocol | [`docs/unix-sockets.md`](docs/unix-sockets.md) — framing, JSON-lines, request/response schema |
| Testing strategy / test matrices | [`docs/testing.md`](docs/testing.md) — traits, unit/integration matrices, CI gates |

**Rules:**
1. **Read before writing** — If a relevant doc exists, read it before writing implementation code.
2. **Update docs when you learn something new** — Import quirk, layout pattern, gotcha → add it to the doc in the same session.
3. **Docs take precedence over intuition** — If a doc says "use `h_flex()` not `div().flex()`", follow the doc.
4. **Unresolved import? Check the export map first** — See `docs/gpui-components.md` → Export Map before grepping crate source.
5. **Design-system atoms → `ds.rs` + docs** — Check `docs/gpui-components.md § Design-System Layer` and `apps/gpui/src/components/ds.rs` before writing any inline chip/badge/picker.

---

## UI / GPUI Component Guidelines

> **Core principle: don't reinvent the wheel.**
> `gpui-component` already implements labels, inputs, buttons, tables, dialogs, tabs, and layout containers.
> Use them. Reach for `div()` only when no library component fits.

### Use the library — not raw divs

| Need | Use | Never |
|---|---|---|
| Text / label | `gpui_component::label::Label` | `div().child("text")` |
| Row layout | `h_flex()` from `gpui_component` | `div().flex().flex_row()` |
| Column layout | `v_flex()` from `gpui_component` | `div().flex().flex_col()` |
| Button | `gpui_component::button::Button` | custom `div().on_click(...)` |
| Text input | `gpui_component::input::TextInput` | custom `div` with key handler |
| Table rows | `TableDelegate` + `h_flex()` root in `render_td` | raw nested divs |
| Modal/dialog | `window.open_dialog(...)` via `WindowExt` | overlay div stack |
| Color | `crate::colors::*` | `gpui::rgb(0x...)` / hex literals |

### Project design-system layer (`components/ds.rs`)

For atoms not covered by gpui-component, use the project's own design-system layer. Check it before writing anything inline.

| Need | Use |
|---|---|
| Read-only colored pill | `ds::badge(text, color)` |
| Interactive toggle chip | `ds::chip(id, label, selected, on_click)` |
| Destination human text | `ds::dest_text(dest)` |
| IP/CIDR scope picker | `ds::cidr_picker(ip, active_octets, state_weak)` |
| Label + content row | `ds::label_row("Label", content)` |

If a UI pattern appears in more than one place and is not in `ds.rs`, extract it there — don't duplicate it.

### Import paths (gpui-component does not re-export everything)

```rust
use gpui_component::h_flex;                    // layout
use gpui_component::v_flex;
use gpui_component::label::Label;              // NOT gpui_component::Label
use gpui_component::button::Button;            // NOT gpui_component::Button
use gpui_component::input::TextInput;
use gpui_component::table::{Column, TableDelegate, TableState};
```

See [`docs/gpui-components.md`](docs/gpui-components.md) → Export Map for the full list.

---

## 1) Product Scope (Locked)

- Platform: Linux desktop first
- Language: Rust
- UI: GPUI + gpui-component
- Service model: local-only, root systemd daemon
- Security posture: fail-close
- Interactive behavior:
  - Unknown flow → hold and ask user
  - Default timeout → auto-deny after 100s (configurable)
  - Pending queue cap → 100
  - Queue overflow default → auto-deny (configurable)
- Rules:
  - App/process, Domain, Subdomain, Wildcard domain (`*.example.com`)
  - IP, CIDR/netmask
  - Wildcard does not match apex by default
  - Optional route target (TUN, NIC, or proxy)
  - Optional per-egress DNS server list
  - Proxy support: SOCKS5, HTTP/HTTPS, Shadowsocks with per-type auth
  - Egress targets have priority ordering; first enabled target is active
- Protocol coverage in v1:
  - TCP + UDP, best-effort domain inference for QUIC/HTTP3
  - On DNS/SNI conflict, treat as IP-only
- Rule duration: quick action = until restart; permanent = explicit user choice
- Storage: SQLite
- Recovery: physical-console-only emergency unlock; boot blocks until daemon healthy

## 2) Core Architecture

See [`docs/architecture.md`](docs/architecture.md) for full component diagrams, crate descriptions, data flow, and design decisions.

### Crate Overview

| Crate | Role |
|---|---|
| `crates/core-types` | Shared types: Rule, FlowContext, PendingDecision, Egress, Proxy |
| `crates/policy-engine` | Rule matching and precedence |
| `crates/flow-classifier` | Process/device identity + DNS/SNI attribution |
| `crates/decision-engine` | Pending queue + timeout state machine |
| `crates/enforcer` | nftables + NFQUEUE integration + verdict bridge |
| `crates/state-store` | SQLite repositories and migrations |
| `crates/control-api` | Unix socket protocol schema |
| `apps/daemon` | `logiguardd` — root systemd daemon |
| `apps/cli` | `logiguard-cli` — operator interface |
| `apps/gpui` | `logiguard-gpui` — GPUI decision UI + tray + settings |

### Daemon–UI Communication

Bidirectional Unix socket at `/tmp/logiguard.sock`. JSON-lines transport. See [`docs/unix-sockets.md`](docs/unix-sockets.md).

### Data Model Summary

Full schema and field definitions are in [`docs/architecture.md`](docs/architecture.md) → Core Crates.

Key types: `Rule`, `FlowContext`, `PendingDecision`, `Egress`, `EgressTarget`, `ProxyConfig`, `DestinationMatcher`, `RuleAction`, `RuleDuration`.

### Rule Resolution

- Action precedence: `Deny > Allow > Ask`; `Allow` and `Route { .. }` share action rank
- Specificity (high → low): process+exact > process+wildcard > exact > wildcard > global
- Tie-break: lexicographically greater `rule.id` wins
- Wildcard: `*.example.com` matches subdomains only; apex must be explicit

## 3) Implementation Phases

### Phase 0: Foundation ✅
- Rust workspace + crate skeleton, core-types schema, trait interfaces, CI pipeline

### Phase 1: Policy + Decision Core ✅
- Rule matcher + precedence, pending queue + timeout state machine, full unit suite

### Phase 2: Enforcement Path ✅ (integration tests pending)
- nftables bootstrap + health gate, NFQUEUE packet ingestion, decision → verdict bridge
- [ ] Integration tests for allow/deny/pending timeout

### Phase 3: Persistence + CLI ✅
- SQLite migrations + repositories, CLI for rules + pending decisions, recovery command

### Phase 4: GPUI Interface (in progress)
- [x] Decision dialog with scope options (process + destination), design-system dark theme
- [x] Material Design 3 dark colors, countdown ring, status bar
- [x] Monitor mode: polls daemon, spawns dialog per pending
- [x] Connected to daemon via Unix socket
- [x] Settings window (Rules, Egress, Proxies tabs) using Table + Dialog components
- [x] Settings runs as separate process (close doesn't kill tray)
- [x] Modular `settings/` directory (mod.rs, rules_tab.rs, egress_tab.rs, proxies_tab.rs, helpers.rs)
- [x] Add/Edit Egress and Proxy form dialogs with custom modal header/footer
- [x] Design-system primitives in `components/ds.rs` (badge, chip, dest_text, cidr_picker, label_row)
- [x] Rule scope UI: process toggle, destination scope chips, CIDR octet picker, rule summary line
- [x] NFQUEUE enable/disable toggle via tray menu
- [ ] Auth fields in proxy form dialog (Basic / Shadowsocks)
- [ ] Egress priority ordering UI

## 4) Open Bugs / Follow-ups

- [x] **Settings window not resizable** — fixed since 2026-05-13 (session 21). Root view now wraps everything in `gpui_component::window_border()` so the resize edges + cursor change work on Linux compositors that use client-side decorations (notably GNOME / Mutter, which refuses xdg-decoration server-side requests). Also explicitly requests `WindowDecorations::Client` and sets `window_min_size = 640×420` so the user can't accidentally collapse the table headers.
- [x] **NFQUEUE tray toggle unreliable** — fixed since 2026-05-13 (session 21). The previous handler just flipped a status bit in `ControlService` and never touched the kernel; the toggle was a no-op. Now `SetNfqueueEnabled` re-applies the nftables protection chains via `NftablesBootstrap::setup(queue, route_mark_base)` — `Some(n)` adds `queue num n` rules, `None` removes them. The cached flag is only committed *after* nftables actually applied. Gate logic is in the pure `plan_nfqueue_toggle` helper with 4 new unit tests covering the (bootstrap present, queue configured, enabled requested) matrix, including the case where the daemon was started without `LOGIGUARD_NFQUEUE` (rejected with an actionable error pointing the operator at the systemd unit). Workspace 126 → 130 tests.
- [ ] **Tray toggle should be single item** — currently two separate enable/disable menu items; should be one checked/unchecked toggle
- [ ] **Add Egress / Add Proxy button styling** — full-width, doesn't match design spec

## 5) Definition of Done (MVP)

- [ ] Unknown flows held, surfaced to user, default-denied after timeout
- [ ] Rules for app/domain/wildcard/IP/CIDR work with precedence guarantees
- [ ] Fail-close behavior enforced at boot and runtime failures
- [ ] CLI supports operational flow for decisions and rules
- [ ] Unit tests for each core unit — see [`docs/testing.md`](docs/testing.md)
- [ ] Integration tests pass for end-to-end critical paths
- [ ] CI gates pass on main branch

---

## 6) Progress Log

### 2026-05-05
- [x] Requirements clarified and locked
- [x] Architecture and test strategy drafted
- [x] Rust workspace skeleton created
- [x] `core-types`, `policy-engine`, `decision-engine` crates + initial unit tests
- [x] Toolchain pinned (`rust-toolchain.toml`); `justfile` for fmt/lint/test
- [x] `state-store` and `control-api` scaffolded with initial unit tests
- [x] CLI commands (`add-rule`, `list-rules`, `delete-rule`) with tests
- [x] Unix socket JSON transport between daemon and CLI
- [x] SQLite-backed `RuleRepository`; protocol metadata; protocol-specific timeout policy
- [x] `show-config` CLI command; global `--json` mode
- [x] SOCKS5 emulator app for proxy testing
- [x] Pending polling API (`AwaitPendingDecision`); `list-pendings` CLI command
- [x] Integration tests for immediate-allow and pending-then-allow relay
- [x] `enforcer` crate skeleton with verdict sink tests

### 2026-05-06 (session 2)
- [x] `flow-classifier` crate: `ProcessResolver`, `DnsResolver`, `DeviceLabelResolver`, `FlowClassifier`
- [x] `PacketProcessor` wiring source → classifier → registrar → sink
- [x] `NftablesBootstrap` trait + `SystemNftablesBootstrap`
- [x] `NfqueueProcessor` using pure-Rust `nfq` crate (no libnetfilter_queue)
- [x] `parse_raw_packet`: IPv4/IPv6, TCP/UDP, best-effort QUIC detection
- [x] 74 tests passing

### 2026-05-06 (session 3)
- [x] Fixed: `expire_timeouts()` called every second via daemon timer thread
- [x] Fixed: `purge_session_rules()` deletes `UntilRestart` rules on startup
- [x] Fixed: CLI `add-rule` extended with `--action`, `--duration`, `--process` flags; destination type auto-detected
- [x] Fixed: `FlowRepository` + SQLite impl; `list-flows` CLI; flow events on every verdict
- [x] Fixed: `PendingRepository` + SQLite impl; persisted and restored on restart
- [x] Fixed: `unlock` CLI; SO_PEERCRED + `/proc/<pid>/fd/0` console check; nftables teardown
- [x] 93 tests passing

### 2026-05-06 (session 4)
- [x] `logiguard-gpui` GPUI app with `AppState`, `DecisionApp` root view, reactive re-render
- [x] Background polling task; decision card with countdown, scope toggle, ALLOW/DENY
- [x] Deep Slate dark theme

### 2026-05-06 (sessions 5–7)
- [x] Window lifecycle: shows/hides based on pending state; auto-exits on timeout
- [x] Monitor mode and architectural analysis vs OpenSnitch

### 2026-05-07/08 (session 8)
- [x] Decision dialog redesigned to Material Design 3 dark theme
- [x] Circular countdown ring, segmented scope pill, custom outlined ALLOW/DENY buttons
- [x] Status bar footer; 1-second countdown ticker; monitor mode + `--pending-id` flag

### 2026-05-08 (session 9)
- [x] Daemon-side routed TCP relay (`OpenRoutedTcp`); per-egress DNS resolution
- [x] Daemon sets `/tmp/logiguard.sock` permissions to `0666`

### 2026-05-09 (routing hardening)
- [x] Policy tie-break: `(specificity, action_rank, rule.id)` for deterministic resolution
- [x] Routed Device: `SO_BINDTODEVICE` + `SO_MARK` + source bind
- [x] Routed Tun: daemon-managed `ip rule` / fwmark tables

### 2026-05-09/10 (settings window + proxy architecture)
- [x] Settings window: Rules, Egress, Proxies tabs; `--settings` flag; single-instance guard
- [x] `ProxyConfig`, `ProxyProtocol`, `ProxyAuth`, `EgressTarget` types
- [x] `RouteTarget::Proxy(id)` replacing `RouteTarget::Socks`; proxy CRUD in daemon + CLI

### 2026-05-10 (session 10 — Table + Dialog refactor)
- [x] All settings tabs use `Table<D>` with `TableDelegate` (Rules, Egress, Proxies)
- [x] Double-click rows open detail/edit dialogs
- [x] `Root` wrapper for dialog support; window 960×720
- [x] Created `docs/gpui-settings.md`

### 2026-05-11 (throne bypass fix)
- [x] `output_nat` nftables chain to bypass throne transparent proxy for device-routed connections
- [x] Configurable `ROUTE_MARK_BASE` via `LOGIGUARD_ROUTE_MARK_BASE`

### 2026-05-11 (session 11 — egress/proxy form dialogs)
- [x] Add/Edit Egress and Proxy form dialogs with custom design-system modal header/footer
- [x] Shared UI primitives extracted to `components/modal.rs`
- [x] `parse_targets_csv` helper for `tun:` / `proxy:` / `dev:` prefix parsing

### 2026-05-11 (session 12 — pending UX + monitor reliability)
- [x] Loopback bypass gap fixed for IPv4-mapped `::ffff:127.x.x.x`
- [x] Tray monitor "only first prompt appears" bug fixed (parent waits on child)
- [x] Deferred pending starvation fixed (retry on next poll cycle)

### 2026-05-12 (session 13 — TLS SNI extraction)
- [x] `extract_tls_sni()` pure byte parser for TLS ClientHello
- [x] TCP SYN/ACK/FIN (empty payload) accepted immediately; ClientHello classified
- [x] Added `docs/nfqueue-packet-interception.md`, `docs/nfqueue-domain-inference.md`

### 2026-05-12 (session 14 — real ProcessResolver)
- [x] `ProcProcessResolver`: reads `/proc/net/{tcp,tcp6,udp,udp6}`, scans `/proc/*/fd/`
- [x] Fixed IPv6 word byte order in `/proc/net/tcp6`; 6 unit tests
- [x] Added `docs/process-resolver.md`

### 2026-05-12 (session 16 — repeated-prompt bug fixes)
- [x] Root cause analysis: three compounding bugs caused flows to re-prompt after user decision
- [x] **Bug 1 — SNI cache:** daemon used `FakeDnsResolver { result: None }`; packets after the TLS ClientHello had no domain, domain-based rules failed to match. Added `SniDnsCache` (`flow-classifier`) — populated by NFQUEUE run loop on every SNI extraction, shared via `Arc` clone into `FlowClassifier` as its `DnsResolver`. Subsequent packets to same IP now resolve domain from cache.
- [x] **Bug 2 — Flow dedup:** `register_unknown_flow` had no deduplication; every retransmitted packet created a new `PendingDecision`. Added `FlowKey (process, dst_ip, dst_port, protocol)` reverse index in `DecisionEngine`; returns existing pending for already-pending flows. Index cleaned up on resolve and expire. Added `Hash` derive to `TransportProtocol`. 3 new tests.
- [x] **Bug 3 — Race window:** UI sent `ResolvePending` + `AddRule` as two separate socket requests; packets in the gap created new pendings before the rule existed. Added `ResolvePendingWithRule { pending_id, action, rule }` to `control-api`; handler installs rule first, then resolves. UI now uses this single atomic request for both Allow and Deny.
- [x] Updated `docs/architecture.md`: decision-engine description, control-api request list, pending resolution flow diagram
- [x] Updated `docs/testing.md`: decision-engine test matrix
- [x] Updated `docs/nfqueue-domain-inference.md`: SNI cache design, thread-safety, remaining gaps
- [x] Updated `docs/nfqueue-packet-interception.md`: packet path diagram

### 2026-05-12 (session 18 — nftables established/related bypass)
- [x] **Root cause:** every TCP/UDP packet (ACK, data, retransmit) went through NFQUEUE, not just new connections. On follow-up packets the socket is already established so `/proc/net` has no fresh SYN entry → process resolution returns `None` → "unknown" pending dialogs flood the queue.
- [x] Added `ct state established,related accept` before `queue num N` in both `output_early` and `forward` chains. Only the first packet of each new connection now enters NFQUEUE.
- [x] Updated `docs/nfqueue-packet-interception.md`: packet path diagram, key rules section.

### 2026-05-12 (session 17 — process resolver improvements + queue sweep)
- [x] **ProcProcessResolver** hardened: retry loop (0/3/8 ms delays for TOCTOU), exe-basename preferred over comm (kernel truncates comm at 15 chars), parent-process fallback for short names (≤3 chars)
- [x] **UDP wildcard sockets:** `/proc/net/udp` shows `0.0.0.0:PORT` for unbound sockets; added port-only pass in `find_socket_inode()` as fallback after exact IP match fails. 3 new tests.
- [x] **UID-filtered /proc scan:** `parse_proc_net` now returns `(inode, uid)`; `find_pid_for_inode` does UID-filtered first pass, full-scan fallback. Reduces O(all_procs×fds) to O(user_procs×fds).
- [x] **Queue sweep:** `sweep_pending()` called after every rule upsert — auto-resolves any pending decisions already covered by a rule without showing a dialog.

### 2026-05-12 (session 15 — rule scope UI + design system)
- [x] `DestinationMatcher::Any` variant (policy-engine + state-store)
- [x] `ProcessScope` / `DestScope` in `AppState`, initialized from flow at startup
- [x] Rule scope section in decision dialog: process toggle, destination scope chips, CIDR octet picker, rule summary line, broad-rule guard
- [x] `components/ds.rs` — design-system primitives (badge, chip, dest_text, cidr_picker, label_row)
- [x] Settings Rules tab: separate ID + Process columns, `Label` for text cells, `badge` for Action/Duration
- [x] Emulator DNS-resolves domain targets before flow registration (fixes `0.0.0.0` IP)
- [x] Window height 488→580px; overflow fixed; layout rows separated
- [x] `docs/gpui-components.md` extended; `docs/testing.md` created; `develop.md` refactored

### 2026-05-13 (session 19 — process-attribution races: three layers of defense)
- [x] **Root-cause analysis:** Duplicate decision dialogs for the same connection (one with a process name, one labelled `(unknown)`) traced to a three-way race between NFQUEUE packet delivery and the kernel publishing socket entries to `/proc/net/{tcp,udp}*`. The race was previously absorbed by *zero* layers: the resolver had no cache, the dedup index keyed on `process_name` (so two race-different packets created two pendings), and `policy_engine::process_matches((Some, None)) → false` (so any later unattributed packet bypassed the user-approved rule and created another dialog).
- [x] **Layer 1 — `ProcProcessResolver` per-socket cache.** `(src_ip, src_port, protocol) → name` with 60 s TTL and 4096-entry cap. Successful resolutions are reused across retransmits and follow-up segments of the same socket so the resolver never *changes its mind* mid-connection. 3 new tests.
- [x] **Layer 2 — symmetric dedup in `DecisionEngine::register_unknown_flow`.** The `(dst_ip, dst_port, protocol)` fallback now fires whenever *at least one* of `(new flow, existing pending)` has `process_name = None`. When a real name arrives for an "unknown" pending, the pending is **upgraded in place** (index re-keyed, `flow.process_name` patched, newly-learned domain/device label filled in). Two distinct *known* names still create two pendings. 3 new tests.
- [x] **Layer 3 — forgiving `policy_engine::process_matches` for specific destinations.** `(rule.proc=Some, flow.proc=None)` now matches when `rule.destination` is `IpExact` or `DomainExact`. Broad rules (`Any` / `Cidr` / `DomainWildcard`) still require a strict process match so they cannot be silently piggy-backed by an unattributed packet. 6 new tests (including 4 safety negatives).
- [x] **Tests:** 12 new tests across `flow-classifier`, `decision-engine`, `policy-engine`. Workspace total **77 → 123**.
- [x] **Documentation:**
  - **New:** [`docs/process-attribution-races.md`](docs/process-attribution-races.md) — the design post-mortem, top-down explanation of all three layers, and a table of which symptom is caught by which layer (so the next person knows what breaks if any layer is removed).
  - Updated `docs/process-resolver.md` (cache, two distinct TOCTOU windows, ASCII lookup chain).
  - Updated `docs/architecture.md` (decision-engine symmetric dedup, policy-engine fallback, `ProcProcessResolver` cache).
  - Updated `docs/testing.md` (new matrix rows for each layer).
  - Updated `docs/implementation-status.md` (Bug 12 entry, refreshed test counts).

### 2026-05-13 (session 20 — wildcard rules: storage/match format mismatch)
- [x] **Root cause.** `DomainWildcard` rules created via the decision dialog never matched any flow, so the user got re-prompted on every connection — including subdomains the rule was supposed to cover. The bug was a silent contract violation between three writers and one matcher:
  - GPUI decision dialog `build_dest_matcher` → `DomainWildcard(domain_apex(d))` (apex-only, no `*.`).
  - CLI `parse_destination` → `DomainWildcard(rest)` after `strip_prefix("*.")` (apex-only).
  - Settings form → `DomainWildcard(dest_val)` verbatim (depends on what the user typed).
  - `policy_engine::wildcard_matches` required `pattern.strip_prefix("*.")` — returned `false` for the apex-only form, which is what production was overwhelmingly writing.

  Net effect: every wildcard rule created through the UI was a no-op rule. The user's report ("wildcard in rules not work, and its subdomain and the domain not allowed") was a faithful description of the symptom.
- [x] **Fix.** Single change in the matcher, single normalization at the form:
  - `wildcard_matches` strips `*.` if present and treats the remainder as the apex. Empty patterns (including `"*."` alone) still match nothing.
  - Settings form (`apps/gpui/src/settings/mod.rs`) strips `*.` on save so user-typed `*.foo.com` and `foo.com` both store as `DomainWildcard("foo.com")` — keeps the rule table free of `*.*.foo.com` render glitches (display layer prepends `*.`).
  - Apex-not-matched semantic preserved: `*.example.com` matches subdomains only. Allowing the apex still requires a separate `DomainExact` rule (per `docs/decision-dialog-ux.md`). Flagged as possible future UX work — a `DomainSuffix` variant or an "apex + subdomains" chip could remove the need for two rules.
- [x] **Tests:** 3 new tests in `policy-engine`. Workspace total **123 → 126**.
  - `wildcard_matches_with_apex_only_storage_form` — locks in the production storage form.
  - `wildcard_matches_both_storage_forms_identically` — `"foo.com"` and `"*.foo.com"` resolve identically.
  - `wildcard_empty_pattern_matches_nothing` — defensive guard against malformed imports.
- [x] **Documentation:**
  - Updated `docs/decision-dialog-ux.md` with a "Canonical storage form" section that names every writer, the display convention, and the past bug so the same contract isn't broken again.
  - Updated `docs/testing.md` (3 new policy-engine rows).
  - Updated `docs/implementation-status.md` (Bug 13 entry, refreshed test counts).

### 2026-05-13 (session 21 — settings resize + NFQUEUE tray toggle)

Two long-standing follow-up items from `## 4) Open Bugs / Follow-ups` (lines 172–173) closed in one session. Both root causes turned out to be cases where the existing code did *almost* the right thing but stopped one step short of being observable to the user.

- [x] **Settings window not resizable.**
  - **Root cause.** The settings window opened on GNOME / Mutter (Wayland), which refuses `xdg-decoration` server-side decorations and forces the app to draw its own chrome. `gpui_component::TitleBar` was rendered, but the root view never wrapped its content in `gpui_component::window_border()` — so there was no shadow hitbox calling `window.start_window_resize(edge)`, and the cursor never switched to a resize cursor on the edges. From the user's POV the window was simply pinned at 960×720.
  - **Fix.** Two changes in `apps/gpui/src/`:
    - `settings/mod.rs`: wrap the whole root in `window_border().child(v_flex()...)` — this is the official `gpui-component` helper for CSD windows (it's a no-op on systems that have real SSD, so KWin/macOS/Windows pay no cost).
    - `main.rs`: open the settings window with `window_decorations: Some(WindowDecorations::Client)`, `is_resizable: true` (explicit; defaults to `true` already), and `window_min_size: Some(640×420)` so the user can't accidentally collapse the table headers and tab bar past the point of being usable.
  - **No new tests** — GPUI window plumbing isn't unit-testable from this side; the build + manual resize confirms the fix.

- [x] **NFQUEUE tray toggle unreliable.**
  - **Root cause.** The `SetNfqueueEnabled { enabled }` handler in `apps/daemon/src/main.rs` just forwarded the request to `ControlService::handle`, which set an `AtomicBool` and returned `Ok`. Nothing about nftables, the kernel, or the running `NfqueueProcessor` changed. `Health` *reported* the new flag, so the GUI thought the toggle had worked, but actual interception was unchanged. The "unreliable" symptom was really "always a no-op" — depending on whether `LOGIGUARD_NFQUEUE` was set at boot, the user saw either always-on or always-off, never actually toggled.
  - **Fix.** The handler now does what its name implies:
    - New `DaemonRuntime { bootstrap, nfqueue_num, route_mark_base }` plumbs the boot config to `handle_client` instead of free-floating parameters.
    - New pure helper `plan_nfqueue_toggle(bootstrap_present, nfqueue_num, enabled) -> NfqueueToggleAction` decides whether to re-apply nftables (`Apply { queue }`) or refuse with an actionable error (`Reject(msg)`). Splitting the gate from the side effect makes the (bootstrap, queue, enabled) matrix testable without faking a `UnixStream`.
    - On `Apply`, the handler calls `bootstrap.setup(queue, route_mark_base)` (which is idempotent — it tears down and re-applies the whole `inet logiguard` table), and *only on success* commits the cached flag in `ControlService`. A kernel failure can't leave `Health` lying about whether interception is on.
    - On `Reject`, no state changes anywhere. Two reject paths today:
      - `bootstrap_present = false`: daemon failed to install nftables at boot (usually not root). Error suggests `nft list ruleset`.
      - `enabled = true && nfqueue_num = None`: daemon was started without `LOGIGUARD_NFQUEUE`, so no `NfqueueProcessor` is running. Adding `queue num N` rules with nobody draining the queue would *drop every packet* (no `bypass` flag in the rules), which is far worse than refusing the toggle. Error points the operator at the systemd unit.
  - **Tests:** 4 new unit tests in `apps/daemon/src/main.rs::tests`, the first tests this binary has ever had:
    - `toggle_rejected_when_bootstrap_missing` — both directions reject if nftables didn't install.
    - `enable_rejected_when_no_queue_configured` — and the error message names the env var.
    - `disable_always_applies_with_no_queue` — disabling is always safe.
    - `enable_applies_with_configured_queue` — the production systemd happy path (`LOGIGUARD_NFQUEUE=0`).
  - Workspace **126 → 130 tests** passing, no regressions.

- [x] **Documentation:** updated the two open-bug entries in `## 4) Open Bugs / Follow-ups` to `[x]` with a one-line summary each, refreshed test counts.

### 2026-05-13 (session 22 — HTTP Host fallback for domain detection)

User-reported regression that turned out to be a long-standing pre-existing gap, not caused by recent changes. Worth its own session entry because it closes a real usability hole for plaintext HTTP flows.

- [x] **Root cause.** `curl google.com` (port 80, no TLS) showed up in the dialog with `process_name = "curl"` but `destination_domain = None`. The pipeline had two cooperating gaps:
  - `parse_raw_packet` only called `extract_tls_sni`, so any payload without a TLS ClientHello produced `sni_hint = None`.
  - DNS is bypassed in the nftables `output_early` chain (`udp dport 53 accept` / `tcp dport 53 accept`), so the daemon never sees DNS responses to populate `SniDnsCache` from there.

  Net effect: HTTP-only flows had no source of truth for the destination domain, and rules like `allow curl → google.com` couldn't match.

- [x] **Fix.** New `extract_http_host(payload)` in `crates/enforcer/src/nfqueue.rs`, wired in as the fallback when SNI is absent — `extract_tls_sni(payload).or_else(|| extract_http_host(payload))`. Parser is defensive by design — early-reject by HTTP method prefix, 4 KiB scan cap, conservative hostname charset, port stripping (incl. bracketed IPv6), case-insensitive `\r\nhost:` search starting after the request line, lowercased output. TLS SNI still wins when present.

- [x] **Tests.** 12 new tests in `nfqueue::tests::http_host_*` — happy path, case-insensitivity, IPv4/IPv6 port stripping, CONNECT proxies, multi-header ordering, truncation safety, garbage rejection, explicit negatives against TLS and non-HTTP TCP. Workspace **130 → 142** tests.

- [x] **Documentation.** Expanded `docs/nfqueue-domain-inference.md` with a full "Plaintext HTTP Host header fallback" section that explains every defensive guard and what's still uncovered (QUIC, plain UDP services, non-HTTP/non-TLS TCP). Updated `docs/implementation-status.md` with a Bug 16 entry. Updated the doc-comment on `FlowContext.sni_hint` / `RawPacket.sni_hint` to call out that the field now holds either source (no rename — too many touch points for an incidental change).
