# Netkeep Development Guide

## Workflow

All work is tracked in GitHub Issues (https://github.com/mohamadkhani/netkeep/issues).

1. Pick or file an issue. Bug reports use the issue template.
2. Branch as `fix/<n>-slug` or `feat/<n>-slug`.
3. For bugs: write the failing test first, then fix.
4. Update the relevant area doc (below) in the same PR when you learned something.
5. PR description carries the write-up: **Root cause / Fix / Tests** for bugs.
6. PR body ends with `Fixes #<n>` so the issue closes on merge. Squash merge to main.

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
  - Optional `egress_id` binding — rule references a named Egress entity; concrete `RouteTarget` resolved at enforcement time
  - Optional per-egress DNS server list
  - Proxy support: SOCKS5, HTTP/HTTPS, Shadowsocks with per-type auth
  - Egress targets have priority ordering; first *available* target wins at enforcement time
- Protocol coverage in v1:
  - TCP + UDP, best-effort domain inference for QUIC/HTTP3
  - On DNS/SNI conflict, treat as IP-only
- Rule duration: quick action = until restart; permanent = explicit user choice
- Storage: SQLite
- Recovery: physical-console-only emergency unlock; boot blocks until daemon healthy

### Linux packages required to build `netkeep-gpui`

The system tray is a vendored **ksni** crate (pure-Rust SNI over `zbus`) — it links no GTK or libappindicator. The remaining system-library needs come from GPUI itself (font-kit, GPU, input). On Linux you need at least:

- **xdotool** — provides **libxdo** (`-lxdo`) on GPUI's X11 dependency path.
- A working **D-Bus session bus** (always present on a desktop) — ksni registers the `org.kde.StatusNotifierItem-<PID>-<n>` name on it.

Arch Linux example:

```bash
sudo pacman -S xdotool
```

(The earlier `libappindicator` dependency was removed when the tray was migrated to ksni.)

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
| `apps/daemon` | `netkeepd` — root systemd daemon |
| `apps/cli` | `netkeep-cli` — operator interface |
| `apps/gpui` | `netkeep-gpui` — GPUI decision UI + tray + settings |

### Daemon–UI Communication

Bidirectional Unix socket at `/tmp/netkeep.sock`. JSON-lines transport. See [`docs/unix-sockets.md`](docs/unix-sockets.md).

### Data Model Summary

Full schema and field definitions are in [`docs/architecture.md`](docs/architecture.md) → Core Crates.

Key types: `Rule`, `FlowContext`, `PendingDecision`, `Egress`, `RouteTarget`, `ProxyConfig`, `DestinationMatcher`, `RuleAction`, `RuleDuration`.

### Rule Resolution

- Precedence: `rule.priority` descending (restriction ladder, seeded at creation; manual reorder via `MoveRule` midpoint insertion) — see [`docs/architecture.md`](docs/architecture.md) → policy-engine
- Tie-break: action rank (`Deny > Allow/Route > Ask`), then lexicographically greater `rule.id`
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
- [x] Settings runs in-process with the tray (close window doesn't kill the tray app)
- [x] Modular `settings/` directory (mod.rs, rules_tab.rs, egress_tab.rs, proxies_tab.rs, helpers.rs)
- [x] Add/Edit Egress and Proxy form dialogs with custom modal header/footer
- [x] Design-system primitives in `components/ds.rs` (badge, chip, dest_text, cidr_picker, label_row)
- [x] Rule scope UI: process toggle, destination scope chips, CIDR octet picker, rule summary line
- [x] NFQUEUE enable/disable toggle via tray menu
- [x] Egress-bound rules: `Rule.egress_id` replaces `route_target`; first available `RouteTarget` resolved at enforcement time via `first_available_target()`
- [x] gpui migrated from crates.io `gpui 0.2` to git HEAD (`zed-industries/zed`); ported `DataTable`, `Column` ownership, removed footer closure API
- [x] Daemon no longer auto-seeds per-interface egresses; only ensures `eg-default` exists on startup
- [x] Egress table: ID column as first column; Name cell no longer shows inline `(id)` sub-text
- [x] Egress form dialog: per-target list editor (TUN/DEV/PROXY type buttons + interface input + ADD/remove) replacing CSV text input; TYPE button height fixed to match select element
- [x] Rules form dialog: egress selector buttons (one per non-system egress, highlighted when selected) replacing free-text route-target input
- [ ] Auth fields in proxy form dialog (Basic / Shadowsocks)
- [ ] Egress priority ordering UI

## 4) Open Bugs / Follow-ups

- [x] **Settings window not resizable** — fixed since 2026-05-13 (session 21). Root view now wraps everything in `gpui_component::window_border()` so the resize edges + cursor change work on Linux compositors that use client-side decorations (notably GNOME / Mutter, which refuses xdg-decoration server-side requests). Also explicitly requests `WindowDecorations::Client` and sets `window_min_size = 640×420` so the user can't accidentally collapse the table headers.
- [x] **NFQUEUE tray toggle unreliable** — fixed since 2026-05-13 (session 21). The previous handler just flipped a status bit in `ControlService` and never touched the kernel; the toggle was a no-op. Now `SetNfqueueEnabled` re-applies the nftables protection chains via `NftablesBootstrap::setup(queue, route_mark_base)` — `Some(n)` adds `queue num n` rules, `None` removes them. The cached flag is only committed *after* nftables actually applied. Gate logic is in the pure `plan_nfqueue_toggle` helper with 4 new unit tests covering the (bootstrap present, queue configured, enabled requested) matrix, including the case where the daemon was started without `NETKEEP_NFQUEUE` (rejected with an actionable error pointing the operator at the systemd unit). Workspace 126 → 130 tests.
- [x] **Auto-seeded interface egresses polluting "Route via" selector** — fixed 2026-05-13. Daemon was calling `detect_egresses()` on every startup and upserting one Egress per local interface into the DB. The decision dialog's "Route via" showed all of them alongside user-defined ones (e.g. "TUN: throne-tun", "LAN: enp3s0"). Daemon now only ensures `eg-default` exists; per-interface availability is checked at routing time by `first_available_target()`.
- [x] **`AwaitPendingDecision` returned `route_target: None` for Route actions** — fixed 2026-05-13. `DecisionEngine.resolved` stored only `RuleAction`; when the emulator polled `AwaitPendingDecision` after the UI had resolved via `ResolvePendingWithRule`, it received `route_target: None` and routed to the wrong interface on the first request. Second request hit the now-existing rule via `RegisterUnknownFlow` and routed correctly. Fix: `resolved` map stores `(RuleAction, Option<egress_id>)`; `resolve_pending()` takes `egress_id`; `take_resolved()` returns both; `AwaitPendingDecision` calls `resolve_route_target()` before responding. `sweep_pending()` also passes `egress_id` so sweep-resolved flows get the same treatment.
- [ ] **Tray toggle should be single item** — currently two separate enable/disable menu items; should be one checked/unchecked toggle
- [ ] **Add Egress / Add Proxy button styling** — full-width, doesn't match design spec
- [ ] **Stale auto-seeded egresses in existing DB** — users who ran an older daemon have interface egresses stored in their SQLite DB. They need to delete them via the Egresses settings tab or by wiping the DB.
- [x] **Decision dialog clips content with many egresses** — fixed 2026-05-13. Window height was hardcoded at 580px; replaced with dynamic estimate (~600px base + 28px per egress row, capped at 90% of display). Root container no longer uses `h_full()`/`overflow_hidden()`.
- [x] **Default route not first in "Route via" selector** — fixed 2026-05-13. Egresses from the daemon are sorted alphabetically by id; `eg-default` can come after `eg-eth0`. Now sorted: system default first, then available, then unavailable.
- [x] **Settings window doesn't focus when re-clicked from tray** — fully fixed 2026-07-15. Root cause: GNOME's AppIndicator extension mints the xdg-activation token inside the compositor and delivers it via the SNI `ProvideXdgActivationToken` method, which the old `tray-icon`/libappindicator did not implement. Fix: migrated the tray to a vendored, patched **ksni** (`crates/ksni/`) that implements `ProvideXdgActivationToken`; the token is stashed and fed to GPUI's `Window::activate_with_token` (GitHub GPUI fork `mohamadkhani/zed`, rev `c612da65`). Tray + settings now share one GPUI process. (Earlier notes about GTK `GdkAppLaunchContext` / `XDG_ACTIVATION_TOKEN` over a Unix socket were superseded — an app cannot mint an authoritative token for its own background window.) Details: [`docs/tray-window-focus-wayland.md`](docs/tray-window-focus-wayland.md).
- [x] **Daemon's own connections attributed to "netkeep-daemon"** — fixed 2026-06-04. The daemon's outbound sockets (DNS forwarder system fallback, TCP relay, proxy connects) were not marked with `SO_MARK`, so nftables queued them to NFQUEUE. The process resolver correctly identified them as belonging to `netkeep-daemon` — but that's the wrong process; the real application that triggered the connection was hidden behind the relay. Fix: added `DAEMON_BYPASS_MARK` (19998, below `ROUTE_MARK_BASE` to avoid triggering policy routing) stamped via `SO_MARK` on all daemon-originated sockets. A new nftables `output_early` accept rule for this mark bypasses NFQUEUE entirely. See [`docs/nfqueue-packet-interception.md`](docs/nfqueue-packet-interception.md) → Daemon bypass mark.

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
- [x] `netkeep-gpui` GPUI app with `AppState`, `DecisionApp` root view, reactive re-render
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
- [x] Daemon sets `/tmp/netkeep.sock` permissions to `0666`

### 2026-05-09 (routing hardening)
- [x] Policy tie-break: `(specificity, action_rank, rule.id)` for deterministic resolution
- [x] Routed Device: `SO_BINDTODEVICE` + `SO_MARK` + source bind
- [x] Routed Tun: daemon-managed `ip rule` / fwmark tables

### 2026-05-09/10 (settings window + proxy architecture)
- [x] Settings window: Rules, Egress, Proxies tabs; in-process with the tray; single-instance guard
- [x] `ProxyConfig`, `ProxyProtocol`, `ProxyAuth`, `EgressTarget` types
- [x] `RouteTarget::Proxy(id)` replacing `RouteTarget::Socks`; proxy CRUD in daemon + CLI

### 2026-05-10 (session 10 — Table + Dialog refactor)
- [x] All settings tabs use `Table<D>` with `TableDelegate` (Rules, Egress, Proxies)
- [x] Double-click rows open detail/edit dialogs
- [x] `Root` wrapper for dialog support; window 960×720
- [x] Created `docs/gpui-settings.md`

### 2026-05-11 (throne bypass fix)
- [x] `output_nat` nftables chain to bypass throne transparent proxy for device-routed connections
- [x] Configurable `ROUTE_MARK_BASE` via `NETKEEP_ROUTE_MARK_BASE`

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
  - **Root cause.** The `SetNfqueueEnabled { enabled }` handler in `apps/daemon/src/main.rs` just forwarded the request to `ControlService::handle`, which set an `AtomicBool` and returned `Ok`. Nothing about nftables, the kernel, or the running `NfqueueProcessor` changed. `Health` *reported* the new flag, so the GUI thought the toggle had worked, but actual interception was unchanged. The "unreliable" symptom was really "always a no-op" — depending on whether `NETKEEP_NFQUEUE` was set at boot, the user saw either always-on or always-off, never actually toggled.
  - **Fix.** The handler now does what its name implies:
    - New `DaemonRuntime { bootstrap, nfqueue_num, route_mark_base }` plumbs the boot config to `handle_client` instead of free-floating parameters.
    - New pure helper `plan_nfqueue_toggle(bootstrap_present, nfqueue_num, enabled) -> NfqueueToggleAction` decides whether to re-apply nftables (`Apply { queue }`) or refuse with an actionable error (`Reject(msg)`). Splitting the gate from the side effect makes the (bootstrap, queue, enabled) matrix testable without faking a `UnixStream`.
    - On `Apply`, the handler calls `bootstrap.setup(queue, route_mark_base)` (which is idempotent — it tears down and re-applies the whole `inet netkeep` table), and *only on success* commits the cached flag in `ControlService`. A kernel failure can't leave `Health` lying about whether interception is on.
    - On `Reject`, no state changes anywhere. Two reject paths today:
      - `bootstrap_present = false`: daemon failed to install nftables at boot (usually not root). Error suggests `nft list ruleset`.
      - `enabled = true && nfqueue_num = None`: daemon was started without `NETKEEP_NFQUEUE`, so no `NfqueueProcessor` is running. Adding `queue num N` rules with nobody draining the queue would *drop every packet* (no `bypass` flag in the rules), which is far worse than refusing the toggle. Error points the operator at the systemd unit.
  - **Tests:** 4 new unit tests in `apps/daemon/src/main.rs::tests`, the first tests this binary has ever had:
    - `toggle_rejected_when_bootstrap_missing` — both directions reject if nftables didn't install.
    - `enable_rejected_when_no_queue_configured` — and the error message names the env var.
    - `disable_always_applies_with_no_queue` — disabling is always safe.
    - `enable_applies_with_configured_queue` — the production systemd happy path (`NETKEEP_NFQUEUE=0`).
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

### 2026-05-13 (session 23 — egress-bound rules + gpui git migration)

Two intertwined changes in one session: a full architectural refactor of how routing targets are stored and resolved, and a migration of the GPUI dependency from the stale crates.io release to git HEAD.

- [x] **`Rule.egress_id` replaces `Rule.route_target`.** Rules no longer embed a concrete `RouteTarget`. Instead they reference a named `Egress` entity by ID. At enforcement time, `control-service::first_available_target()` walks the egress's ordered target list and returns the first available one — checking `/sys/class/net/<name>/operstate` for Device/Tun targets and `ProxyRepository.enabled` for Proxy targets. This enables true failover (primary VPN down → fall through to backup) without changing the rule.
  - `RuleAction::Route` — dropped the embedded `{ target: RouteTarget }` field; now a unit variant
  - `Rule.egress_id: Option<String>` — replaces the removed `route_target: Option<RouteTarget>`
  - `FlowDecision::Immediate(action, Option<RouteTarget>)` — carries the resolved target alongside the action so the enforcer still gets a concrete target even though `RuleAction::Route` no longer embeds one
  - `ImmediateVerdict { action, route_target: Option<RouteTarget> }` and `PendingResolved { action, route_target }` in `control-api` — same pattern
  - `state-store`: `rules` table migrated — added `egress_id TEXT NULL`, dropped `route_target_kind`/`route_target_value`; migration applied at startup
  - `policy-engine`: `ResolvedRule.egress_id` threads through from matched rule
  - `control-service`: `resolve_route_target()` + `first_available_target()` added; all response constructors updated
  - `gpui action_footer`: sends `egress_id` on rule instead of a resolved target
  - `cli`: `--route <device>` replaced with `--egress <id>`; display shows `egress=<id>`
  - `emulator`: pattern matches updated for new `RuleAction::Route` and `route_target` field

- [x] **Daemon no longer auto-seeds per-interface egresses.** Previously `detect_egresses()` was called on every startup and each local interface was upserted as a separate Egress in the DB. This caused the decision dialog "Route via" selector to show "TUN: throne-tun", "LAN: enp3s0", etc. alongside user-defined egresses like "proxy1". Daemon now only ensures the single `eg-default` system egress exists. Interface availability is checked at routing time.

- [x] **gpui migrated from crates.io 0.2 to git HEAD** (`zed-industries/zed`). API breakages fixed:
  - `Table::new(...)` → `DataTable::new(...)`
  - `column()` return type: `&Column` → `Column` (clone from stored vec)
  - `.footer(closure)` API removed — `button_props` handles OK/Cancel now
  - `cx.update_entity(...).unwrap_or()` → returns `R` directly, not `Result<R>`
  - Added `gpui_platform` dep with `features = ["font-kit", "wayland", "x11"]` — required to avoid runtime `unreachable!()` panic when Wayland is detected but no backend is compiled in
  - `Application::new().run(...)` → `gpui_platform::application().with_assets(...).run(...)`

### 2026-05-13 (session 24 — fix Route target lost on AwaitPendingDecision)

- [x] **Root cause.** When a user picked a Route egress in the decision dialog, the UI sent `ResolvePendingWithRule` and received a correct `PendingResolved { route_target: Some(...) }`. But the **emulator** was polling via `AwaitPendingDecision`, and that handler always returned `route_target: None` — because `DecisionEngine.resolved` stored only `RuleAction`, discarding the `egress_id`. The emulator then attempted to route with no target, which fell back to the wrong interface. The second `curl` worked because a rule now existed and `RegisterUnknownFlow` matched it immediately, calling `resolve_route_target()` correctly.
- [x] **Fix.** `DecisionEngine.resolved: HashMap<String, (RuleAction, Option<String>)>`. `resolve_pending()` takes an `egress_id: Option<String>` argument. `take_resolved()` returns `Option<(RuleAction, Option<String>)>`. Updated three call sites in `control-service`:
  - `AwaitPendingDecision` — destructures `(action, egress_id)`, calls `resolve_route_target(&egress_id)`, returns the real target.
  - `ResolvePendingWithRule` — passes `egress_id.clone()` so the emulator poller and the direct response both resolve identically.
  - `sweep_pending()` — passes `resolved.egress_id` so auto-swept flows also carry the correct egress when polled.
  - `ResolvePending` (no-rule inline) — passes `None`.

### 2026-05-13/14 (session 25 — decision dialog dynamic height + egress sorting + settings focus)

Three UI polish fixes in one session:

- [x] **Decision dialog height is now dynamic.** The window was hardcoded at 440×580 — when many egress entries were present, the action footer (scope toggles, egress chips, Allow/Deny buttons) pushed below the visible area and got clipped by `overflow_hidden()`. Removed `h_full()` and `overflow_hidden()` from the root container. Window height is now estimated at open time: ~600px base (derived from actual component padding/gap values) + 28px per egress chip row + 24px if a device label is present, capped at 90% of the primary display. Files: `apps/gpui/src/app.rs`, `apps/gpui/src/main.rs`.

- [x] **Default route is first and selected in "Route via" selector.** Egresses from the daemon were sorted alphabetically by id (`eg-default` could come after `eg-eth0`), and `selected_egress_index` was always 0. After `fetch_egresses()`, the list is now sorted: system default first, then available egresses, then unavailable — so the Default Route chip is always at position 0 and selected by default. File: `apps/gpui/src/main.rs`.

- [x] **Settings window focuses on re-click from tray (Wayland/GNOME).** Fully fixed 2026-07-15: GNOME's AppIndicator extension mints the xdg-activation token in the compositor and delivers it via the SNI `ProvideXdgActivationToken` method; the old `tray-icon`/libappindicator didn't implement it. Migrated the tray to a vendored, patched **ksni** (`crates/ksni/`) that implements that method, stashes the token, and feeds it to GPUI's `Window::activate_with_token` (GitHub fork `mohamadkhani/zed`, rev `c612da65`). Tray + settings share one GPUI process; the `--settings` subprocess and settings_ipc socket are gone. (The earlier GTK `get_startup_notify_id` / `XDG_ACTIVATION_TOKEN`-over-socket approach was superseded — an app can't mint an authoritative token for its own background window.) Details: [`docs/tray-window-focus-wayland.md`](docs/tray-window-focus-wayland.md).
- **Files:** `apps/gpui/src/main.rs`.

### 2026-05-14 (session 26 — process resolver hardening + DB path + initial egress seeding)

Five independent improvements in one session, all in the process-identification and first-run experience paths.

- [x] **Process resolver: IPv4-mapped sockets now found in `/proc/net/tcp6`.**
  - **Root cause.** Modern apps often open `AF_INET6` sockets with `IPV6_V6ONLY=0` even when connecting to an IPv4 destination. The kernel records those sockets in `/proc/net/tcp6` as `::ffff:a.b.c.d` (IPv4-mapped form). The old `find_socket_inode` only looked in the family-matching file (`/proc/net/tcp` for an IPv4 src_ip). An IPv4 flow whose socket appeared exclusively in `tcp6` was never found → process name shown as "unknown".
  - **Fix.** `find_socket_inode` now always checks both files, preferring the matching-family file first: `[tcp, tcp6]` for an IPv4 src_ip, `[tcp6, tcp]` for IPv6. New helper `parse_hex_addr(hex)` normalises 8-char (IPv4 LE) and 32-char (IPv6 four-word LE) hex addresses, collapsing `::ffff:a.b.c.d` to `IpAddr::V4`. `parse_proc_net` uses `parse_hex_addr` and handles all four cross-family combinations: V4↔V4, V6↔V6, V6↔V4, V4↔V6.
  - **New test:** `ipv4_address_matches_ipv4_mapped_entry_in_tcp6`.
  - **File:** `crates/flow-classifier/src/proc_resolver.rs`.

- [x] **Parent fallback allowlist replaces length threshold.**
  - **Root cause.** The parent-process fallback (walk to parent when child has a short/generic name) triggered for `name.len() <= 3`. Too broad: `ssh`, `git`, `bun` all have 3 chars and should keep their own name.
  - **Fix.** Threshold replaced with an explicit shell allowlist: `sh`, `bash`, `dash`, `zsh`, `fish`. Single-character names still trigger the fallback. All other short names keep their own basename.
  - **File:** `crates/flow-classifier/src/proc_resolver.rs`.

- [x] **Retry delays extended to 4 attempts with higher caps.**
  - Old: `[0, 3, 8]ms` (3 attempts, 11 ms worst case). New: `[0, 5, 15, 40]ms` (4 attempts, 60 ms worst case). Covers Electron/JVM/sandbox wrappers where the kernel `/proc/net` lag is longer. Only the first SYN of each connection enters NFQUEUE, so this blocking cost is paid at most once per connection.
  - **File:** `crates/flow-classifier/src/proc_resolver.rs`.

- [x] **DB path moved to `~/.config/netkeep/netkeep.db`.**
  - Old default `/tmp/netkeep.db` was lost on reboot. New default is the XDG config directory. `~` is resolved at runtime via `$HOME` env var (Rust doesn't expand shell tildes). Parent directory is created with `fs::create_dir_all` on startup. Override still available via `NETKEEP_DB_PATH`.
  - **File:** `apps/daemon/src/main.rs`.

- [x] **Initial egress seeding (LAN + TUN) on fresh DB.**
  - Fresh installs had only `eg-default` with no concrete targets. `seed_initial_egresses()` now runs on startup **only when no user-defined egresses exist**:
    - **LAN** (`#3b82f6`): `ip route get 8.8.8.8` → `dev <iface>` → `RouteTarget::Device`.
    - **TUN** (`#8b5cf6`): `/sys/class/net/*/type = 65534` → one egress per TUN/TAP/WireGuard interface found.
  - Skipped entirely once any user egress exists.
  - **File:** `apps/daemon/src/main.rs`.

- [x] **Emulator integration test fixed: `ImmediateVerdict` and `PendingResolved` missing `route_target`.**
  - Both variants gained a `route_target` field in session 24; the `socks_allow_relay` test was not updated. Added `route_target: None` to both literals.
  - **File:** `apps/emulator/tests/socks_allow_relay.rs`.

**Tests:** workspace **143** passing, no regressions.

### 2026-05-16 (session 27 — settings UI polish: egress table ID column + form dialog UX)

Four settings-window UI improvements applied in `design/settings_window.html` first (design spec), then ported to the Rust implementation files.

- [x] **Egress table: ID column added.**
  - HTML: removed `PRIORITY` column (was col-span-2); added `ID` (col-span-2) before `NAME`; adjusted `NAME` to col-span-3, `STATUS` to col-span-1 to keep grid sum at 12.
  - `settings/egress_tab.rs`: `ID` is now `columns[0]` (90px); `render_td` arm 0 renders `egress.id` in muted 11px text. `NAME` arm moved to index 1 with no inline `(id)` sub-text.

- [x] **Egress form dialog: TYPE button height mismatch fixed.**
  - HTML: TYPE selection buttons (`TUN` / `DEV` / `PROXY`) changed from `py-1` to `py-1.5` so they match the height of the adjacent `<select>` element.

- [x] **Egress form dialog: per-target list editor replaces CSV text input.**
  - `settings/mod.rs` (`open_egress_form_dialog`): `targets_input: Entity<InputState>` removed; replaced with `targets_list: Arc<Mutex<Vec<String>>>` (interior-mutable, shared across `Fn` renders) and `new_tgt_iface: Entity<InputState>` + `new_tgt_type: Arc<Mutex<String>>`.
  - Dialog body renders existing targets as badge + name + ✕ remove button rows; below is an inline add-target form with `TUN`/`DEV`/`PROXY` type buttons + interface input + `ADD` button.
  - `on_ok` joins the vec into a comma-separated string and passes to `helpers::parse_targets_csv`.

- [x] **Rules form dialog: egress selector replaces free-text route input.**
  - `settings/mod.rs` (`open_rule_form_dialog`): `route_input: Entity<InputState>` removed; `available_egresses: Vec<(String, String)>` captured at open time from `self.state.read(cx).egresses`; `selected_route: Arc<Mutex<String>>` holds the selected egress id.
  - When action is `ROUTE`, the dialog shows one button per non-system egress (highlighted when selected); empty list shows a hint to add egresses first.
  - `on_ok` reads `route_ok.lock().unwrap()` instead of an input entity.

### 2026-05-16 (session 28 — process resolver: electron name + inode=0 fix)

Two bugs in `crates/flow-classifier/src/proc_resolver.rs` investigated and fixed.

- [x] **Cursor (and any AppImage Electron app) shows as "electron" in the dialog.**
  - **Root cause.** `read_exe_basename(pid)` returns `"electron"` — the actual binary name — for Electron-based apps installed as AppImages or with the Electron runtime placed inside an app directory (e.g. `/opt/cursor/electron`). The existing name-fixup code only handled single-char names and shell wrappers; `"electron"` passed through unchanged.
  - **Fix.** Added `"electron"` and `"AppRun"` (AppImage entry-point) to the generic-name trigger. Three fallback strategies tried in order:
    1. **`APPIMAGE` env var** — inherited by every subprocess in the tree; file stem lowercased and version suffix stripped: `"Cursor-0.45.5.AppImage"` → `"cursor"`.
    2. **Exe parent directory** — `/opt/cursor/electron` → `"cursor"`. Generic dirs (`bin`, `usr`, `lib`, `tmp`, etc.) are excluded.
    3. **Parent process exe basename** — filtered to exclude other generic names.
  - New pure helper `parse_environ_for_app_name(environ: &str) -> Option<String>` decouples the parsing logic from I/O so it is unit-testable.
  - **File:** `crates/flow-classifier/src/proc_resolver.rs`.

- [x] **process=None for connections that reuse a recently-closed port (TIME_WAIT inode=0 bug).**
  - **Root cause.** `/proc/net/tcp` rows for TIME_WAIT sockets carry `inode=0`. If a port is reused quickly enough that the TIME_WAIT row is still present when the new SYN arrives, `parse_proc_net` matches the TIME_WAIT row first and returns `inode=0`. `find_pid_for_inode(0)` then searches for `"socket:[0]"` — a string that never appears in any real process's fd directory — and deterministically returns `None`. Every retry of both loops also returns `None`, so the failure is guaranteed rather than racy.
  - **Fix.** Added `if inode == 0 { continue; }` in both `parse_proc_net` and `parse_proc_net_port_only`. The scan skips TIME_WAIT rows and continues to the real ESTABLISHED/SYN_SENT entry.
  - **Additional hardening:** `find_pid_for_inode` retries extended from `[0, 3, 8]` ms to `[0, 3, 8, 20]` ms (31 ms max) for Cursor AppImage's longer fork/exec gap.
  - **File:** `crates/flow-classifier/src/proc_resolver.rs`.

- [x] **Tests:** 9 new tests — 6 for `parse_environ_for_app_name` (AppImage path parsing, hyphenated names, version stripping, `ELECTRON_APP_NAME` var, missing vars, short-name rejection), 2 for inode=0 skip (TIME_WAIT row skipped + only TIME_WAIT returns None). Workspace total **143 → 152** tests, no regressions.

- [x] **Documentation:** Updated `docs/process-resolver.md` (lookup chain ASCII diagram, new fallback strategies). Updated `docs/process-attribution-races.md` (Bug 23 entry covering both root causes, fix details, and test coverage).

### 2026-05-16 (session 29 — DNS snoop cache: third domain detection method)

Closes the last significant gap in domain attribution: UDP/QUIC flows and non-HTTP/non-TLS TCP could not be matched against domain-based rules because neither SNI nor HTTP Host extraction applies.

- [x] **Root cause.** DNS queries are bypassed in `output_early` (`udp dport 53 accept`) so NFQUEUE never sees DNS traffic. DNS responses are INPUT packets — they are not in any OUTPUT hook. For UDP flows (e.g. a game client, QUIC, `dig`), the SniDnsCache was always empty, so `destination_domain = None` even when the app had just performed a DNS lookup a millisecond earlier.

- [x] **Fix — DNS snoop worker (`crates/enforcer/src/dns_snoop.rs`).**
  - `parse_dns_packet(data: &[u8]) -> Vec<(IpAddr, String)>` — pure DNS wire-format parser. Reads QNAME from the question section as the queried domain (correct even for CNAME chains), then extracts A (type 1) and AAAA (type 28) answer RDATA as resolved IPs. Handles label-pointer compression, NXDOMAIN (RCODE≠0) rejection, and malformed/truncated input.
  - `DnsSnoopWorker` — binds to queue `main_queue + 1` on the INPUT hook (nftables `bypass` flag), calls `parse_dns_from_ip_packet` to strip IP/UDP headers, then writes `resolved_ip → queried_domain` into the shared `SniDnsCache`. Always returns `Verdict::Accept` — never blocks DNS.

- [x] **nftables change (`crates/enforcer/src/lib.rs`).**
  - When `queue_num` is `Some(q)` and `q < u16::MAX`, `NftablesBootstrap::setup` now also adds:
    ```
    add chain inet netkeep input_dns { type filter hook input priority 0; policy accept; }
    add rule inet netkeep input_dns udp sport 53 queue num {q+1} bypass
    ```
  - With `bypass`: if `DnsSnoopWorker` is not running, DNS responses pass through instantly (no latency regression, no DNS failure risk).

- [x] **Daemon wiring (`apps/daemon/src/main.rs`).**
  - After `NfqueueProcessor` starts successfully, opens `DnsSnoopWorker::open(queue_num + 1, dns_cache.clone())` and spawns its `run_loop` on a background thread. Both share the same `Arc<Mutex<...>>` inside `SniDnsCache`, so DNS response entries are visible to the main NFQUEUE classify path immediately.

- [x] **Tests.** 8 new tests in `dns_snoop::tests` — A record, AAAA record, query (not response), NXDOMAIN, truncated/empty input, zero ANCOUNT, domain lowercasing, multiple round-robin A records. Workspace total **152 → 163** tests, no regressions.

- [x] **Documentation.** Updated `docs/nfqueue-domain-inference.md` — "DNS snoop cache" section replacing the previous "Still uncovered" note; explains QNAME approach, CNAME chain correctness, race window for UDP, and bypass safety.

### 2026-05-17 (session 30 — exe-path identity, app_name, ss fallback, attribution caches)

Six related improvements to process attribution, all motivated by two user-reported issues: (1) processes showing as "electron" instead of the real app name, and (2) a one-off `(unknown)` dialog appearing during YouTube playback after 4 minutes.

- [x] **`ProcessInfo` struct replaces `Option<String>` return from `resolve()`.**
  - New: `ProcessInfo { name: String, exe: Option<String>, app_name: Option<String> }`.
  - `exe` = full `/proc/<pid>/exe` path — immune to `/proc/<pid>/comm` 15-char truncation and basename collisions.
  - `app_name` = package manager name when it differs from `name` (e.g. `"cursor-bin"` for `"electron"`).
  - `CachedEntry` in the per-socket cache now stores the full `ProcessInfo` (was just `name: String`).
  - `FakeProcessResolver::resolve()` returns `ProcessInfo { name, exe: None, app_name: None }`.
  - All tests updated: `CachedName` → `CachedEntry`, `resolve().as_deref()` → `resolve().map(|p| p.name).as_deref()`.
  - **File:** `crates/flow-classifier/src/lib.rs`, `crates/flow-classifier/src/proc_resolver.rs`.

- [x] **`process_exe` and `app_name` in `Rule` and `FlowContext`.**
  - Both fields added with `#[serde(default)]` for backward-compatible deserialization.
  - `process_exe` stored in `Rule` when user creates a rule from the decision dialog (via `ProcessScope::Specific`).
  - `policy_engine::process_matches` prefers exe-path equality when both sides have it; falls back to name comparison.
  - DB migration: `ALTER TABLE rules ADD COLUMN process_exe TEXT NULL` on startup.
  - State-store SELECT/INSERT updated to include `process_exe` at column index 8.
  - **Files:** `crates/core-types/src/lib.rs`, `crates/policy-engine/src/lib.rs`, `crates/state-store/src/lib.rs`.

- [x] **`app_name` from `pacman -Qo <exe>` (Arch Linux).**
  - `pacman_query_owner(exe_path)` runs `pacman -Qo -- <exe>` and parses "owned by PKG" from stdout.
  - `lookup_pacman(&self, exe)` checks `pacman_cache: Mutex<HashMap<String, Option<String>>>` first; falls through to the subprocess only on a miss. Caches both hits and misses.
  - Suppressed when `app_name == name` (avoids showing "chromium (chromium)").
  - Shown in daemon logs: `process="electron" (cursor-bin)`.
  - Shown in decision dialog: secondary muted line `pkg: cursor-bin` under the process name.
  - **Files:** `crates/flow-classifier/src/proc_resolver.rs`, `crates/control-service/src/lib.rs`, `apps/gpui/src/components/flow_info.rs`, `apps/gpui/src/app.rs`.

- [x] **`ss` fallback when `/proc/net` scan fails.**
  - `try_ss_fallback(ip, port, protocol)` runs `ss -Hnp [-t|-u] src :<port>`, filters lines via `ss_local_matches` (handles IPv4, IPv6, IPv4-mapped), extracts `pid=N` from the `users:(("name",pid=N,...))` field.
  - If a pid is found, re-enters the standard `/proc/<pid>/exe` → name → app_name path.
  - Called only after all `/proc/net` retry attempts are exhausted.
  - **File:** `crates/flow-classifier/src/proc_resolver.rs`.

- [x] **Layer 0 attribution caches in `NfqueueProcessor` (CDN IP rotation fix).**
  - IP-based cache (`proc_attr`): `HashMap<(dst_ip, dst_port), CachedProcessAttr>`, TTL 15 min, max 1024. Consulted when `process_name = None` after classification; filled on every successful classification.
  - Domain-based cache (`domain_proc_attr`): `HashMap<(domain, dst_port), CachedProcessAttr>`, TTL 1 hour, max 512. Keyed on the stable domain name — handles CDN IP rotation (same domain, different IP each connection). Filled whenever a successful classification includes a `destination_domain`.
  - Both caches store `CachedProcessAttr { process_name, process_exe, app_name, expires_at }`.
  - **File:** `crates/enforcer/src/nfqueue.rs`.

- [x] **Decision dialog shows package name.**
  - `flow_info_section` gains `app_name: &Option<String>` parameter.
  - `process_value()` renders a secondary muted line (`pkg: cursor-bin`) at 10px when `app_name` is present. Icon aligns to top with `items_start()` + `pt(px(1.))`.
  - `design/decision_dialog_window.html` updated: `app-name-row` div (hidden by default), `setAppName(name)` JS function, "Electron app" scenario button.
  - **Files:** `apps/gpui/src/components/flow_info.rs`, `apps/gpui/src/app.rs`, `design/decision_dialog_window.html`.

- [x] **Tests:** 164 total (was 163). 1 new test added for `ss_local_matches` IPv4-mapped address handling. All 164 pass, no regressions.

- [x] **Documentation:**
  - `docs/process-resolver.md`: lookup chain updated (ss fallback step, pacman step, `ProcessInfo` in cache); Step 3 section replaced with full `ProcessInfo` explanation; multi-package-manager support plan added.
  - `docs/process-attribution-races.md`: Bug 24 entry added with Layer 0 diagram and `CachedProcessAttr` definition.
  - `docs/implementation-status.md`: test count updated to 164; Phase 2 checklist updated; Bug 24 entry added; `Rule`, `FlowContext` data structures updated; DB schema updated.
  - `develop.md`: this session log entry.

### 2026-05-17 (session 31 — Route via LAN not working: 5-layer routing fix)

User reported "Route via LAN not working — seems to route via default route (VPN currently) not LAN." Symptom: with a `Route via eg-lan-enp3s0` rule for `curl → www.digikala.com`, curl's `Established connection ... from 10.34.158.72` showed the VPN's CGNAT source IP, not enp3s0's `192.168.7.7`. After partial fixes: TCP handshake completed on VPN, TLS hello timed out at 10s. After the final fix: full TLS 1.3 handshake completes, connection runs symmetrically on LAN.

Root cause was compound — five interacting failure modes had to be solved together. None alone is sufficient; each unblocks the next.

- [x] **`output_early` chain type `filter` → `route`.**
  - Initial hypothesis: NFQUEUE-stamped marks need a route-type chain to trigger `ip_route_me_harder()`.
  - Necessary but insufficient — see next item.
  - **File:** [`crates/enforcer/src/lib.rs`](crates/enforcer/src/lib.rs).

- [x] **Three-chain reroute dance (the actual reroute mechanism).**
  - The kernel's `nf_route_table_hook4` runs its pre/post mark-change check on the return path of `nft_do_chain`. When the chain returns `NF_QUEUE` the function exits there; after `nf_reinject()` the iterator resumes at the *next* hook entry, so the chain that queued the packet never sees the verdict-mark. Verified by reading `net/netfilter/nft_chain_route.c`.
  - Also verified the `nfq` crate (0.2.5) does not expose `NFQA_CT` writes, so saving to ct mark from userspace isn't possible.
  - Solution: put the mark write *inside a later route chain's own `nft_do_chain`* so its post-check fires.
    - `output_early` (route, -150): NFQUEUE rule. Userspace stamps `meta mark = X`. Chain exits via `NF_QUEUE` → reinject; no reroute fires here.
    - `output_save_mark` (filter, -125): `meta mark >= base ct mark set meta mark meta mark set 0`. Saves the verdict-mark into ct mark and clears meta mark to 0.
    - `output_reroute` (route, -100): `ct mark >= base meta mark set ct mark`. Pre-mark 0 vs post-mark X — kernel detects the change, calls `ip_route_me_harder()`, packet is now routed via the fwmark table.
  - **File:** [`crates/enforcer/src/lib.rs`](crates/enforcer/src/lib.rs) (`SystemNftablesBootstrap::setup`).

- [x] **POSTROUTING masquerade chain.**
  - `ip_route_me_harder()` updates dst but does NOT redo source-address selection. So the rerouted packet leaves enp3s0 still carrying the VPN's source IP — ISP drops it under BCP38 / SAV, return traffic takes the VPN path → asymmetric routing → TLS timeout.
  - New `postrouting` chain (`type nat hook postrouting priority srcnat`) with `meta mark >= base oifname != "lo" masquerade` plus a `ct mark >= base` twin (relay path: `output_nat` overwrote `meta mark` with `0x2024`, original is in ct mark). Conntrack records the SNAT once at NEW and reverses transparently.
  - **File:** [`crates/enforcer/src/lib.rs`](crates/enforcer/src/lib.rs).

- [x] **Classify SYNs (not just data packets).**
  - Tcpdump revealed: SYN went out via VPN unmarked; later data packet rerouted to enp3s0 *with the VPN source IP*. Conntrack-NAT freezes the no-NAT decision at the conntrack-NEW (SYN) packet, so masquerade on a later data packet can't undo it.
  - New `tcp_syn: bool` on `RawPacket`, populated via `t.syn()` in `parse_raw_packet`. `nfqueue::decide()` short-circuits only on `tcp_payload_empty && !tcp_syn`; SYNs fall through to full classification (DNS-snoop cache hit on dst_ip + /proc resolver → rule match → Route + mark on packet 1).
  - **Behavior change:** flows without a matching Allow rule have their SYN dropped while `Pending` is open. Applications retransmit SYNs at ~1s intervals and resume once the user decides. Matches OpenSnitch / Little Snitch interactive-firewall default.
  - **Files:** [`crates/flow-classifier/src/lib.rs`](crates/flow-classifier/src/lib.rs), [`crates/enforcer/src/nfqueue.rs`](crates/enforcer/src/nfqueue.rs).

- [x] **In-table `unreachable` fallback + transactional `add_route`.**
  - The user's VPN-tun proxy app floods `main` with `dev <VPN> scope link` routes covering nearly all of IPv4. So if our lookup table is missing or empty, packets fall through to `main` and silently exit via VPN.
  - First attempt (separate `type unreachable` policy rule at fixed pref 32700) had an ordering inversion: pref 32700 < auto-assigned lookup pref 32763, so unreachable fired first and would have dropped every marked packet.
  - Final design: in-table `unreachable default metric 1000` alongside `default via <gw> dev <iface> metric 100`. Lower metric wins under normal conditions; if the primary route fails to install (or its interface goes down), the in-table unreachable returns `EHOSTUNREACH`. No pref games, failure stays within one table.
  - `SystemRouteManager::add_route` is now transactional — on `ip route` failure both the lookup rule and any partial installs are rolled back. `ensure_route_mark` only advances `next_mark` after success, so transient install failures don't burn marks.
  - **Files:** [`crates/enforcer/src/lib.rs`](crates/enforcer/src/lib.rs), [`apps/daemon/src/main.rs`](apps/daemon/src/main.rs).

- [x] **Tests:** 164 total, all pass. No new tests added — these are nftables / kernel-routing changes that can't be exercised in unit tests; verification was on the live system with curl + tcpdump + conntrack.

- [x] **Verification:** `curl --max-time 10 -v https://www.digikala.com` against a `Route via eg-lan-enp3s0` rule with the VPN tun up. Full TLS 1.3 handshake (Client Hello → Server Hello → certs → CERT verify → Finished → change_cipher → Finished) completes. Conntrack records the SNAT mapping `10.34.158.72:port → 192.168.7.7:port` for the connection lifetime.

- [x] **Side observation worth recording (no fix this session):** if netkeep is first started while a VPN is up, `seed_initial_egresses()` uses `ip route get 8.8.8.8` to identify the "LAN" interface and gets the VPN tun. The seeded "LAN" egress then points at the VPN device — confusing for the user. Recorded in `docs/architecture.md` design decision #15 as a known gotcha; a future fix should prefer `/sys/class/net/<iface>/type == 1` (ethernet) over `65534` (tun) when seeding.

- [x] **Documentation:**
  - `docs/nfqueue-packet-interception.md`: chain table rewritten with all 7 chains; rationale block "Why three OUTPUT chains for one routing decision" explaining the kernel-side limitation; simplified rules block updated; SYN classification section added; new "End-to-end Route Action Flow" diagram; new "Fail-closed Routing Tables" section.
  - `docs/architecture.md`: design decisions #9 (managed routing) extended with in-table unreachable + transactional add_route; #11 rewritten as the three-chain reroute + POSTROUTING masquerade design with full rationale; #15 (egress seeding) gains the VPN-up gotcha note.
  - `docs/implementation-status.md`: Bug 12 entry with all five sub-fixes, file refs, and verification steps.
  - `develop.md`: this session log entry.

### 2026-05-18 (session 32 — CDN multi-tenancy breaks domain detection)

User reported that process name and domain detection randomly fail — the same application connecting to the same CDN IP sometimes shows `domain=None` while the very next connection to a different IP for the same service shows the correct domain.

- [x] **Root cause: `SniDnsCache` is a 1:1 map (`IP → domain`) that cannot represent CDN multi-tenancy.** CDN IPs serve many domains. When `api2.cursor.sh` and `api3.cursor.sh` both resolve to the same Cloudflare IP `104.18.18.125`, the DNS snoop worker overwrites the cache entry. The next TLS ClientHello with SNI `api2.cursor.sh` hits the conflict check in `resolve_domain()` — DNS cache says `api3.cursor.sh` but SNI says `api2.cursor.sh`, so the code discards BOTH and returns `domain=None`. The SNI is authoritative (extracted from the actual packet), but the stale cache entry poisoned the comparison.

  The race is also cross-thread: the DNS snoop worker runs on a separate thread and can overwrite the `SniDnsCache` entry *between* the NFQUEUE's `dns_cache.insert(sni)` (line 191) and `classify()`'s `dns_cache.lookup()` (line 160) — even within the same `decide()` call.

- [x] **Fix.** `FlowClassifier::resolve_domain()` now trusts the per-packet SNI/Host when present and only falls back to the DNS cache when no per-packet hint is available. The old conflict check `(Some(dns), Some(sni)) => None` is removed — it was protecting against DNS spoofing but in practice the "spoofed" value was always just a different customer on the same CDN IP, which is harmless. QUIC still uses DNS-cache-only (SNI is encrypted in QUIC v1).

  **File:** `crates/flow-classifier/src/lib.rs`.

- [x] **Tests:** 1 test replaced with 2 (old `dns_sni_conflict_yields_ip_only` split into `sni_overrides_stale_dns_cache_on_cdn_ip` + `dns_cache_used_when_no_sni`). Workspace total **164 → 165** tests, all pass.

- [x] **Documentation:** Updated `docs/nfqueue-domain-inference.md` (Domain Resolution Priority table rewritten). Updated `docs/architecture.md` design decision #3 (from "DNS/SNI conflict → IP-only" to "SNI is authoritative over DNS cache").

### 2026-05-18 (session 33 — SOCK_DIAG netlink: eliminate /proc TOCTOU race for process detection)

Process name detection randomly failed because `retry_find_socket` races with the kernel's asynchronous publication of socket entries to `/proc/net/tcp`. The retry delays ([0, 5, 15, 40]ms) closed most of the gap but not all of it, especially under heavy system load or during desktop startup when many applications launch simultaneously. The `ss` subprocess fallback used the kernel's SOCK_DIAG netlink interface (which has no race) but only fired after 60ms of wasted `/proc` retries.

- [x] **Fix.** Added `crates/flow-classifier/src/sock_diag.rs` — `query_socket_inode()` via `NETLINK_SOCK_DIAG` / `InetRequest` with `(src_ip, src_port)` in `SocketId`. Returns `(inode, uid)` from kernel socket structures without reading `/proc/net`. Dependencies: `netlink-packet-core`, `netlink-packet-sock-diag`, `netlink-sys`. `ProcProcessResolver::find_pid` tries SOCK_DIAG first, then `retry_find_socket`, then `ss`.

- [x] **Tests:** 167 tests passing (`cargo test --workspace`). Unit tests: `query_socket_inode_does_not_panic`, `sock_addr_matches_ipv4_mapped`.

- [x] **Documentation:** `docs/process-resolver.md` lookup chain + race section updated for SOCK_DIAG primary path.

### 2026-05-29 (session 34 — NFQUEUE self-recovery on ENOENT)

The daemon crashed when the kernel invalidated the NFQUEUE binding (nftables table flushed, TUN interface removed, etc.) — `recv()` returned `ENOENT` (os error 2) and both `NfqueueProcessor::run_loop()` and `DnsSnoopWorker::run_loop()` terminated. The daemon kept running but without packet interception, silently becoming a no-op. A second bug in the initial recovery attempt caused `EPERM` on socket reopen because the old binding was never released.

- [x] **Root cause (two bugs):**
  1. `run_loop()` propagated all `recv()` errors upward, terminating the thread. No restart mechanism existed.
  2. `reopen()` created a new `Queue::open()` + `bind()` while the old `self.queue` still held the kernel binding. The kernel only allows one binding per queue number, so `bind()` returned `EPERM`.

- [x] **Fix — three-tier error handling in `run_loop()`:**
  - `ENOENT` (queue binding invalidated): calls `recover(queue_num)` to re-apply nftables, then `unbind()` + `Queue::open()` + `bind()` to get a fresh socket. Retries with exponential backoff (100ms → 30s cap) on any failure.
  - `EINTR` / `ENOBUFS` / `EWOULDBLOCK`: simple retry with backoff on the same socket (self-correcting).
  - Fatal errors (`EBADF`, etc.): terminate the loop as before.

- [x] **`run_loop()` now accepts `queue_num` and `recover` callback.** The daemon passes `|q| bootstrap.setup(Some(q), route_mark_base)` for both the main NFQUEUE processor and the DNS snoop worker. This re-creates the full `inet netkeep` nftables table (idempotent) including `queue num N` rules.

- [x] **`reopen()` unbinds before opening.** `queue.unbind(queue_num)` releases the kernel binding, then the old socket is dropped, then a fresh `Queue::open()` + `bind()` claims the now-free binding.

- [x] **New helpers:** `is_queue_invalidated_error()` (ENOENT) and `is_transient_netlink_error()` (EINTR, ENOBUFS, EWOULDBLOCK) — `pub(crate)` in `nfqueue.rs`, shared with `dns_snoop.rs`.

- [x] **Files:** `crates/enforcer/src/nfqueue.rs`, `crates/enforcer/src/dns_snoop.rs`, `apps/daemon/src/main.rs`.

- [x] **Tests:** 168 passing (167 + 1 new: `transient_error_detection` covering ENOENT/EINTR/ENOBUFS/EWOULDBLOCK classification and safety negatives).

- [x] **Documentation:** `docs/nfqueue-packet-interception.md` — new "NFQUEUE Error Recovery" section with error classification table, ENOENT recovery flow diagram, and wiring details.

### 2026-05-31 (session 35 — SOCKS5/HTTP proxy client routing)

Implements actual proxy routing for `RouteTarget::Proxy(id)`. Previously the proxy entity (CRUD, persistence, settings UI) was fully built but routing through the proxy was a stub returning `"proxy routing not yet implemented"`.

- [x] **New crate: `crates/proxy-client/`.** Synchronous SOCKS5 (RFC 1928/1929) and HTTP CONNECT (RFC 7231 §4.3.6) client. No async runtime dependency — uses `socket2`-compatible `TcpStream` with configurable timeout. Public API:
  - `connect_via_proxy(proxy, host, port, timeout) -> Result<TcpStream, ProxyClientError>`
  - Error types: `Io`, `Protocol(msg)`, `AuthRejected`, `UnsupportedProtocol`, `ConnectTimeout`
  - SOCKS5: greeting → method negotiation → optional username/password auth → CONNECT command with IPv4/IPv6/domain address types → reply parsing with bound-address consumption
  - HTTP CONNECT: `CONNECT host:port HTTP/1.1` with optional `Proxy-Authorization: Basic` header → 200 status check → header skip
  - Shadowsocks: returns `UnsupportedProtocol` (cipher/stream layer not yet implemented)

- [x] **Daemon relay wiring (`apps/daemon/src/main.rs`).** `open_routed_tcp` now handles `RouteTarget::Proxy(id)`:
  - Loads the proxy config from SQLite via `load_proxy_config(db_path, id)`
  - Calls `proxy_client::connect_via_proxy` to establish the tunnel
  - Skips local DNS resolution for proxy targets — SOCKS5 sends the domain to the proxy (proxy-side resolution), and HTTP CONNECT includes the domain in the request line. This avoids DNS leaks through the local resolver.
  - The local relay (`TcpListener::bind("127.0.0.1:0")` + bidirectional byte copy) is unchanged

- [x] **NFQUEUE verdict path for proxy-routed packets — transparent proxy.** When a packet matches a Route rule whose egress resolves to `RouteTarget::Proxy`, the NFQUEUE path stamps a special `PROXY_REDIRECT_MARK` (route_mark_base - 1) instead of a routing fwmark. A new nftables nat chain `output_proxy_redirect` (priority -50) REDIRECTs these marked packets to the transparent proxy port. The transparent proxy uses `SO_ORIGINAL_DST` to recover the original destination, then tunnels through SOCKS5/HTTP.
  - `PROXY_REDIRECT_MARK` is deliberately below `ROUTE_MARK_BASE` so it bypasses all the save/restore/masquerade chains (which only match `>= base`)
  - `TransparentProxy` server in `proxy-client::transparent`: accepts redirected connections, reads original destination via `SO_ORIGINAL_DST`, connects through the configured SOCKS/HTTP proxy, relays bytes bidirectionally
  - The transparent proxy starts automatically when enabled proxies exist in the DB; binds to `127.0.0.1:0` (OS-assigned port)
  - `set_route_mark_fn` in the daemon returns `Some(PROXY_REDIRECT_MARK)` for proxy targets (instead of `None`)
  - `NftablesBootstrap::setup` signature extended with `transparent_proxy_port: Option<u16>` parameter
  - `DaemonRuntime` stores `transparent_proxy_port` for recovery callbacks

- [x] **Removed empty `crates/socks5-client/` directory** (pre-existing placeholder).

- [x] **Tests:** 180 passing (168 + 12 new in `proxy-client`). New tests cover SOCKS5 greeting encoding (no-auth vs username/password auth), CONNECT request formatting (IPv4, IPv6, domain), HTTP CONNECT request construction (with and without Basic auth), response status parsing (200 and 407), Shadowsocks unsupported protocol rejection, and `SO_ORIGINAL_DST` constant verification.

- [x] **Files:** `crates/proxy-client/Cargo.toml`, `crates/proxy-client/src/lib.rs`, `Cargo.toml` (workspace member), `apps/daemon/Cargo.toml` (dependency), `apps/daemon/src/main.rs` (relay wiring + route_mark_fn).

### 2026-06-01 (session 36 — transparent proxy hardening)

Bug fixes for the NFQUEUE transparent proxy path. The transparent proxy was accepting connections but failing to relay through SOCKS5 due to multiple issues:

- [x] **SOCKS handshake I/O timeout.** After `socket2::connect_timeout` established the TCP connection, the SOCKS5 greeting/method-selection/CONNECT exchange used blocking `read_exact()` with no timeout. If wireproxy was unresponsive, the transparent proxy hung indefinitely. Fix: set read/write timeouts on the TcpStream before handshake, map `TimedOut` to `ConnectTimeout`, clear timeouts after handshake for unthrottled relay.
- [x] **`IP_TRANSPARENT` socket option.** The transparent proxy listener was a plain `TcpListener::bind()`. Linux requires `IP_TRANSPARENT` on the listening socket for nftables `REDIRECT` to deliver connections. Fix: `bind_transparent_listener()` uses `socket2` + `libc::setsockopt(SOL_IP, IP_TRANSPARENT=19)`.
- [x] **IPv6 `SO_ORIGINAL_DST`.** Only `SOL_IP` was tried for original-destination lookup. IPv6 connections would fail. Fix: try `SOL_IP` first, fall back to `IPPROTO_IPV6`.
- [x] **NFQUEUE re-queuing proxy-marked packets.** `PROXY_REDIRECT_MARK` (below `ROUTE_MARK_BASE`) was not matched by any bypass rule, so follow-on data segments were re-queued and could be dropped. Fix: `meta mark {PROXY_REDIRECT_MARK} accept` before the `queue num` rule.
- [x] **Silent misconfiguration warning.** When transparent proxy starts but `NETKEEP_NFQUEUE` is unset, daemon now prints a warning.

- [x] **Tests:** 180 passing (no new tests; existing tests cover the unchanged protocol logic).

### 2026-06-01 (session 37 — eBPF DNS tracker + DNS forwarder for egress routing)

Architecture: [`docs/dns-forwarder.md`](docs/dns-forwarder.md)

Problem: Apps resolve DNS through the default system resolver, getting fake IPs from throne/VPN (e.g. `10.10.34.36` for all blocked domains). The transparent proxy connects to fake IPs through SOCKS, which fails. The 1:1 `SniDnsCache` is unreliable when throne returns the same IP for every domain.

Solution: DNS forwarder on `127.0.0.1:53` that intercepts DNS queries, identifies the source process via eBPF, matches against routing rules, and resolves through the correct egress's DNS servers. Apps get real IPs, transparent proxy sends hostnames to SOCKS.

- [x] **eBPF DNS tracker** (`crates/dns-tracker-ebpf/` + `crates/dns-tracker-common/` + `crates/dns-tracker/`):
  - Kernel-space kprobe on `udp_sendmsg`: captures PID (`bpf_get_current_pid_tgid`), process name (`bpf_get_current_comm`), and DNS query domain (parsed from UDP payload)
  - Filters for `dport == 53`
  - Writes to BPF HashMap: `(src_ip, src_port) → (pid, comm, domain)`
  - Userspace loader: `aya::Ebpf`, attach kprobe, expose `DnsTracker::lookup(src_ip, src_port) → Option<DnsQueryInfo>`
  - Build: stable toolchain + `bpfel-unknown-none` target + `bpf-linker`, using `-Z build-std=core` unlocked via `RUSTC_BOOTSTRAP=1` (no nightly)

- [x] **DNS forwarder** (`crates/dns-tracker/src/forwarder.rs`):
  - UDP server on `127.0.0.1:53`
  - Per-query dispatch: eBPF lookup → process + domain → rule match → resolve through egress DNS
  - Proxy egress: DNS-over-SOCKS5 (TCP with 2-byte length prefix)
  - Tun egress: `SO_MARK` on outbound UDP socket for policy routing
  - Device egress: `SO_BINDTODEVICE` on outbound UDP socket
  - No match: forward to system DNS
  - Populates shared `SniDnsCache` from DNS response A/AAAA records
  - Proxy configs cached in-memory to avoid per-query SQLite opens

- [x] **Daemon integration** (`apps/daemon/src/main.rs`):
  - Start eBPF DNS tracker at boot
  - Start DNS forwarder on `127.0.0.1:53`
  - Share `SniDnsCache` between DNS forwarder, NFQUEUE processor, and DNS snoop
  - Rule-matching closure for `(process, domain) → egress`
  - `FwmarkResolver` closure for `RouteTarget → fwmark` (Tun egress DNS)

- [x] **Build infrastructure**: `xtask/` for BPF bytecode compilation, `aya` dependency

### 2026-06-02 (session 38 — code review fixes for sessions 35–37)

Review: [`plans/code-review-session-35-37.md`](plans/code-review-session-35-37.md)

- [x] **SO_MARK in `resolve_via_so_mark()`**: Tun egress DNS now sets `SO_MARK` via `libc::setsockopt` on the outbound UDP socket, routing DNS queries through the correct policy routing table
- [x] **Wire `SniDnsCache` into DNS forwarder**: Forwarder parses A/AAAA records from DNS responses and populates the shared IP→domain cache; daemon creates one shared cache for forwarder + NFQUEUE + DNS snoop
- [x] **Cache proxy configs**: `resolve_via_proxy()` checks in-memory cache before opening SQLite; first query loads from DB, subsequent queries hit cache
- [x] **Remove unused deps**: Removed `enforcer` and `policy-engine` from `dns-tracker/Cargo.toml`
- [x] **Delete dangling doc comment**: Removed orphan `/// Detect local interfaces` comment from `main.rs`
- [x] **Fix `architecture.md`**: Replaced `dns-forwarder/` entry with `dns-tracker/` (forwarder is a module inside dns-tracker)
- [x] **`cargo fmt --all`**: Fixed indentation and formatting across workspace

**Deferred** (tracked in review doc):
- IPv6 DNS forwarder: add debug log for dropped queries
- eBPF BTF: runtime validation of hardcoded struct offsets
- EDNS0: bump `DNS_BUF` from 512 to 4096
- Socket pooling in `forward_udp()`

### 2026-06-02 (session 39 — eBPF socket tracker for 100% process detection)

**Goal:** Eliminate process detection failures by capturing PIDs at the kernel level before NFQUEUE delivers packets.

- [x] **SOCK_DIAG dual-family query** (`sock_diag.rs`): Query both `AF_INET` and `AF_INET6` for any source IP. Many apps use `AF_INET6` sockets with `IPV6_V6ONLY=0` for IPv4 connections — the kernel stores these as `::ffff:a.b.c.d` in the IPv6 table. Previously only queried one family.
- [x] **SOCK_DIAG UDP wildcard retry** (`sock_diag.rs`): Retry with `INADDR_ANY` (0.0.0.0) when specific-IP queries fail for UDP/QUIC. UDP sockets often bind to the wildcard address.
- [x] **eBPF socket tracker program** (`dns-tracker-ebpf/src/sock_tracker.rs`): New BPF program with three hooks:
  - `tracepoint:sock:inet_sock_set_state` — captures PID at TCP `SYN_SENT`
  - `kprobe:udp_sendmsg` — captures PID at every UDP send
  - `kprobe:udp_lib_unhash` — cleans up stale entries on socket close
  - Uses `SOCK_EVENTS` BPF HashMap (16384 entries) keyed by `(src_ip[16], src_port, protocol)`
- [x] **Userspace SockTracker loader** (`dns-tracker/src/sock_tracker.rs`): Loads BPF program, attaches hooks, provides `lookup_pid()`. Implements `flow_classifier::SocketTracker` trait.
- [x] **SocketTracker trait** (`flow-classifier/src/lib.rs`): New trait for dependency inversion — `flow-classifier` defines the trait, `dns-tracker` implements it. Avoids circular dependencies.
- [x] **ProcProcessResolver integration** (`proc_resolver.rs`): New Step 0 — check eBPF map before SOCK_DIAG. Metrics: `netkeep.proc.resolver.ebpf.hits` / `misses`.
- [x] **Daemon integration** (`main.rs`): Loads `SockTracker` at startup, passes to `ProcProcessResolver::with_sock_tracker()`. Graceful fallback on eBPF load failure.
- [x] **xtask build**: Updated to build both `dns-tracker-ebpf` and `sock-tracker-ebpf` binaries.
- [x] **Tests**: 4 new tests for `build_sock_key()` (IPv4→mapped IPv6, IPv6 raw, QUIC→UDP protocol, Other→0). All 180 workspace tests pass.
- [x] **Documentation**: Updated `process-resolver.md`, `process-attribution-races.md` (Layer −1).
- [x] **DNS forwarder retry logic** (`forwarder.rs`): `forward_udp()` now retries up to 2 times on timeout (EAGAIN) with 3s per-attempt timeout. Previously a single 8s attempt with no retry — standard DNS clients retry because UDP is unreliable.
- [x] **DNS tracker wildcard fallback** (`tracker.rs`): `DnsTracker::lookup()` now tries `0.0.0.0` (INADDR_ANY) key when the specific-IP lookup fails. Auto-bound UDP sockets have `skc_rcv_saddr = 0.0.0.0` even when the actual packet source IP is `127.0.0.1`. This fixed the DNS forwarder attributing queries to `netkeep-daemon` instead of the real client (e.g. `chromium`).

### 2026-06-05 (session 38 — proxy/egress connectivity test modal)

New feature: "Test" button on each proxy and egress table row in the settings GUI. Opens a modal dialog for testing proxy connectivity via HTTP/HTTPS and DNS.

- [x] **Control API** (`crates/control-api/src/lib.rs`):
  - New `ControlRequest::TestProxyHttp { proxy_id, url }` — test HTTP/HTTPS connectivity through a proxy.
  - New `ControlRequest::TestProxyDns { proxy_id, domain }` — test DNS resolution through a proxy (via 8.8.8.8:53).
  - New `ControlResponse::ProxyTestResult { success, latency_ms, error }` — result for both test types.
  - Validation: rejects empty proxy_id, url, and domain.

- [x] **Proxy client test functions** (`crates/proxy-client/src/lib.rs`):
  - `test_http_connectivity(proxy, url, timeout)` — connects via proxy to port 80 (always, since we send plain HTTP without TLS), sends HTTP HEAD, measures round-trip latency in ms.
  - `test_dns_connectivity(proxy, domain, timeout)` — connects to 8.8.8.8:53 via proxy, sends DNS A query over TCP, measures round-trip latency in ms. Uses resilient `read()` loop instead of `read_exact()` to handle partial responses and early EOF gracefully.
  - `parse_test_url(url)` — extracts (host, port, is_https) from HTTP/HTTPS URLs.
  - `build_dns_a_query(domain)` — builds a minimal DNS A query wire-format packet.

- [x] **Control service handler** (`crates/control-service/src/lib.rs`):
  - `TestProxyHttp`: looks up proxy by ID → calls `proxy_client::test_http_connectivity` → returns `ProxyTestResult`.
  - `TestProxyDns`: looks up proxy by ID → calls `proxy_client::test_dns_connectivity` → returns `ProxyTestResult`.
  - 10-second timeout per test.
  - Added `proxy-client` dependency to `control-service/Cargo.toml`.

- [x] **Proxy table "Test" button** (`apps/gpui/src/settings/proxies_tab.rs`):
  - Added teal "Test" button in Controls column alongside Edit/Toggle/Delete.
  - On click: sets `SettingsState.proxy_test_request = Some(proxy)` + `cx.notify()`.
  - Controls column widened from 180px to 240px.

- [x] **Egress table "Test" button** (`apps/gpui/src/settings/egress_tab.rs`):
  - Added teal "Test" button for egresses that contain at least one `RouteTarget::Proxy(_)` target.
  - On click: resolves first proxy target from egress → sets `SettingsState.egress_test_request = Some(egress)` + `cx.notify()`.
  - Controls column widened from 160px to 220px.

- [x] **Settings state** (`apps/gpui/src/settings/mod.rs`):
  - New `SettingsState.proxy_test_request: Option<ProxyConfig>` — side-channel for proxy test.
  - New `SettingsState.egress_test_request: Option<Egress>` — side-channel for egress test.
  - Observer drains test requests and opens the test dialog.

- [x] **Test modal dialog** (`apps/gpui/src/settings/mod.rs::open_proxy_test_dialog`):
  - Shows proxy name, protocol badge, and host:port at the top.
  - URL input (default `http://www.google.com`) + "Test HTTP" button — always connects to port 80 since no TLS is performed.
  - Domain input (default `google.com`) + "Test DNS" button — sends DNS A query to 8.8.8.8:53 through the proxy tunnel.
  - Results area: green ✓ with latency in ms on success, red ✗ with error message on failure.
  - Loading states: ⏳ "Testing..." shown while async test is running (per-button `Arc<Mutex<bool>>` flags).
  - Async test execution: spawns background task → sends `TestProxyHttp`/`TestProxyDns` to daemon → updates shared result state → triggers dialog re-render.
  - Close button.

- [x] **CLI match arm** (`apps/cli/src/main.rs`):
  - Added `ControlResponse::ProxyTestResult` match arm to fix non-exhaustive pattern.

- [x] **Tests:** 18 new tests — 8 in `control-api` (validation + serialization), 8 in `proxy-client` (URL parsing, DNS query building), 2 in `proxy-client` (connectivity_tests). Workspace total **180 → 198** tests, no regressions.

- [x] **Build:** Full workspace `cargo build --workspace` and `cargo test --workspace` pass cleanly.

**Bug fixes (same session):**

- **HTTP test "failed to fill whole buffer":** `test_http_connectivity` was connecting to port 443 (from `https://` URL parsing) but sending a plain HTTP HEAD request — no TLS handshake. The server immediately closed the connection. Fixed by always using port 80 regardless of URL scheme, since we don't perform TLS. Default URL changed from `https://www.google.com` to `http://www.google.com` in the settings dialog.

- **DNS test "failed to fill whole buffer":** `test_dns_connectivity` used `read_exact()` which fails when the TCP stream gets EOF before the full buffer is filled (e.g., proxy closes connection mid-response, fragmented reads). Fixed by using `stream.read()` in a loop with `set_read_timeout()`, tolerating early EOF on the response body if ≥12 bytes (DNS header) are already received. Descriptive error messages replace raw IO errors.
