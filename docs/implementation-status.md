# LogiGuard Current Implementation State

**Test Status:** 180 tests passing (`cargo test --workspace`)
**Phase:** 4 / 5 (GPUI UI complete, rule scope selection implemented)
**Last Updated:** 2026-06-01

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
- [x] `RawPacket::tcp_fin` / `tcp_rst` flags to distinguish connection teardown from pure ACKs in verdict cache
- [x] Real ProcessResolver via `/proc/net/{tcp,tcp6,udp,udp6}` → inode → `/proc/<pid>/fd` → `/proc/<pid>/exe`
- [x] `ProcessInfo` struct: `{ name, exe: Option<String>, app_name: Option<String> }` returned by `resolve()`
- [x] `process_exe` stored in `Rule` and `FlowContext` as exe-path rule identity
- [x] `app_name` from `pacman -Qo <exe>` shown in decision dialog and daemon logs
- [x] `ss` fallback: `ss -Hnp [-t|-u] src :<port>` when `/proc/net` + inode scan both fail
- [x] IP-based attribution cache (`proc_attr`): `(dst_ip, dst_port) → CachedProcessAttr`, TTL 15 min, max 1024
- [x] Domain-based attribution cache (`domain_proc_attr`): `(domain, dst_port) → CachedProcessAttr`, TTL 1 hour, max 512 — handles CDN IP rotation
- [x] DNS snoop cache for UDP/QUIC domain inference via INPUT hook NFQUEUE (queue+1, bypass flag)
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
  - `settings/egress_tab.rs` — EgressDelegate (TableDelegate) with type badges, delete; ID is first column
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

## Bug Fixes (process-attribution races, 2026-05-13)

**Bug 12:** Duplicate decision dialogs for the same connection — one with a process name, one labelled `(unknown)`.
- **Root cause:** A three-layer race between NFQUEUE packet delivery and the kernel publishing socket entries to `/proc/net/{tcp,udp}*`. Two packets of the same connection could yield different `process_name` resolutions; the decision-engine's dedup index (keyed by `process_name`) treated them as different flows; after a rule was installed the policy engine still rejected later unattributed packets because `process_matches((Some, None)) → false`. See [`docs/process-attribution-races.md`](process-attribution-races.md).
- **Fix (3 layers):**
  1. `ProcProcessResolver` gained a `(src_ip, src_port, protocol) → name` cache (60 s TTL, 4096-entry cap). Retransmits of the same socket reuse the cached resolution instead of re-racing `/proc`.
  2. `DecisionEngine::register_unknown_flow` fallback dedup is now **symmetric**: when an "unknown" pending exists and a later packet with a real process name arrives for the same `(dst_ip, dst_port, protocol)`, the pending is **upgraded in place** (index re-keyed, `flow.process_name` patched). Two distinct *known* names still produce two pendings.
  3. `policy_engine::process_matches((Some, None))` now returns `true` when the rule's destination is `IpExact` or `DomainExact`. Broad rules (`Any`/`Cidr`/`Wildcard`) still require a strict process match so they cannot be silently piggy-backed by an unattributed packet.
- **Tests:** 12 new tests (3 in `flow-classifier`, 3 in `decision-engine`, 6 in `policy-engine` including safety negatives).

## Bug Fixes (wildcard rules, 2026-05-13)

**Bug 13:** `DomainWildcard` rules created via the decision dialog never matched. Every connection re-prompted the user, including subdomains the wildcard rule was supposed to cover. Apex requests were also un-matched (by design, but indistinguishable from the wildcard-broken case for the user).

- **Root cause — storage / match format mismatch.** Three writers stored the wildcard pattern in two different forms:
  - GPUI decision dialog (`apps/gpui/src/components/action_footer.rs::build_dest_matcher`) wrote `DomainWildcard(domain_apex(d))` — apex-only, no `*.` prefix.
  - CLI (`apps/cli/src/main.rs::parse_destination`) stripped `*.` before writing — also apex-only.
  - Settings form (`apps/gpui/src/settings/mod.rs`) wrote `dest_val` verbatim — sometimes with the prefix, sometimes without, depending on what the user typed.

  But `policy_engine::wildcard_matches` required the `*.` prefix (`pattern.strip_prefix("*.")` returned `None` otherwise and the function returned `false`). The two most common writers (decision dialog + CLI) silently produced rules that could never match. The bug had been latent since the wildcard chip was introduced.

- **Fix:**
  1. `wildcard_matches` now strips `*.` if present and treats the remainder as the apex (`pattern.strip_prefix("*.").unwrap_or(pattern)`). Empty patterns (including `"*."` alone) still match nothing — defensive guard against malformed imports.
  2. Settings form now strips `*.` on save so user-typed `*.foo.com` and `foo.com` produce identical rules. The display layer in `ds::dest_text` prepends `*.` for rendering, so the rule table shows `*.foo.com` regardless.
  3. Apex-not-matched semantic is preserved (per `docs/decision-dialog-ux.md`) — `*.example.com` matches subdomains only. Allowing the apex still requires a separate `DomainExact` rule. Flagged as a possible UX follow-up.

- **Tests:** 3 new tests in `policy-engine`:
  - `wildcard_matches_with_apex_only_storage_form` — locks in the production storage form (no prefix) for subdomain matches, deep-subdomain matches, apex non-match, and `notexample.com`-style substring safety.
  - `wildcard_matches_both_storage_forms_identically` — both `"foo.com"` and `"*.foo.com"` resolve to the same outcome.
  - `wildcard_empty_pattern_matches_nothing` — defensive guard.

## Bug Fixes (HTTP Host fallback for domain detection, 2026-05-13)

**Bug 16:** Plain HTTP flows (e.g. `curl google.com` on port 80) showed up in the decision dialog with no domain — just the destination IP.

- **Root cause:** Two compounding gaps in the domain-inference pipeline:
  1. `parse_raw_packet` in `crates/enforcer/src/nfqueue.rs` only called `extract_tls_sni`, so anything without a TLS ClientHello produced `sni_hint = None`.
  2. The nftables `output_early` chain unconditionally bypasses DNS (`udp dport 53 accept` / `tcp dport 53 accept`), so the daemon never sees DNS responses to populate `SniDnsCache` from there either.

  The net effect was an HTTP-only flow had no source of truth for its destination domain. Rules like `allow curl → google.com` couldn't match because `destination_domain = None`. (HTTPS always worked via SNI extraction; this was specifically a plaintext HTTP gap.)

- **Fix:** New `extract_http_host(payload)` in `crates/enforcer/src/nfqueue.rs` parses the `Host:` header from plaintext HTTP/1.x requests and feeds it into the same `sni_hint → SniDnsCache` pipeline that SNI uses. The parser:
  - Early-rejects payloads that don't start with a known HTTP method (`GET `, `POST `, `HEAD `, `OPTIONS `, `PATCH `, `CONNECT `, `TRACE `, …) so we don't substring-search arbitrary binary TCP.
  - Scans the first 4 KiB only (bounded cost; well above realistic HTTP header sizes).
  - Searches for `\r\nhost:` case-insensitively, skipping the request line so absolute-form URLs don't shadow the actual header.
  - Strips optional `:port` suffix and bracketed IPv6 literals (`[2001:db8::1]:8443` → `2001:db8::1`).
  - Validates against a conservative hostname character set to reject coincidental `\r\nHost:` byte sequences in non-HTTP traffic.
  - Lowercases the result so wildcard matching is stable.

  Once `sni_hint` is populated by either source, `SniDnsCache` records `dst_ip → host` so subsequent connections to the same IP — HTTPS or HTTP — also resolve. TLS SNI still wins when present (more authoritative); HTTP is the fallback.

- **Tests:** 12 new tests in `nfqueue::tests::http_host_*` covering the happy path, case-insensitivity, IPv4/IPv6 port stripping, CONNECT proxies, multi-header ordering, truncation safety, garbage rejection, and explicit negatives against TLS payloads and non-HTTP TCP bytes.

- **Field rename:** kept the historical `RawPacket.sni_hint` and `FlowContext.sni_hint` field name (would have rippled through too many crates for an incidental rename); updated the doc-comment in `crates/flow-classifier/src/lib.rs` to call out that the field now holds either source.

- **Still uncovered:** QUIC (SNI is encrypted), plain UDP services, non-HTTP/non-TLS TCP (SSH, raw protocols). Those would need a DNS snoop cache — flagged in [`docs/nfqueue-domain-inference.md`](nfqueue-domain-inference.md).

## Bug Fixes (settings resize + NFQUEUE tray toggle, 2026-05-13)

**Bug 14:** Settings window pinned at its initial 960×720 with no way to resize.
- **Root cause:** On GNOME / Mutter (Wayland), the compositor refuses `xdg-decoration` server-side requests and forces client-side decorations. The settings root view rendered `gpui_component::TitleBar` but never wrapped its content in `gpui_component::window_border()`, so there was no edge hitbox calling `window.start_window_resize(edge)` and the cursor never switched on the edges.
- **Fix:** Wrapped the settings root in `window_border()`; explicitly requested `WindowDecorations::Client` and `is_resizable: true` in `WindowOptions`; set `window_min_size = 640×420` to keep table headers and the tab bar usable. No new tests — manual resize confirms the fix.

**Bug 15:** "Enable Network Interception" tray menu item appeared to do nothing.
- **Root cause:** The `SetNfqueueEnabled` handler flipped an `AtomicBool` in `ControlService` and returned `Ok`. Nothing about nftables, the running `NfqueueProcessor`, or the kernel changed — but `Health` reported the new flag, so the GUI claimed the toggle had worked. Symptom looked "unreliable" because actual interception state was determined entirely by whether `LOGIGUARD_NFQUEUE` was set at boot.
- **Fix:** The handler now re-applies the `inet logiguard` nftables table via `NftablesBootstrap::setup(queue, route_mark_base)` — `Some(n)` adds `queue num n` rules, `None` removes them — and only commits the cached flag in `ControlService` after the kernel update succeeds. A new pure helper `plan_nfqueue_toggle(bootstrap_present, nfqueue_num, enabled) -> NfqueueToggleAction` decides between `Apply` and `Reject` so the (bootstrap, queue, enabled) matrix is exhaustive and unit-testable. Two reject paths: nftables didn't install at boot, or `enabled=true` was requested without `LOGIGUARD_NFQUEUE` (which would queue packets to a number nobody is draining → kernel drops everything). Each reject returns an actionable error message; no state mutates on reject.
- **Tests:** 4 new tests in `apps/daemon/src/main.rs::tests` covering both reject paths and both apply paths. First unit tests this binary has ever had.

## Bug Fixes (process resolver + DB path + egress seeding, 2026-05-14)

**Bug 20:** Process name "unknown" for apps using `AF_INET6` sockets to reach IPv4 destinations.

- **Root cause:** `find_socket_inode` only checked the address-family-matching `/proc/net` file. Apps with `IPV6_V6ONLY=0` appear in `/proc/net/tcp6` as `::ffff:a.b.c.d` even for IPv4 connections, so an IPv4 src_ip lookup in `/proc/net/tcp` only would always miss them.
- **Fix:** `find_socket_inode` now checks both files for any src_ip (matching family first). New `parse_hex_addr()` collapses IPv4-mapped entries to `IpAddr::V4`; `parse_proc_net` handles all four cross-family combinations. Parent fallback threshold changed from `len <= 3` to an explicit shell allowlist (`sh/bash/dash/zsh/fish`) so three-char names like `ssh`/`git`/`bun` keep their own identity. Retry delays extended to `[0, 5, 15, 40]ms` (4 attempts, 60 ms worst case).
- **Test:** `ipv4_address_matches_ipv4_mapped_entry_in_tcp6`.

**Bug 21:** Fresh DB has no egresses beyond `eg-default`; users could not route without manually creating egresses.

- **Fix:** `seed_initial_egresses()` runs on first startup: LAN via `ip route get 8.8.8.8`, TUN interfaces via `/sys/class/net/*/type = 65534`. Seeding is skipped once any user egress exists.

## Bug Fixes (ACK eviction + Electron fd gap, 2026-05-15)

**Bug 22:** `process=None` on follow-up packets for multi-process apps (e.g. Electron/Cursor), producing a second `(unknown)` decision dialog for a connection the user had already approved.

- **Root cause (compound):**
  1. **ACK eviction bug.** `NfqueueProcessor::decide()` used the `tcp_payload_empty` guard to evict the 5-tuple verdict cache. Pure ACKs (client acknowledging server data) have empty payloads and triggered the guard, evicting the cache and forcing full re-classification of the next data packet on every ACK/data alternation. This re-ran `ProcProcessResolver` far more often than necessary.
  2. **No retry in `find_pid_for_inode`.** The inode→pid scan had no retry, unlike `retry_find_socket`. Electron's `--type=utility` network-service subprocess has a brief `fork`→`exec` window where its fds are absent from `/proc/<pid>/fd/`. The ACK eviction guaranteed that re-classification would hit this window frequently.

- **Fix:**
  1. `RawPacket` gained two new fields: `tcp_fin: bool` and `tcp_rst: bool`, populated from `etherparse::TcpHeaderSlice`. `decide()` now evicts the verdict cache only on FIN/RST (connection closing). Pure ACKs consult the cache without evicting it.
  2. `find_pid_for_inode` gained a `[0, 3, 8]` ms retry loop, matching the pattern already used by `retry_find_socket` for the `/proc/net/tcp` lookup.

- **Tests:** All 143 existing tests pass; no new tests added (the invariants are already covered by the three-layer race test suite added for Bug 12).

- **Docs:** `docs/nfqueue-packet-interception.md` TCP handling section rewritten; `docs/process-resolver.md` lookup chain and Race Conditions section updated; `docs/process-attribution-races.md` Bug 22 worked example added.

## Process Resolver: exe-path identity + app_name + ss fallback + attribution caches (2026-05-17)

**Bug 24:** One-off `process=None` mid-session for long-running flows (e.g. YouTube video) when CDN rotates IP addresses.

- **Root cause:** The per-socket resolver cache (Layer 1) and the three attribution layers only help with retransmits of *existing* sockets. When Chromium opens a brand-new connection to a *different CDN IP* serving the same domain (googlevideo.com CDN rotation), the new socket races `/proc` fresh. If it loses, `process_name = None` produces an `(unknown)` prompt even though the user already approved Chromium for that domain.
- **Fix (nfqueue-level Layer 0 caches):**
  - IP-based: `(dst_ip, dst_port) → CachedProcessAttr`, TTL 15 min, max 1024. Filled on every successful classification; consulted when `process_name` is None after classify.
  - Domain-based: `(domain, dst_port) → CachedProcessAttr`, TTL 1 hour, max 512. Filled when a successful classification has a destination domain; handles CDN IP rotation by keying on the stable domain rather than the rotating IP.
- **Files:** `crates/enforcer/src/nfqueue.rs`.

**Improvements:** `ProcessInfo` struct, exe-path rule identity, `app_name` from `pacman -Qo`, `ss` fallback.

- **`ProcessInfo { name, exe, app_name }`** — `resolve()` now returns `Option<ProcessInfo>` instead of `Option<String>`. `exe` is the full `/proc/<pid>/exe` path; `app_name` is the package manager name when it differs from `name`.
- **`process_exe` in `Rule` and `FlowContext`** — stored as the primary rule identity. `policy_engine::process_matches` prefers exe-path equality when both the rule and flow have it, falling back to name comparison.
- **`app_name` from `pacman -Qo <exe>`** — shown in the decision dialog as a secondary line (`pkg: cursor-bin`) and in daemon logs as `(cursor-bin)`. Cached per exe-path in `pacman_cache`. Suppressed when it equals the process name.
- **`ss` fallback** — `ss -Hnp [-t|-u] src :<port>` tried when the full `/proc/net` + inode scan fails all retries. Parses `pid=N` from the `users` field.
- **DB migration** — `ALTER TABLE rules ADD COLUMN process_exe TEXT NULL` on startup.
- **Tests:** 164 total (was 163). 1 new test for `ss_local_matches` IPv4-mapped handling.
- **Docs:** `docs/process-resolver.md` lookup chain and ProcessInfo section updated; `docs/process-attribution-races.md` Bug 24 entry added.

**Bug 25:** Domain detection randomly fails for CDN IPs that serve multiple domains.

- **Root cause:** `SniDnsCache` is a 1:1 map (`IP → domain`). CDN IPs (Cloudflare, CloudFront, etc.) serve many domains. When `api2.cursor.sh` and `api3.cursor.sh` both resolve to the same IP, the DNS snoop worker overwrites the cache. The next TLS ClientHello with a different SNI triggers the conflict check in `resolve_domain()` — DNS cache says one domain, SNI says another — both are discarded, yielding `domain=None`. The race is also cross-thread: the DNS snoop worker can overwrite the cache between the NFQUEUE's `insert()` and `classify()`'s `lookup()`.
- **Fix:** `FlowClassifier::resolve_domain()` now trusts the per-packet SNI/Host when present (authoritative, extracted from the actual packet). DNS cache is only used as a fallback when no SNI/Host is in the packet. The conflict check `(Some(dns), Some(sni)) => None` is removed — it was protecting against DNS spoofing but in practice the "spoofed" value was always a different customer on the same CDN IP. QUIC still uses DNS-cache-only (SNI encrypted in QUIC v1).
- **Files:** `crates/flow-classifier/src/lib.rs`.
- **Tests:** +1 (old conflict test split into 2). 164 → 165.
- **Docs:** `docs/nfqueue-domain-inference.md` Domain Resolution Priority rewritten; `docs/architecture.md` design decision #3 rewritten.

**Process resolver (2026-05-19):** SOCK_DIAG netlink is now the primary inode lookup (`crates/flow-classifier/src/sock_diag.rs`), before `/proc/net` retries and `ss` fallback. Mitigates kernel-publishing TOCTOU on first packets of new connections. See `docs/process-resolver.md`.

**Bug 26 (2026-05-29): Daemon crashes when NFQUEUE binding invalidated (ENOENT).**

- **Root cause (compound):**
  1. `NfqueueProcessor::run_loop()` and `DnsSnoopWorker::run_loop()` propagated all `recv()` errors upward, terminating the thread. When the kernel invalidated the NFQUEUE binding (nftables table flushed, TUN interface removed, kernel module reloaded), `recv()` returned `ENOENT` and the processor thread died. The daemon kept running but without packet interception — a silent failure.
  2. Initial recovery attempt failed with `EPERM` because `reopen()` created a new `Queue::open()` + `bind()` while the old socket still held the kernel binding. The kernel only allows one binding per queue number.

- **Fix:** `run_loop()` now accepts a `recover(queue_num)` callback and handles errors in three tiers:
  - `ENOENT` (queue invalidated): calls `recover()` to re-apply nftables, then `unbind()` + `Queue::open()` + `bind()`. Retries with exponential backoff (100ms → 30s cap) on failure.
  - `EINTR` / `ENOBUFS` / `EWOULDBLOCK`: simple retry with backoff (transient, self-correcting).
  - Fatal errors (`EBADF`, etc.): terminate the loop.
  The daemon passes `|q| bootstrap.setup(Some(q), route_mark_base)` as the recover callback, which re-creates the full `inet logiguard` nftables table (idempotent).
- **Files:** `crates/enforcer/src/nfqueue.rs`, `crates/enforcer/src/dns_snoop.rs`, `apps/daemon/src/main.rs`.
- **Tests:** +1 (`transient_error_detection`). 167 → 168.
- **Docs:** `docs/nfqueue-packet-interception.md` — new "NFQUEUE Error Recovery" section.

## Settings UI Polish (2026-05-16)

Four improvements to the settings window applied to both `design/settings_window.html` and the Rust implementation.

**Egress table — ID column.** Removed the unused `PRIORITY` column; added an `ID` column as the first column (col-span-2 in HTML, 90px in `egress_tab.rs`). `NAME` no longer shows an inline `(id)` sub-text. Column grid still sums to 12.

**Egress modal — TYPE button height.** The `TUN`/`DEV`/`PROXY` type-selector buttons were shorter than the adjacent `<select>` element (`py-1` vs the taller select). Changed to `py-1.5` so the row is visually uniform.

**Egress form dialog — per-target list editor.** Replaced the free-text CSV input for targets with an interactive list: existing targets render as badge + name + ✕ remove button; below is an inline add-form with type buttons + interface input + ADD button. Uses `Arc<Mutex<Vec<String>>>` for interior mutability inside the `Fn` dialog closure. Files: `settings/mod.rs` (`open_egress_form_dialog`).

**Rules form dialog — egress selector.** Replaced the free-text route-target input with one button per non-system egress (highlighted when selected). Available egresses are captured at dialog-open time from `self.state.read(cx).egresses`. Empty list shows a "No egresses configured" hint. Uses `Arc<Mutex<String>>` for the selected egress id. Files: `settings/mod.rs` (`open_rule_form_dialog`).

## Bug Fixes (decision dialog + settings focus, 2026-05-13)

**Bug 17:** Decision dialog clips action footer when many egress entries present.
- **Root cause:** Window height was hardcoded at 580px. The root container used `h_full()` + `overflow_hidden()`, which clipped children exceeding the window height. With 3+ egress chips, the Allow/Deny buttons pushed below the visible area.
- **Fix:** Removed `h_full()` and `overflow_hidden()` from the root container. Window height is now estimated dynamically from actual component padding/gap values (~600px base + 28px per egress chip row + 24px for device label), capped at 90% of primary display height.
- **Files:** `apps/gpui/src/app.rs`, `apps/gpui/src/main.rs`.

**Bug 18:** Default Route not first in "Route via" selector.
- **Root cause:** `ListEgresses` in the daemon sorts by `id` alphabetically, so `eg-default` could come after `eg-eth0`. The decision dialog always used `selected_egress_index = 0`, which might not be the default.
- **Fix:** Egresses are sorted after fetching: system default first, then available, then unavailable. `selected_egress_index = 0` is now always the Default Route.
- **Files:** `apps/gpui/src/main.rs`.

**Bug 19:** Settings window doesn't focus when "Settings…" is re-clicked from tray on GNOME/Wayland.
- **Root cause:** GPUI's `activate_window()` requests an `xdg-activation` token from the compositor, but Mutter rejects it because the settings process has no recent user-interaction serial (the click happened in the tray process, a different Wayland surface). The activation is silently ignored.
- **Fix:** The tray process (which has GTK initialized with the user's click serial) obtains an xdg-activation token via `GdkAppLaunchContext::startup_notify_id()` and sends it to the settings process via Unix socket. The settings process sets `XDG_ACTIVATION_TOKEN` and calls `activate_window()`. Even when Mutter rejects full activation, it uses the `app_id` to show an urgency/attention indicator in the taskbar. Settings window state is fully preserved.
- **Files:** `apps/gpui/src/main.rs`.

## Bug Fixes (routing, 2026-05-09)

**Bug 10:** SOCKS `Route` → Tun exited via LAN (Digikala saw Iranian IP / HTTP 200 instead of VPN/geo edge). Daemon reused WireGuard’s discovered fwmark from `ip rule`; that mark often means **split-tunnel bypass**, so marked packets followed **`main`** → **`wlp`**, not the tunnel.

- **Fix:** Tun upstream sockets use only **`ensure_route_mark(RouteTarget::Tun)`** (managed `default dev <tun>` table). Removed heuristic fwmark discovery for Tun connects.

**Bug 11:** Two equally specific `Route` rules (e.g. demo tun + demo wifi rows) produced **non-deterministic** winners depending on SQLite iteration order.

- **Fix:** `resolve_action` compares `(specificity, action_rank, rule.id)`; greater `id` wins when the first two tie.

## Bug Fixes (routing, 2026-05-17)

**Bug 12:** Direct application `Route` (e.g. `curl https://www.digikala.com` matching a `Route via LAN` rule, no `SO_MARK` on the socket) silently exited via the **VPN** instead of LAN, even with the egress correctly configured. Symptom: `Established connection ... from <VPN-IP>` on the curl side, or — once partial fixes were in place — TCP handshake completing on VPN, TLS handshake timing out, curl `(28)` after 10s.

Compound bug — five interacting failure modes:

1. **`output_early` was `type filter`.** Setting a verdict mark from NFQUEUE userspace didn't trigger any reroute, so the packet exited whichever interface the original (pre-mark) routing decision chose. Initial fix: change to `type route`. Insufficient on its own — see #2.
2. **`type route` + NFQUEUE-set mark do not compose.** The kernel's `nf_route_table_hook4` runs its pre/post mark-change check on the return path of `nft_do_chain`. When the chain returns `NF_QUEUE` the function exits there; after `nf_reinject()` the iterator resumes at the *next* hook entry, so the chain that queued the packet never sees the verdict-mark. **Fix:** a three-chain dance — `output_early` (route, NFQUEUE) → `output_save_mark` (filter, -125; meta→ct, clear meta) → `output_reroute` (route, -100; restore meta from ct). The mark write is now *inside* a later route chain's own `nft_do_chain`, so its post-check sees pre=0 vs post=X and fires `ip_route_me_harder()`.
3. **`ip_route_me_harder()` updates dst but not src.** Reroute landed the packet on `enp3s0`, but the source IP was still the VPN's CGNAT address, dropped at ISP egress (BCP38) and producing asymmetric return paths. **Fix:** new `postrouting` chain (`type nat hook postrouting priority srcnat`) with `meta mark >= base oifname != "lo" masquerade` (plus a `ct mark >= base` twin for the relay path where `output_nat` overwrote `meta mark` with `0x2024`). Conntrack records the SNAT once at NEW; reverse-NAT on the return path is transparent to the application.
4. **SYNs were short-circuited (`tcp_payload_empty` → Accept, no mark).** Even after #1–#3, the SYN still went out unmarked. Conntrack-NAT freezes the no-NAT decision at the conntrack-NEW packet, so a later data packet's mark could not undo that. **Fix:** classify SYNs. New `tcp_syn: bool` on `RawPacket` (populated from `t.syn()` in `parse_raw_packet`). `nfqueue::decide()` short-circuits only on `tcp_payload_empty && !tcp_syn`. Trade-off: flows without a matching Allow rule have their SYN dropped while `Pending` is open — application retransmits at ~1s and resumes once the user decides. Matches OpenSnitch / Little Snitch behavior.
5. **VPN-poisoned `main` table caused unmatched marks to leak via VPN, not fail closed.** A separate `type unreachable` policy rule at a fixed pref had an ordering inversion problem (fires before lookup, dropping everything). **Fix:** put the unreachable *inside the lookup table* at metric 1000, with the primary route at metric 100. Lower metric wins normally; if the primary install fails or its interface goes down, the in-table unreachable returns `EHOSTUNREACH` instead of falling through to `main`. Also made `SystemRouteManager::add_route` transactional and stopped advancing `next_mark` on failure in `ensure_route_mark`.

- **Files:** [`crates/enforcer/src/lib.rs`](../crates/enforcer/src/lib.rs) (chain layout, masquerade, in-table unreachable, transactional `add_route`), [`crates/enforcer/src/nfqueue.rs`](../crates/enforcer/src/nfqueue.rs) (SYN classification, `tcp_syn` parse), [`crates/flow-classifier/src/lib.rs`](../crates/flow-classifier/src/lib.rs) (`RawPacket.tcp_syn`), [`apps/daemon/src/main.rs`](../apps/daemon/src/main.rs) (`ensure_route_mark` guard).
- **Verification:** `curl --max-time 10 -v https://www.digikala.com` with a `Route via eg-lan-enp3s0` rule active and the VPN tun up — full TLS 1.3 handshake completes; conntrack records the SNAT (`10.x.x.x → 192.168.7.7`).

## Bug Fixes (transparent proxy hardening, 2026-06-01)

**Bug 13:** SOCKS5/HTTP CONNECT handshake had no I/O timeout. After `socket2::connect_timeout` established the TCP connection to the local proxy, the subsequent SOCKS greeting/method-selection/CONNECT exchange used blocking `read_exact()` with no timeout. If the upstream proxy (wireproxy) was unresponsive, the transparent proxy hung indefinitely, and the application (curl, httpie) saw a silent hang.

- **Fix:** Set `SOCK_STREAM` read/write timeouts (`set_read_timeout`/`set_write_timeout`) on the TcpStream before the SOCKS/HTTP handshake, map `TimedOut` to `ProxyClientError::ConnectTimeout`, clear timeouts after handshake so the relay path is unthrottled.

**Bug 14:** Transparent proxy listener lacked `IP_TRANSPARENT` socket option. The Linux kernel requires `IP_TRANSPARENT` on the listening socket for nftables `REDIRECT` to deliver connections. Without it, `accept()` and `SO_ORIGINAL_DST` could fail or behave incorrectly.

- **Fix:** `bind_transparent_listener()` in `proxy-client::transparent` uses `socket2` to create the socket, sets `IP_TRANSPARENT` via `libc::setsockopt(SOL_IP, 19)`, then binds and listens.

**Bug 15:** `SO_ORIGINAL_DST` only tried `SOL_IP` (IPv4). IPv6 connections redirected via nftables would fail the original-destination lookup.

- **Fix:** `get_original_dst()` tries `SOL_IP` first, then falls back to `IPPROTO_IPV6` for IPv6 connections. Error messages include both attempts.

**Bug 16:** NFQUEUE re-queued follow-on packets of proxy-routed connections. `PROXY_REDIRECT_MARK` (below `ROUTE_MARK_BASE`) wasn't matched by any bypass rule in `output_early`, so data segments after the initial SYN were sent through NFQUEUE again and could be dropped.

- **Fix:** Added `meta mark {PROXY_REDIRECT_MARK} accept` rule in `output_early` before the `queue num {q}` rule.

**Bug 17:** Silent misconfiguration when transparent proxy started without NFQUEUE. If proxies existed in DB but `LOGIGUARD_NFQUEUE` was unset, the transparent proxy listened but no outbound traffic was ever marked for redirect — no error, no traffic.

- **Fix:** Daemon prints a warning: `transparent proxy is listening but LOGIGUARD_NFQUEUE is unset`.

- **Files:** [`crates/proxy-client/src/lib.rs`](../crates/proxy-client/src/lib.rs) (handshake timeouts), [`crates/proxy-client/src/transparent.rs`](../crates/proxy-client/src/transparent.rs) (IP_TRANSPARENT, IPv6 SO_ORIGINAL_DST), [`crates/enforcer/src/lib.rs`](../crates/enforcer/src/lib.rs) (PROXY_REDIRECT_MARK bypass rule), [`apps/daemon/src/main.rs`](../apps/daemon/src/main.rs) (NFQUEUE unset warning).

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
    pub egress_id: Option<String>,     // References Egress entity
    pub process_exe: Option<String>,   // Full /proc/<pid>/exe path (preferred identity)
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
    pub process_name: Option<String>,       // e.g., "firefox"
    pub destination_ip: String,             // e.g., "142.251.33.46"
    pub destination_port: u16,              // e.g., 443
    pub destination_domain: Option<String>, // e.g., "google.com" (from DNS, SNI, or HTTP Host)
    pub protocol: TransportProtocol,        // Tcp | Udp | Quic | Other
    pub direction: FlowDirection,           // Outbound | Inbound
    pub device_label: Option<String>,       // e.g., "vpn-work" (gateway device label)
    pub process_exe: Option<String>,        // full /proc/<pid>/exe path
    pub app_name: Option<String>,           // package manager name (e.g. "cursor-bin")
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
    egress_id TEXT,              -- references egress.id (nullable)
    process_exe TEXT             -- full /proc/<pid>/exe path for precise rule identity (nullable)
);
```

`process_exe` is added via migration (`ALTER TABLE rules ADD COLUMN process_exe TEXT NULL`) on startup for existing databases. It enables exe-path rule matching which is immune to `/proc/<pid>/comm` 15-char truncation and basename collisions.

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
| policy-engine | 10 | Matching, precedence, disabled rules, **unknown-process fallback** + safety negatives |
| decision-engine | 13 | Pending lifecycle, timeout, overflow, **symmetric `(dst_ip, port, proto)` dedup** with name-upgrade |
| flow-classifier | 19 | Process/domain attribution, `/proc/net` parsing, **per-socket resolver cache** |
| enforcer | 22 | Packet parsing, verdict paths, SNI, loopback (IPv4-mapped), **NFQUEUE error recovery** |
| state-store | 17 | CRUD, persistence |
| control-api | 11 | Request validation |
| control-service | 12 | RPC handlers, pending lifecycle, push notifications |
| cli | 17 | Command parsing, output formatting |
| proxy-client | 12 | SOCKS5/HTTP CONNECT protocol encoding, auth handling, transparent proxy, error cases |
| daemon + emulator integration | 3 | route target switch e2e (2), SOCKS5 allow relay (1) |
| **Total** | **180** | |

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
- `LOGIGUARD_DB_PATH` — SQLite DB location (default `~/.config/logiguard/logiguard.db`; directory created automatically)
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

9. **libayatana-appindicator deprecation warning:** The system tray prints a startup warning (`libayatana-appindicator is deprecated. Please use libayatana-appindicator-glib in newly written code.`). This is cosmetic — the tray works correctly. Migration to the newer library or the `ksni` approach is blocked on upstream Rust crate stabilization.

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

- Workspace compiles cleanly
- 168 tests passing (`cargo test --workspace`)
- No CI pipeline set up yet

### Planned

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Coverage thresholds: policy/decision ≥95%, rest ≥85%

## Key Metrics

- **Lines of code (Rust):** ~6,000 (crates + apps)
- **Test code:** ~2,500 (unit + integration)
- **Test count:** 180 passing
- **Crates:** 8 (core, policy, decision, flow, enforcer, state, control, proxy-client)
- **Apps:** 3 (daemon, CLI, GPUI)
- **Database tables:** 6 (rules, flow_events, pending_decisions, egresses, egress_targets, egress_dns_servers, proxies)
- **Unix socket path:** `/tmp/logiguard.sock`
- **Default timeouts:** 100s (default), 5s (UDP/QUIC), 3s (other)
- **Queue cap:** 100 pending decisions
- **GPUI components:** Table (TableDelegate), Dialog, TabBar, Button, Checkbox, Root

## Conclusion

LogiGuard is feature-complete for MVP (Phase 1-4). Core logic tested extensively. Settings window uses gpui-component Table and Dialog for data management. Proxy support fully implemented across all crates. Enforcement path fully wired: real ProcessResolver reads `/proc`, TLS SNI extraction populates destination domain. Ready for Phase 2 integration testing and real-world deployment.
