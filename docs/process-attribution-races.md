# Process Attribution Races and the Three Layers of Defense

> **Read this before touching any of `proc_resolver.rs`, `decision-engine`, or `process_matches` in `policy-engine`.**

This document is the post-mortem of the duplicate-dialog bug fixed in session 19 (2026-05-13). The same underlying problem can resurface in many shapes; the three layers below exist so that any *single* layer's miss does not translate into a user-visible duplicate prompt.

---

## The race

`ProcProcessResolver` answers the question *"what local process owns this packet?"* by querying the kernel's `SOCK_DIAG` netlink interface for `(src_ip, src_port)`, falling back to reading `/proc/net/{tcp,tcp6,udp,udp6}` for the matching row, then scanning `/proc/*/fd/` for the matching `socket:[inode]` symlink. Two things make this inherently racy with NFQUEUE packet delivery:

1. **The `/proc/net` fallback is asynchronous.** SOCK_DIAG returns inode + uid synchronously from the kernel's socket hash table and avoids this race entirely. When SOCK_DIAG misses (netlink unavailable, permission denied), the `/proc/net` fallback can race: a packet may be handed to userspace by NFQUEUE while the corresponding `/proc/net/tcp` row has not been written yet. The retry loop in `retry_find_socket` (delays `[0, 5, 15, 40]` ms) closes most of this window but not all of it.
2. **The same packet may be re-classified more than once.** A pending decision means NFQUEUE drops the packet; the kernel retransmits. Each retransmit re-enters NFQUEUE and is re-classified by `FlowClassifier`. A flow whose first attempt yielded `process_name = None` can yield `Some("curl")` on the second — or vice versa.

The observable symptom is always the same: **two dialogs for the same logical connection**, one with the process name, one without.

---

## What was wrong before

The original code had three independent gaps that compounded:

| Layer | Gap | Effect |
|---|---|---|
| Resolver | No cache. Each packet did a fresh `/proc` lookup. | Successive packets of the same socket could disagree on the process name. |
| Dedup | `FlowKey` included `process_name`. The "process-name fallback" only fired when the *new* packet had `process_name=None`. | An "unknown" pending followed by a packet with a known name created a *second* pending — the same flow, twice. |
| Policy | `process_matches((Some, None)) → false`. | Once a rule existed with a specific `process_name`, any later packet whose attribution failed bypassed the rule and re-created a pending dialog. |

After the user clicked Allow on the first dialog, the second one appeared *anyway* because the policy layer would not honour the rule for a packet whose process the resolver had failed to identify.

---

## The three layers, top down

Each layer protects against a different time-slice of the problem.

```
                          packet arrives at NFQUEUE
                                    │
                                    ▼
        ┌──────────────────────────────────────────────────────┐
        │ Layer 1: ProcProcessResolver cache                  │
        │ keyed (src_ip, src_port, protocol), TTL 60s         │
        │ - hit  → return cached name (no /proc read)         │
        │ - miss → /proc lookup; on success insert into cache │
        └───────────────────────┬──────────────────────────────┘
                                ▼
        ┌──────────────────────────────────────────────────────┐
        │ Layer 2: DecisionEngine::register_unknown_flow      │
        │ fallback (dst_ip, dst_port, protocol) lookup when   │
        │ at least one of (new flow, existing pending) has    │
        │ process_name=None. On match:                        │
        │  - new packet has name, existing pending is None    │
        │      → re-key index, patch the pending's flow,      │
        │        return the (upgraded) existing PendingDec    │
        │  - new packet is None, existing pending has a name  │
        │      → return existing PendingDec verbatim          │
        └───────────────────────┬──────────────────────────────┘
                                ▼
        ┌──────────────────────────────────────────────────────┐
        │ Layer 3: policy_engine::process_matches             │
        │ (rule.proc=Some, flow.proc=None) is allowed only    │
        │ when the rule pins a *specific* destination         │
        │ (IpExact or DomainExact).                           │
        │ Broad rules (Any / Cidr / Wildcard) still require   │
        │ a strict process match.                             │
        └──────────────────────────────────────────────────────┘
```

### Layer 1 — Per-socket resolver cache

**File:** `crates/flow-classifier/src/proc_resolver.rs`
**Key:** `(src_ip, src_port, protocol)`
**TTL:** 60 s
**Cap:** 4096 entries, evicted on next insert when full

**Why this is enough.** A successful SOCK_DIAG or `/proc/net/tcp` resolution for `(192.168.1.5, 54321, TCP)` is stable for the lifetime of that socket. The kernel does not rebind those exact `(ip, port)` tuples to a different process while the first socket is alive. A retransmit of the same connection will therefore hit the cache and return the same name we already learned, even if the live lookup would briefly fail.

**Why 60 s is the right TTL.** Long enough to cover idle HTTP keep-alive periods and typical TCP `TIME_WAIT`, short enough that an eventual port reuse by a different process gets a fresh lookup.

**Why this is *not* enough on its own.** The first packet of a *new* connection (different `src_port`) bypasses the cache entirely — it has to lose or win the live lookup on its own. SOCK_DIAG makes the inode lookup synchronous, but the fork/exec fd-visibility gap and process-exit races can still produce `None`. That is what Layers 2 and 3 are for.

### Layer 2 — Symmetric dedup in the decision engine

**File:** `crates/decision-engine/src/lib.rs`
**Function:** `DecisionEngine::register_unknown_flow`

The dedup index is keyed by `FlowKey = (process_name, dst_ip, dst_port, protocol)`. When an exact-key match misses, a *fallback* search looks for any existing pending with the same `(dst_ip, dst_port, protocol)` provided at least one side is `process_name=None`:

```rust
.find(|(k, _)| {
    k.destination_ip == dst_ip
        && k.destination_port == dst_port
        && k.protocol == protocol
        && (flow.process_name.is_none() || k.process_name.is_none())
})
```

Two cases match:

1. **Existing pending has a name, new packet is None.** Return the existing pending verbatim — the new packet is the same flow with a temporarily-failed attribution.
2. **Existing pending is None, new packet has a name.** *Upgrade* the pending: rewrite `pending_by_flow` under the new key and patch `pending.flow.process_name` (also `destination_domain` / `device_label` if they were previously absent). The next call to `ListPending` from the UI will show the real process name.

The case `(both Some, different names)` is **not** deduped — that is genuinely two different processes connecting to the same destination at the same moment (e.g. chrome and firefox to google.com), and they deserve separate dialogs.

### Layer 3 — Forgiving policy match for specific destinations

**File:** `crates/policy-engine/src/lib.rs`
**Function:** `process_matches`

After the user clicks Allow, the rule has `process_name=Some(P)` and some destination matcher. A later packet whose resolver fails would, by strict pairwise comparison, miss this rule and bubble back up to `register_unknown_flow` — re-creating a dialog the user already answered.

The rule used to be:

```rust
(Some(_), None) => false,
```

The current rule is:

```rust
(Some(_), None) => matches!(
    rule.destination,
    DestinationMatcher::IpExact(_) | DestinationMatcher::DomainExact(_)
),
```

**Why limit to specific destinations.** A wildcard rule like `allow curl → *.example.com` must *not* silently apply to an unattributed packet, because that would let any local process piggy-back on the wildcard. Pinning to exact IP / exact domain bounds the risk: the user explicitly trusted that single host for that process; an attacker would have to target the exact same host AND defeat process attribution.

`(Some, Some)` mismatches are still hard rejects: if attribution succeeded but yielded a different name, the rule does not match.

---

## How the layers interact

A normal connection only ever exercises Layer 1: the first packet's SOCK_DIAG (or `/proc` fallback) lookup wins, the cache fills, every later packet of the connection hits the cache, the decision engine pending (if any) is a single entry, and the policy engine matches cleanly.

The other layers only fire when something has already gone wrong:

| Symptom | Caught by |
|---|---|
| First packet attribution failed, retransmit succeeded → two pendings before any rule exists | Layer 2 (upgrade path) |
| Pending exists with a known name, a later packet's attribution fails before the user clicks → two pendings | Layer 2 (reuse path) |
| Rule installed, follow-up packet on the *same* socket but attribution races again | Layer 1 (cache hit) |
| Rule installed, a *new* socket to the same exact destination races and attribution fails | Layer 3 (specific-destination fallback) |
| Two genuinely different processes to the same destination | not caught — separate dialogs by design |

If you remove any layer, an above row reappears as a duplicate dialog.

---

## Tests pinning each layer

- **Layer 1:** `flow-classifier::tests::cache_hit_returns_name_without_touching_proc`, `cache_misses_for_different_port_or_protocol`, `cache_entry_expires_after_ttl`.
- **Layer 2:** `decision-engine::tests::unknown_then_named_packet_reuses_and_upgrades_pending`, `named_then_unknown_packet_reuses_pending`, `distinct_named_processes_to_same_destination_are_not_deduped`.
- **Layer 3:** `policy-engine::tests::unknown_process_matches_specific_destination_rule`, `unknown_process_matches_specific_ip_rule`, `unknown_process_does_not_piggyback_on_wildcard_rule`, `unknown_process_does_not_piggyback_on_any_rule`, `unknown_process_does_not_piggyback_on_cidr_rule`, `known_process_mismatch_still_blocks_specific_rule`.

---

## What this is *not*

- It is **not** a substitute for perfect process attribution. SOCK_DIAG eliminates the `/proc/net` TOCTOU race for inode lookup, but the fork/exec fd-visibility gap and process-exit races remain. Layers 2 and 3 are safety nets for those residual misses.
- It is **not** a way to relax security for wildcard rules. Layer 3 specifically refuses to apply broad rules to unattributed flows.
- It is **not** a way to merge unrelated processes' decisions. Layer 2 only deduplicates when at least one side is `None`; two distinct known names always stay separate.

---

## Bug 23 — Daemon's own connections intercepted (fixed 2026-06-04)

This is not a process attribution race per se, but it produces the same visible symptom: `process=Some("logiguard-daemon")` in policy logs.

### Root cause

The daemon makes outbound connections on behalf of applications:

- DNS forwarder system fallback (`forward_udp`) — plain UDP to the system DNS server.
- DNS forwarder device-egress fallback (`resolve_via_bindtodevice`) — UDP with `SO_BINDTODEVICE`.
- DNS forwarder proxy-egress (`dns_over_socks`) — TCP to a SOCKS5 proxy.
- TCP relay proxy connects (`connect_via_proxy_target`) — TCP to a SOCKS5/HTTP proxy.
- TCP relay device fallback (`connect_plain`) — plain TCP.

None of these sockets had `SO_MARK` set. The nftables `output_early` chain only bypasses NFQUEUE for packets with `mark >= ROUTE_MARK_BASE` (20000) or specific proxy marks. All unmarked daemon traffic was queued to NFQUEUE, classified as `process=logiguard-daemon`, and triggered policy matching.

This was **not** a resolver failure — the resolver correctly identified the process. The problem was that the daemon's relay/DNS connections should never have been intercepted in the first place.

### Fix

Added `DAEMON_BYPASS_MARK` (19998, defined in `enforcer::DAEMON_BYPASS_MARK`) — a dedicated fwmark below `ROUTE_MARK_BASE` that:

1. **Bypasses NFQUEUE** via a new nftables `output_early` accept rule: `meta mark 19998 accept`.
2. **Does NOT trigger policy routing** — marks below 20000 don't match any `ip rule add fwmark N lookup T` entries, so the daemon's connections follow the system default route.

All daemon-originated sockets now call `SO_MARK(DAEMON_BYPASS_MARK)` before connect/send.

### Why not use `ROUTE_MARK_BASE`?

Using `ROUTE_MARK_BASE` (20000) would cause the daemon's own connections to be routed through a specific egress interface (e.g. a VPN tunnel) via the policy routing table — breaking connectivity when the real application needs the default route.

---

## Bug 22 — ACK eviction + Electron fd gap (fixed 2026-05-15)

This is a worked example of two bugs that compounded to produce the `process=None` symptom in production (`electron → api2.cursor.sh`).

### Root cause 1 — ACK eviction in `NfqueueProcessor::decide()`

The nftables `output_early` chain sends **all** output packets to NFQUEUE — SYNs, pure ACKs, FINs, RSTs, and data alike. The old `decide()` used a single `tcp_payload_empty` guard:

```rust
// old, buggy
if raw.tcp_payload_empty {
    self.decided.remove(&key);  // evicted cache for ACKs too
    return (Verdict::Accept, None);
}
```

A pure ACK (client acknowledging server data) has an empty TCP payload. The guard fired, evicted the 5-tuple verdict cache, and forced the **next** data packet to miss the cache and run the full classification pipeline — including `ProcProcessResolver`. If that re-classification raced `/proc`, `process_name` came back `None`.

**Fix:** Split the guard into two distinct branches.

```rust
// FIN/RST — connection closing. Evict.
if raw.tcp_fin || raw.tcp_rst {
    self.decided.remove(&key);
    return (Verdict::Accept, None);
}

// Pure ACK (or SYN during handshake) — no application data. Consult cache; do NOT evict.
if raw.tcp_payload_empty {
    if let Some(cached) = self.decided.get(&key) { ... }
    return (Verdict::Accept, None);
}
```

Two new fields were added to `RawPacket`: `tcp_fin: bool` and `tcp_rst: bool`, populated by `parse_raw_packet()` from `etherparse::TcpHeaderSlice::fin()` / `.rst()`.

### Root cause 2 — no retry in `find_pid_for_inode`

`retry_find_socket` already had a retry loop (`[0, 5, 15, 40]` ms) for the `/proc/net/tcp` inode lookup. But `find_pid_for_inode` (the `/proc/*/fd/` scan) had **no retry** at all. Electron spawns a dedicated `--type=utility` network-service subprocess; during the `fork`→`exec` window its fds are not visible. Without the ACK eviction bug the window was rarely hit; with it, every client ACK triggered a re-classification that landed squarely in the fork/exec gap.

**Fix:** Added `[0, 3, 8]` ms retry to `find_pid_for_inode` (same pattern as `retry_find_socket`). Extended to `[0, 3, 8, 20]` ms in Bug 23 to cover Cursor AppImage's longer fork/exec gap.

### Why two separate Allow rules were created

Rule `ui-1778793567` was created when `process=Some("electron")` — the GPUI dialog offered a `DomainWildcard("cursor.sh")` destination. Layer 3 (`process_matches`) requires an exact destination (`IpExact` or `DomainExact`) to forgive `process=None`; wildcards still require a strict match. When the next connection arrived with `process=None`, the wildcard rule did not match, and the user was prompted again — producing rule `ui-1778793599` with `DomainExact("api2.cursor.sh")` and no process constraint.

---

## Bug 23 — "electron" process name + inode=0 false match (fixed 2026-05-16)

Two independent bugs that both produce misleading process attribution for Cursor (and other Electron apps).

### Root cause 1 — wrong process name: "electron" instead of "cursor"

Cursor (and any Electron-based app installed as an AppImage, or packaged with the Electron binary under an app-specific directory) has its utility subprocess's `/proc/<pid>/exe` pointing to a binary literally named `electron`. `read_exe_basename(pid)` faithfully returns `"electron"`, which is the correct filesystem name but the wrong user-facing label.

Previous fixup code only walked to parent for single-character names and known shell wrappers (`sh`, `bash`, etc.). `"electron"` had length 8, so it passed through unchanged.

**Fix.** Added `"electron"` and `"AppRun"` (the AppImage entry-point) to the generic-name trigger. For these names three fallback strategies are tried in order:

1. **`APPIMAGE` env var** — the AppImage runtime sets this in every process in the tree (including utility subprocesses). `/proc/<pid>/environ` is read, the file stem of the AppImage path is extracted and lowercased, and a trailing `-<version>` component is stripped: `"Cursor-0.45.5.AppImage"` → `"cursor"`.
2. **Exe parent directory** — for packages like `/opt/cursor/electron`, the directory name `"cursor"` is used. Generic directory names (`bin`, `usr`, `lib`, `tmp`, etc.) are excluded so this only fires for app-specific install dirs.
3. **Parent process exe basename** — filtered to exclude other generic names so we don't walk further up into systemd.

**Tests:** 6 new unit tests in `parse_environ_for_app_name` cover AppImage path parsing, hyphenated names, version stripping, the `ELECTRON_APP_NAME` env var path, missing vars, and short-name rejection.

### Root cause 2 — inode=0 causes guaranteed process=None

`/proc/net/tcp` rows for TIME_WAIT sockets (state `0x06`) have `inode=0`. If a TIME_WAIT socket exists with the same `(src_ip, src_port)` as an incoming new connection's SYN, `parse_proc_net` could match that row first and return `inode=0`. `find_pid_for_inode(0)` then searches for `"socket:[0]"` in `/proc/*/fd/` — a string that never appears in any real process's fd directory — and always returns `None`.

This is deterministic (not a race): whenever a port is reused quickly and a TIME_WAIT entry is still present, the first attempt always returns inode=0, all retries also return inode=0, and the process is always `None`.

**Fix.** Added `if inode == 0 { continue; }` in both `parse_proc_net` and `parse_proc_net_port_only`. The scan continues past the TIME_WAIT row to find the real ESTABLISHED/SYN_SENT entry.

**Tests:** 2 new unit tests: `inode_zero_row_is_skipped_and_real_entry_returned` (TIME_WAIT row present but real entry follows it), `inode_zero_only_row_returns_none` (only a TIME_WAIT row — returns `None` so the retry loop fires).

### Additional hardening

`find_pid_for_inode` retries extended from `[0, 3, 8]` ms (3 attempts, 11 ms) to `[0, 3, 8, 20]` ms (4 attempts, 31 ms) to cover Cursor AppImage's longer fork/exec gap.

---

## Bug 24 — CDN IP rotation causes one-off `process=None` mid-session (fixed 2026-05-17)

### Root cause

The three layers described above only help *after* the first packet of a connection races `/proc`. For long-running sessions (e.g. a YouTube video playing for several minutes), a different failure mode appears: the CDN rotates IP addresses. Chromium opens a new connection to a fresh IP that the Layer 1 per-socket cache has no entry for. The new connection races `/proc` — if it loses, `process_name = None` for that packet.

Layer 3 helps if the rule used `DomainExact` or `IpExact`, but not if it used `DomainWildcard` or if the new CDN IP is not in the user's approved IP list. The result: one rogue `(unknown)` dialog appearing 4+ minutes into a session, after dozens of successful attributions to the same process.

### Layer 0 — nfqueue-level attribution caches

Two new caches live in `NfqueueProcessor` (file: `crates/enforcer/src/nfqueue.rs`), at a layer *above* the resolver and *below* the decision engine:

```
                          packet arrives at NFQUEUE
                                    │
                                    ▼
     ┌──────────────────────────────────────────────────────────┐
     │ Layer 0a: IP-based attribution cache                    │
     │ keyed (dst_ip, dst_port), TTL 15 min, max 1024 entries  │
     │ If process_name=None after classify:                    │
     │   look up (dst_ip, dst_port) → restore process attrs    │
     └─────────────────────────────┬────────────────────────────┘
                                   │ still None
                                   ▼
     ┌──────────────────────────────────────────────────────────┐
     │ Layer 0b: Domain-based attribution cache                │
     │ keyed (domain, dst_port), TTL 1 hour, max 512 entries   │
     │ If domain known and process_name=None after 0a:         │
     │   look up (domain, dst_port) → restore process attrs    │
     └─────────────────────────────┬────────────────────────────┘
                                   │
                                   ▼
                             (Layers 1–3 unchanged)
```

**IP-based cache** (`proc_attr`): when a packet is successfully classified with a non-None `process_name`, the resolver stores `(dst_ip, dst_port) → CachedProcessAttr { process_name, process_exe, app_name, expires_at }`. On the next packet to the same server IP (retransmit or re-connection), if attribution fails, the cached attrs are restored. TTL: 15 minutes, max 1024 entries (LRU-evicted on overflow).

**Domain-based cache** (`domain_proc_attr`): when a successfully classified packet also has a `destination_domain`, `(domain, dst_port) → CachedProcessAttr` is stored. When a *new CDN IP* serves the same domain and the IP cache has no entry (because it's a different IP), this cache provides the attribution. TTL: 1 hour, max 512 entries.

The domain cache uses a longer TTL because CDN IP rotation is slow (minutes to hours) and domains are stable within a browsing session. The IP cache uses a shorter TTL to avoid attributing a reused port on a different machine to the wrong process.

### `CachedProcessAttr`

```rust
struct CachedProcessAttr {
    process_name: String,
    process_exe:  Option<String>,
    app_name:     Option<String>,
    expires_at:   u64,   // unix seconds
}
```

When restored from either cache, all three fields are patched back into the `FlowContext` before it is passed to the policy engine and decision engine.

### What this is not

Layer 0 is not a substitute for proper per-socket resolution. It is specifically for *re-connections to the same logical server* within a session, where we have high confidence the same process is responsible. Two different processes connecting to the same destination at overlapping times could theoretically interfere — but in practice a process rarely connects to a service it doesn't own while another process is already connected to it.

---

## Layer −1 — eBPF socket tracker (added 2026-06-02)

The eBPF socket tracker eliminates the TOCTOU race **entirely** by capturing the PID at the kernel level, before NFQUEUE delivers the packet to userspace.

### How it works

Three eBPF hooks populate a shared BPF `HashMap` (`SOCK_EVENTS`, 16384 entries):

| Hook | Type | When it fires | What it does |
|---|---|---|---|
| `sock:inet_sock_set_state` | tracepoint | TCP enters `SYN_SENT` | Inserts `(src_ip, src_port, TCP) → (pid, uid, ts)` |
| `udp_sendmsg` | kprobe | Every UDP send | Inserts `(src_ip, src_port, UDP) → (pid, uid, ts)` |
| `udp_lib_unhash` | kprobe | UDP socket close | Removes the entry |

`ProcProcessResolver::find_pid()` checks this map **first** (Step 0). On a hit, the entire SOCK_DIAG → `/proc/net` → `/proc/*/fd` → `ss` chain is skipped. The PID is already known — no TOCTOU race, no fork/exec fd-visibility gap, no inode=0 false match.

### Why this is different from the other layers

- **Layer 0** (NFQUEUE caches) patches up *after* a miss — it restores attribution from a previous successful lookup. The eBPF tracker *prevents* the miss.
- **Layer 1** (per-socket cache) avoids redundant lookups for the same socket. The eBPF tracker provides the *first* lookup result.
- **Layer 2** (dedup) prevents duplicate prompts. The eBPF tracker ensures the *first* prompt has the correct process name.
- **Layer 3** (forgiving match) tolerates `process=None`. The eBPF tracker aims to make `process=None` rare.

### Graceful degradation

If the eBPF program fails to load (no `CAP_BPF`, kernel < 5.5, etc.), the daemon logs a warning and falls back to SOCK_DIAG + `/proc` + `ss`. All existing defense layers remain active.

### Metrics

- `logiguard.proc.resolver.ebpf.hits` — PID found via eBPF map
- `logiguard.proc.resolver.ebpf.misses` — eBPF map had no entry (fell through to SOCK_DIAG)

### Files

| File | Purpose |
|---|---|
| `crates/dns-tracker-ebpf/src/sock_tracker.rs` | eBPF program (BPF bytecode) |
| `crates/dns-tracker/src/sock_tracker.rs` | Userspace loader + `SocketTracker` trait impl |
| `crates/flow-classifier/src/lib.rs` | `SocketTracker` trait + `TrackedProcess` struct |
| `crates/flow-classifier/src/proc_resolver.rs` | Step 0 integration in `find_pid()` |
| `crates/flow-classifier/src/sock_diag.rs` | Dual-family + UDP wildcard SOCK_DIAG fix |

---

## When to revisit

The eBPF socket tracker (Layer −1) addresses the first bullet below — it returns a PID without touching `/proc/net/*`. Remaining areas to revisit:

- a resolver that returns `(name, confidence)` instead of `Option<name>` (Layer 3's "specific destination" guard could be replaced by a confidence threshold);
- packet-level user-space queues other than NFQUEUE (the race window changes shape);
- eBPF BTF: runtime validation of hardcoded struct offsets in `sock_tracker.rs` (currently hardcoded for x86_64, Linux 6.x).
