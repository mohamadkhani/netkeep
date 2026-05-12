# Process Attribution Races and the Three Layers of Defense

> **Read this before touching any of `proc_resolver.rs`, `decision-engine`, or `process_matches` in `policy-engine`.**

This document is the post-mortem of the duplicate-dialog bug fixed in session 19 (2026-05-13). The same underlying problem can resurface in many shapes; the three layers below exist so that any *single* layer's miss does not translate into a user-visible duplicate prompt.

---

## The race

`ProcProcessResolver` answers the question *"what local process owns this packet?"* by reading `/proc/net/{tcp,tcp6,udp,udp6}` for the matching `(src_ip, src_port)` row, then scanning `/proc/*/fd/` for the matching `socket:[inode]` symlink. Two things make this inherently racy with NFQUEUE packet delivery:

1. **The kernel publishes the socket entry to `/proc/net` *asynchronously*.** A packet can be handed to userspace by NFQUEUE while the corresponding `/proc/net/tcp` row has not been written yet (or has just been overwritten/reordered by another CPU). The retry loop in `retry_find_socket` (delays `[0, 3, 8]` ms) closes most of this window but not all of it.
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

**Why this is enough.** A successful `/proc/net/tcp` resolution for `(192.168.1.5, 54321, TCP)` is stable for the lifetime of that socket. The kernel does not rebind those exact `(ip, port)` tuples to a different process while the first socket is alive. A retransmit of the same connection will therefore hit the cache and return the same name we already learned, even if `/proc/net/tcp` briefly fails the next read.

**Why 60 s is the right TTL.** Long enough to cover idle HTTP keep-alive periods and typical TCP `TIME_WAIT`, short enough that an eventual port reuse by a different process gets a fresh lookup.

**Why this is *not* enough on its own.** The first packet of a *new* connection (different `src_port`) bypasses the cache entirely — it has to lose or win the `/proc` race on its own. That is what Layers 2 and 3 are for.

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

A normal connection only ever exercises Layer 1: the first packet's `/proc` lookup wins, the cache fills, every later packet of the connection hits the cache, the decision engine pending (if any) is a single entry, and the policy engine matches cleanly.

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

- It is **not** a substitute for proper process attribution. If you ever switch to `SOCK_DIAG` / `inet_diag_msg` or to an eBPF resolver that does not race, Layers 2 and 3 stay but become rarely-exercised safety nets.
- It is **not** a way to relax security for wildcard rules. Layer 3 specifically refuses to apply broad rules to unattributed flows.
- It is **not** a way to merge unrelated processes' decisions. Layer 2 only deduplicates when at least one side is `None`; two distinct known names always stay separate.

---

## When to revisit

Add a fourth layer if you ever ship one of:

- a per-PID resolver that can return a name without `/proc/net/*` (the cache layer's TTL becomes irrelevant);
- a resolver that returns `(name, confidence)` instead of `Option<name>` (Layer 3's "specific destination" guard could be replaced by a confidence threshold);
- packet-level user-space queues other than NFQUEUE (the race window changes shape).
