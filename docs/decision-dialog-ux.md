# Decision Dialog UX Specification

This document defines the interaction design of the LogiGuard connection decision dialog — the window shown when an unknown flow is intercepted and the user must decide whether to allow or deny it.

The reference visual is `design/decision_dialog_window.html`.

---

## Dialog Structure

```
┌─────────────────────────────────────────┐
│ 1. Header (CONNECTION INTERCEPTED + timer) │
├─────────────────────────────────────────┤
│ 2. Flow Details (read-only)             │
│    Process / Destination / IP / Protocol│
├─────────────────────────────────────────┤
│ 3. Rule Scope (interactive)             │
│    Process scope toggle                 │
│    Destination scope toggle             │
│    Rule summary line                    │
│    Duration + Route row                 │
│    Allow / Deny buttons                 │
└─────────────────────────────────────────┘
│ 4. Footer (queue status)               │
└─────────────────────────────────────────┘
```

**Section 2 is read-only.** It shows what the kernel intercepted — factual, not editable.  
**Section 3 is interactive.** It defines the scope of the rule that Allow/Deny will create.

---

## 1. Header

- **Left:** security shield icon + `CONNECTION INTERCEPTED` label
- **Right:** circular countdown ring with remaining seconds + `AUTO-DENY` label below
- Countdown ring color: green → drains as time passes
- On timeout: dialog closes, flow is denied, no rule is created

---

## 2. Flow Details (read-only)

| Field | Source | Display when unknown |
|---|---|---|
| Process | `/proc/<pid>/comm` via ProcProcessResolver | `(unknown)` in muted italic |
| Destination | TLS SNI or DNS snoop cache | `(unknown)` in muted italic |
| IP Address | packet dst_ip | Always present |
| Protocol | packet transport layer | `TCP : 443`, `UDP : 53`, etc. |
| Direction | `Outbound` (all NFQUEUE-intercepted flows) | — |

---

## 3. Rule Scope

This section defines **what rule gets created** when the user clicks Allow or Deny. It does not affect the one-time verdict for the current packet — it controls how future flows matching the same pattern are handled.

### 3.1 Process Scope Toggle

A two-option button group:

```
[ firefox ]  [ all processes ]
```

| Selection | Rule field | Meaning |
|---|---|---|
| `firefox` (specific) | `process_name: Some("firefox")` | Rule applies only when firefox is the source process |
| `all processes` | `process_name: None` | Rule applies regardless of which process makes the connection |

**When process is unknown** (`(unknown)` in flow details):
- The toggle shows `[ unknown ] [ all processes ]`
- `unknown` is pre-selected and cannot be changed to `all processes`
- Rationale: "all processes + any destination" would create a blanket allow/deny with no useful scope

### 3.2 Destination Scope

The available options depend on whether a domain was resolved for this flow.

#### Case A — Domain known (e.g. `accounts.google.com`)

Three-option button group:

```
[ accounts.google.com ]  [ *.google.com ]  [ any ]
```

| Selection | Rule type | Covers |
|---|---|---|
| `accounts.google.com` | `DomainExact` | Exactly this subdomain |
| `*.google.com` | `DomainWildcard` | All subdomains of google.com (not the apex itself per wildcard semantics) |
| `any` | no destination matcher | Any destination |

Default: exact subdomain (narrowest scope, safest default).

**Note on wildcard semantics:** `*.google.com` does NOT match `google.com` itself. If the user wants to cover both, they need two rules. The UI label `*.google.com` is shown verbatim so this is honest.

#### Canonical storage form

`DomainWildcard` stores **the apex without the `*.` prefix** — e.g. `DomainWildcard("google.com")`, not `DomainWildcard("*.google.com")`. The `*.` is a UI/display convention only:

- The decision dialog (`apps/gpui/src/components/action_footer.rs::build_dest_matcher`) computes `domain_apex(domain)` and stores the result directly.
- The CLI (`apps/cli/src/main.rs::parse_destination`) strips `*.` before storing.
- The settings form (`apps/gpui/src/settings/mod.rs`) strips `*.` on save so user-typed `*.foo.com` and `foo.com` produce the same rule.
- `ds::dest_text` and the rule table prepend `*.` for display.

The matcher in `policy-engine::wildcard_matches` is intentionally **lenient** and accepts both `"foo.com"` and `"*.foo.com"` so rules created by any of the above paths — and any rules that may have been persisted with the prefix in older builds — all match identically. This is covered by `wildcard_matches_both_storage_forms_identically` and `wildcard_matches_with_apex_only_storage_form` in `crates/policy-engine/src/lib.rs`.

> **Past bug:** before the lenient matcher, the writers (decision dialog, CLI) stored apex-only while the matcher required the `*.` prefix. Every dialog-installed wildcard rule silently failed to match, so the user got re-prompted for the same subdomain on every connection. Fixed 2026-05-13. The lenient matcher means future writers don't need to agree on a single form — they just need to be a valid apex.

#### Case B — Domain unknown, IP only

When no domain is available, the user selects the CIDR prefix by clicking directly on the IP octets:

```
[ 142 ] . [ 250 ] . [ 80 ] . [ 100 ]  /32
```

**Interaction model:**
- Each octet is a clickable chip
- Clicking an active octet masks it and all octets after it
- Clicking a masked octet re-activates it and all octets before it
- The `/prefix` badge updates live next to the IP

**Visual states:**

| Octet state | Appearance | Value shown |
|---|---|---|
| Active (included in rule) | Highlighted — primary color background | Real value (`142`, `250`, …) |
| Masked (wildcarded) | Dimmed — strikethrough | `0` |

**Examples for IP `142.250.80.100`:**

```
[ 142 ] . [ 250 ] . [ 80 ] . [ 100 ]  /32   → IpExact  142.250.80.100
[ 142 ] . [ 250 ] . [ 80 ] . [  0  ]  /24   → Cidr     142.250.80.0/24
[ 142 ] . [ 250 ] . [  0 ] . [  0  ]  /16   → Cidr     142.250.0.0/16
[ 142 ] . [  0  ] . [  0 ] . [  0  ]  /8    → Cidr     142.0.0.0/8
```

Default: all four octets active (/32 exact IP). The user can always re-click a masked octet to restore it.

The `any` option (no destination constraint) is available as a separate toggle for Case B — it is not reachable through the octet picker since at least one octet is always active.

#### Case C — Both process and destination unknown

- Process toggle is locked to `unknown` (cannot select `all processes`)
- Destination scope shows the same octet IP picker (Case B), but without the `any` option
- A destination is **required** — the user must narrow to at least an exact IP
- A warning banner appears at the top of the rule scope section:
  > "Unable to identify this connection. Specify a destination to create a rule, or allow/deny this one-time connection only."

---

## 4. Validation: Preventing Overly Broad Rules

A rule is considered **too broad** if it has no process constraint AND no destination constraint. This would create a blanket allow/deny for all traffic.

| Process scope | Destination scope | Allowed? |
|---|---|---|
| specific process | any destination | ✓ |
| all processes | specific domain/IP/CIDR | ✓ |
| all processes | any | ✗ blocked |
| unknown | specific IP/CIDR | ✓ |
| unknown | any | ✗ blocked (option hidden) |

**Enforcement:**
- When `all processes` is selected, the `any` destination option is visually disabled (grayed, unclickable)
- The Allow and Deny buttons are disabled when the combination would produce a blanket rule
- The rule summary line always reflects the current selection so the user sees exactly what will be created

---

## 5. Rule Summary Line

A single sentence below the scope controls that describes the rule in plain language:

> Rule applies to **firefox** connecting to **accounts.google.com**

> Rule applies to **any process** connecting to **142.250.80.0/24**

> Rule applies to **curl** connecting to **any destination**

This updates live as the user changes any toggle. It is the primary feedback mechanism — the user should be able to read this line and confirm their intent before clicking Allow or Deny.

---

## 6. Duration and Route Row

Below the rule scope block, a compact row combines:

- **Duration toggle:** `THIS SESSION` / `PERMANENTLY` (existing behavior)
- **Route via:** chip group of available egress targets (existing behavior)

These are collapsed into one row to reduce vertical height since they are secondary decisions.

---

## 7. Allow / Deny Buttons

Two full-width buttons side by side. State:

| Condition | State |
|---|---|
| Valid scope selection | Enabled — green border Allow, red border Deny |
| Too-broad combination | Both disabled (35% opacity, cursor: not-allowed) |

Clicking Allow or Deny:
1. Creates a rule matching the selected scope (process + destination + duration + route)
2. Sends a `ResolvePending` request to the daemon with the action
3. Closes the window immediately

If the user selects `any destination` with a specific process and clicks Allow: no destination field is stored in the rule — it matches all destinations for that process. This is intentional and valid.

---

## 8. One-Time Decision vs Rule Creation

Every Allow or Deny click creates a rule (scoped by the user's selections). There is no "just this once" mode — the minimum scope is the narrowest possible (specific process + specific subdomain/IP), which is functionally equivalent to a session-scoped one-time decision.

If the user genuinely wants no rule created (e.g. temporary exception), they should select `THIS SESSION` and the narrowest destination scope. The rule expires on daemon restart.

---

## 9. Rule Construction Reference

The following table maps every UI state combination to the resulting `Rule` struct fields:

| Process toggle | Destination toggle | `process_name` | `destination` |
|---|---|---|---|
| `firefox` | `accounts.google.com` | `Some("firefox")` | `DomainExact("accounts.google.com")` |
| `firefox` | `*.google.com` | `Some("firefox")` | `DomainWildcard("google.com")` |
| `firefox` | `any` | `Some("firefox")` | none (matches all) |
| `all processes` | `accounts.google.com` | `None` | `DomainExact("accounts.google.com")` |
| `all processes` | `*.google.com` | `None` | `DomainWildcard("google.com")` |
| `all processes` | `any` | — | — *(blocked)* |
| `firefox` | all 4 octets active | `Some("firefox")` | `IpExact("142.250.80.100")` |
| `firefox` | 3 octets active (/24) | `Some("firefox")` | `Cidr("142.250.80.0/24")` |
| `firefox` | 2 octets active (/16) | `Some("firefox")` | `Cidr("142.250.0.0/16")` |
| `firefox` | 1 octet active (/8) | `Some("firefox")` | `Cidr("142.0.0.0/8")` |
| `unknown` | all 4 octets active | `None` | `IpExact("142.250.80.100")` |
| `unknown` | 3 octets active (/24) | `None` | `Cidr("142.250.80.0/24")` |

The `duration` field comes from the duration toggle (`UntilRestart` or `Permanent`).  
The `route_target` comes from the egress chip selection (optional).

---

## 10. Scenarios Summary

| Scenario | Process | Destination | Dialog state |
|---|---|---|---|
| Normal | `firefox` | `accounts.google.com` | All options available |
| IP only | `curl` | `(unknown)` | Domain toggles replaced by CIDR picker |
| Both unknown | `(unknown)` | `(unknown)` | Warning banner; process locked; `any` destination hidden; destination required |

## SNI deferral for unknown TLS connections (Bug 26, 2026-09-16)

**Symptom.** After the daemon had been running for a while, decision dialogs
appeared in bursts showing bare IPv4/IPv6 addresses instead of hostnames —
typically many addresses from a single CDN range, one dialog per new IP.

**Root cause.** The pending decision fired on the connection's first packet —
the SYN. A SYN never carries a TLS ClientHello, so the hostname is
unknowable at that point, and the IP→domain cache only knows IPs seen before
(via prior SNI) or learned by the DNS snoop. Because a Pending verdict DROPS
the SYN, the handshake could not complete, so the ClientHello — the only
packet that carries the SNI — could never arrive to fill the dialog in. For
any rotating CDN IP that the cache had not seen, the only possible outcome
was a bare-IP dialog (and, once allowed, a new `IpExact` rule — hence the
rule-table full of per-IP allows).

**Fix.** `ControlService::register` now returns `FlowDecision::DeferSni`
instead of opening a pending when ALL of these hold:

- no rule matched (the decision would be Pending),
- the flow is TCP with destination port 443,
- the classified packet is the SYN,
- no hostname is known (otherwise the dialog already has a domain).

`DeferSni` accepts the bare handshake (verdict Accept, never cached) so the
ClientHello arrives. Pending verdicts are deliberately never cached, so the
ClientHello is re-classified and either:

* matches an existing rule by hostname — the connection flows with **no
  dialog at all** (this is what reduces decision prompts), or
* opens the pending **with the real hostname** (verified live: a curl to a
  never-seen IP produces a pending carrying the SNI name, `tcp_syn=false`),
  or
* non-TLS traffic on 443 (no ClientHello ever) opens an IP-only pending on
  its first payload packet — same as before, just one packet later.

**Exposure.** For an unknown TLS connection the handshake (SYN/SYN-ACK/ACK)
passes unclassified; the ClientHello itself is the first gated packet and is
dropped while the dialog is open, so no application payload flows before a
verdict.

**Caveat.** Domain-scoped *Route* rules first match at ClientHello time, one
round-trip after conntrack NEW, so the initial NAT binding was made on the
default egress. The SNI seen on the ClientHello is written to the shared
DNS cache, so the application's reconnect attempt matches the route rule at
SYN time and routes correctly from a clean connection.

**Tests.** `control-service`: `syn_without_domain_defers_instead_of_pending`,
`client_hello_with_domain_opens_pending_with_domain`,
`deferred_syn_resolves_silently_once_domain_known`,
`non_https_syn_still_pends_immediately`. `FlowContext` gained a
serde-defaulted `tcp_syn` flag (set by the classifier from the packet).
