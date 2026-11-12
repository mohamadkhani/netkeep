# Destination and process misattribution in Netkeep

**Investigation date:** 2026-11-12 → 2026-11-13
**Base commit:** `83d0499` (`main`)
**Status:** read-only investigation of the live system. No code, rule, or database change was made; this document and its evidence companion are the only artifacts added.
**Companion file:** [Evidence tables](2026-11-misattribution-evidence.md)

This document records what was established from the live daemon, how it was established, which mechanisms can produce it, and the fix order that follows. Claims are marked **proven** (directly visible in logs and reproducible), **inferred** (the mechanism fits all observed data but the exact step was not logged), or **not established** (cannot be decided from the available evidence).

---

## 1. Executive summary

Netkeep can apply a policy verdict to a connection using a `(process, destination)` pair that never occurred together. The wrong pair is then written to the rule store as a `Permanent` rule and replayed against other pending connections.

Three independent weaknesses compound:

1. **The destination name is not connection-scoped.** `SniDnsCache` maps a destination IP to a list of domains and returns the most recent one (`list[0]`). The map is keyed by IP only: it is shared by every local process, ignores the destination port, and mixes in-band TLS SNI / HTTP `Host` observations with DNS-cache answers. A TCP SYN carries no SNI, but a cache-derived name makes `destination_domain` non-`None`, which suppresses the SNI deferral — so the verdict is made before the real ClientHello arrives.
2. **A pending decision can be completed by a different socket.** The pending fallback dedup keys on `(destination_ip, destination_port, protocol)` only. A later packet to the same destination can upgrade the pending with its process name and domain. Two more layers can supply a foreign name: the destination-keyed `AttrCache` restore, and the eBPF `PORT_PIDS` fallback, which is keyed by source port only.
3. **The answer is permanent and amplified.** The decision dialog copies `flow.process_name` / `flow.destination_domain` verbatim into a `ui-<epoch>` `Permanent` rule. After `AddRule`, `AddRuleWithProcessPriority`, and `ResolvePendingWithRule`, `sweep_pending()` re-evaluates **every** pending against the **entire** rule set and silently resolves the ones that now match.

Proven consequences in the live system:

- An existing Deny for `synara → synara-account-api-trial.synara-orgs.workers.dev` was bypassed by classifying the same connection as `synara → events.kiloapps.io` (Route).
- `ssh → models.dev` exists as a `Permanent`, `Route`, `/usr/bin/ssh` rule (`ui-1794205260`). `ssh` never connects to port 443; the policy verdict for this rule appears **zero times** in 2.41 M journal lines. The rule was created in the same second as `sweep_pending: auto-resolving pending-16 (Some("ssh") → Route)`. Which upstream step produced the pending is not established (§4.6).
- One TCP connection to `5.202.198.83:22` was labelled `oevaite.kaariiz.com` and then `sm.logicamp.dev` three seconds later. `ssh` carries no application-layer name, so in the current pipeline the only source is the shared IP→domain cache.
- 57 cases where the same 4-tuple changed domain within 15 s; in 17 the **action** changed (Allow ↔ Route ↔ Deny).
- 3,674 pending decisions were auto-resolved without a dialog. One burst resolved 100 pendings in a single second.
- 71 of the 599 rules in the 09:41 snapshot never matched a single journal line.

**Inferred, from timing and zero DNS observations:** a borrowed process name produced the `kilo → …workers.dev` Deny (`ui-1794510938`), which then denied `synara` flows until the restart (§4.5). The attribution step itself was never logged.

The recommended minimum fix is five surgical changes in Stage 0 (§7). Naming `ssh` destinations needs the command line at connect time and, generally, an eBPF uprobe on `getaddrinfo`/`gethostbyname`; `known_hosts` plus reverse DNS can only supply **unselected UI candidates**, never a cache that decides policy (§6).

Nothing has been changed in the live system. The rule-cleanup list in §8 and the open decisions in §10 await confirmation.

---

## 2. Scope, data sources, and method

### 2.1 Environment

- Daemon: `netkeepd.service`, running as root, `NETKEEP_DNS_FORWARDER=1`.
- Control socket: `/run/netkeep/netkeep.sock`, queried read-only as `mohamad` with `netkeep-cli`.
- Rule database: `/var/lib/netkeep/netkeep.db` is root-only and no passwordless sudo was available. **The database was never read or written directly.** All rule evidence comes from the control API (`netkeep-cli rule list --format json`).
- Daemon restart during the investigation: pid 663936 → 1174639 at 2026-11-12 23:45:45. `UntilRestart` rules did not survive it, which is itself evidence (§4.5).

### 2.2 Corpora

| Artifact | Size / span | Use |
|---|---|---|
| `netkeepd` journal (`journalctl -u netkeepd -o short-iso`) | 2,414,333 lines, 420 MB, 2026-09-30 09:50:44 → 2026-11-12 09:46:58 | policy verdicts, proxy targets, sweeps, DNS attribution |
| `policy:` lines | 199,073 | applied rule, process, domain, destination, source port |
| `transparent proxy:` lines | 2,154,978 | in-band CONNECT/SNI target and proxy fallback attempts |
| `sweep_pending: auto-resolving` lines | 3,674 | silent approvals and their process/action |
| `dns-forwarder: … process=… domain=…` lines | 29,896 | which app resolved which name |
| Rule dump at 2026-11-12 09:41 | 599 rules | baseline for per-rule evidence |
| Rule dump at 2026-11-12 10:39 | 604 rules | drift check |
| Live rule dump at 2026-11-13 00:25 | 602 rules | post-restart state |
| Flow events (`flow list --limit 5000`) | 5,000, 2026-11-12 00:17–09:43 | per-flow state, shared-IP collisions |

The extracted evidence is in [2026-11-misattribution-evidence.md](2026-11-misattribution-evidence.md). Raw artifacts stayed outside the repository because the journal alone is 420 MB.

### 2.3 Joins and their limits

- **Policy line ↔ proxy line.** The reliable join is the client source port plus the destination port, within one second: `policy: … dst=188.114.99.0:443 src=:50700` and `transparent proxy: 192.168.100.120:50700 -> host:443`. This is what proves a destination substitution. A single proxy line is not absolute proof of the final target because the proxy also logs fallback hint attempts; the three cited cases are same-second, same-port, and consistent with the rule that fired.
- **Policy log dedup.** `log_policy_match` suppresses repeated `(process, domain, destination_ip)` lines for `POLICY_LOG_DEDUP_SECS = 300` (`crates/control-service/src/lib.rs:15,269`). *Absence* of a line is therefore strong but not absolute evidence; *presence* of contradictory lines is conclusive.
- **Rule ids encode creation time.** `ui-<epoch_secs>` is generated by the dialog (`apps/gpui/src/components/action_footer.rs:732,847`; also `apps/gpui/src/settings/mod.rs:630`). This is the primary rule↔journal correlation key. A rule id is not a sequence number.
- **Rule snapshots drift.** The live store changed from 599 to 604 to 602 rules while the investigation ran (rules added by the running UI, `UntilRestart` rules removed by the restart). Counts are as-of the stated dump, not constants.
- **Source-port reuse.** The same `(destination_ip, destination_port, source_port)` can recur across days. All flip analysis is bounded to 15 s and same-day.
- **CNAME aliasing.** A policy domain can legitimately be the canonical name behind the name the proxy dials (`a632.t.akamai.net` vs `api.marscode.com`). The aggregate policy↔proxy mismatch count in §4.9 is therefore an upper bound, not a bug count. The case studies do not rely on aliasing: they are either cross-registrant substitutions or flips inside one connection.
- **Root-only DB.** No schema-level or historical-rule evidence is available. Deleted rules can only be studied through their ids in the journal.

---

## 3. How a flow gets its two names

The current pipeline, in order:

1. **Packet capture.** NFQUEUE delivers a packet; the transparent-proxy parser can attach `sni_hint` (TLS SNI or HTTP `Host`). A SYN has `tcp_syn = true` and no hint. `FlowContext` (`crates/core-types/src/lib.rs:86`) has `destination_domain: Option<String>` but **no field recording where that domain came from**.
2. **Process attribution.** `ProcProcessResolver` asks `SOCK_DIAG` for `(src_ip, src_port)`, falls back to `/proc/net/{tcp,tcp6,udp,udp6}`, then to eBPF socket maps. `dns-tracker` keeps a full key `(src_ip, src_port, protocol)` and a port-only key `(src_port, protocol)`; `lookup_pid` prefers whichever entry is **newer**, and the port-only entry is accepted for up to 10 s (`crates/dns-tracker/src/sock_tracker.rs:202-260`).
3. **Destination attribution.** `FlowClassifier::resolve_domain` (`crates/flow-classifier/src/lib.rs:296`) prefers the in-band `sni_hint`; if there is none it falls back to `SniDnsCache::lookup(dst_ip)`. QUIC always uses the cache because QUIC v1 encrypts SNI. `SniDnsCache` (`crates/flow-classifier/src/lib.rs:53-126`) is `HashMap<ip, Vec<DomainEntry>>`; `insert_with_ttl` puts the newest first; `lookup` returns `list[0]`. The DNS forwarder populates it from every resolved answer (`crates/dns-tracker/src/forwarder.rs:290`). Entries carry no process and no port.
4. **Layer-0 restore.** If live resolution failed, `AttrCache::restore` (`crates/enforcer/src/nfqueue.rs:155-200`, called at `:538`) can fill the process from `(dst_ip, dst_port)` first, then `(domain, dst_port)`. A successful resolution populates both maps (`:566`). Ambiguity is detected only by comparing the process **name**: a conflicting entry is removed, and the next successful resolve can insert again (`insert_unless_ambiguous`, `:131-153`).
5. **Policy evaluation.** `policy-engine` matches process and destination. `process_matches` (`crates/policy-engine/src/lib.rs:77-97`) prefers exe equality; otherwise it compares names; if the flow has no process name, a rule with a specific `IpExact`/`DomainExact` destination still applies.
6. **SNI deferral.** The control service returns `DeferSni` only when `destination_domain.is_none() && protocol == Tcp && destination_port == 443 && tcp_syn` (`crates/control-service/src/lib.rs:880`). A cache-derived domain is non-`None`, so it defeats this guard.
7. **Pending.** `DecisionEngine::register_unknown_flow` (`crates/decision-engine/src/lib.rs:101`) dedups exact flows by `FlowKey` (`:25`), then has a fallback `find` over `(destination_ip, destination_port, protocol)` where either side may lack a process name. That path can also **upgrade** an existing pending with a new process name and domain (`:135-155`). The source port is not part of this key.
8. **Dialog.** `show_decision_dialog` copies `flow.process_name` / `flow.process_exe` verbatim when scope is `Specific`, builds the destination matcher from `flow.destination_domain`, and writes `ui-<epoch>` with duration `Permanent` by default (`apps/gpui/src/components/action_footer.rs:55-63,622,732`).
9. **Sweep.** `sweep_pending` (`crates/control-service/src/lib.rs:651`) lists every pending, calls `resolve_action` against the whole rule set, and resolves anything that is not `Ask`. It runs after the three rule-writing requests (`:326,334,474`). The log line contains the pending id, process name, and action — **not** the rule id or the domain.

### Name sources and their scope

| Source | Lifetime | Key | Knows the process? | Knows the port? | In-band for this connection? |
|---|---|---|---|---|---|
| TLS SNI / HTTP Host | until evicted from the list | destination IP | no | no | **yes** |
| DNS forwarder answer | DNS TTL (clamped) | destination IP | no | no | no (a prior observation) |
| `AttrCache` IP entry | `PROC_ATTR_TTL_SECS` | `(dst_ip, dst_port)` | name/exe/app only | yes | no |
| `AttrCache` domain entry | `DOMAIN_ATTR_TTL_SECS` | `(domain, dst_port)` | name/exe/app only | yes | no |
| `PORT_PIDS` | 10 s | `(src_port, protocol)` | pid/comm | source port only | kernel observation, no destination check |
| Pending fallback | pending lifetime | `(dst_ip, dst_port, protocol)` | yes | destination only | no source-port check |

Every row except the first can attach a name that belongs to a different connection. The first row is authoritative but exists only after the handshake, which is exactly the window the deferral is supposed to protect.

---

## 4. Evidence

All times are `+03:30`. Rule creation times are decoded from the rule id. Full tables are in the companion evidence file.

### 4.1 `ssh` inherits HTTPS names from the IP cache

`ssh` carries no SNI and no HTTP `Host`. In the whole corpus, `ssh` policy verdicts go to port 22 (2,174) and 52176 (16); there is not a single `ssh` verdict on 443. Yet 2,051 of 2,190 `ssh` verdicts carry a domain.

The first appearance of one such name:

```
2026-11-01T10:53:23  policy: id=ui-1792666817 action=Allow process=Some("brave") domain=Some("oevaite.kaariiz.com") dst=5.202.198.83:443 src=:32906
2026-11-01T10:53:42  policy: id=ui-1792666817 action=Allow process=Some("ssh")   domain=Some("oevaite.kaariiz.com") dst=5.202.198.83:22  src=:59808
```

`oevaite.kaariiz.com` first appears from `brave` on `:443`; 19 seconds later the same name is attached to an `ssh` connection on `:22`. The DNS forwarder logged **zero** queries with `process=ssh` in the entire journal, and there is no `~/.ssh/config`. The name cannot have come from `ssh`'s own resolution; it came from the shared IP entry.

The cleanest proof is a single TCP connection whose domain changes inside itself:

```
2026-11-09T09:39:04  policy: id=ui-1792666817 action=Allow process=Some("ssh") domain=Some("oevaite.kaariiz.com") dst=5.202.198.83:22 src=:59056
2026-11-09T09:39:07  policy: id=ui-1792827494 action=Allow process=Some("ssh") domain=Some("sm.logicamp.dev")     dst=5.202.198.83:22 src=:59056
```

Same destination and same source port three seconds apart, with two different domains. Either this was one connection whose cache entry changed, or two back-to-back connections whose names came from the same shared cache; in neither case does `ssh` carry the name. A TCP connection has one destination, and the domain is not part of what `ssh` sends.

`5.202.198.83` accumulated **22** distinct domains in policy lines and `ssh` used **14** of them. `/etc/hosts` maps the IP to `files.logicamp.dev`, `searxng.kaariiz.com`, and `m.tameshk-company.ir`; reverse DNS returns those same three names. None of them explains `oevaite`, `sm.logicamp.dev`, `litellm`, `sub2api`, `devsie2r`, or `lcr`.

The action stayed `Allow` in the flip because a process-less global rule `ui-1792666817` (`IpExact 5.202.198.83`, 2,834 matches) covers the IP. The wrong domain is still durable: it is what the dialog shows and what a new rule would record.

### 4.2 `gvfsd-http` routes a connection to `api.ipify.org` as `api.zeroeval.com`

```
2026-11-10T11:49:19  policy: id=ui-1793912852 action=Route process=Some("gvfsd-http") (gvfs) domain=Some("api.zeroeval.com") dst=188.114.98.0:443 src=:40758
2026-11-10T11:49:19  transparent proxy: 192.168.1.101:40758 -> api.ipify.org:443 via 127.0.0.1:2080
```

Same second, same source port. A rule for the real host already exists (`ui-1791022832`, `gvfsd-http → api.ipify.org`, Allow, 2,336 matches), but the connection was routed through the `api.zeroeval.com` Route rule (`eg-1790749737`) instead. This is a **destination** substitution with the correct process.

### 4.3 A Deny is bypassed by substituting another domain on the same IP

```
2026-11-12T01:14:38  policy: id=ui-1794344181 action=Route process=Some("synara") domain=Some("events.kiloapps.io") dst=188.114.99.0:443 src=:50700
2026-11-12T01:14:38  transparent proxy: 192.168.100.120:50700 -> synara-account-api-trial.synara-orgs.workers.dev:443 via 192.168.100.121:1082
```

`ui-1794398999` has denied `synara → synara-account-api-trial.synara-orgs.workers.dev` since 2026-11-11 15:39:59 (277 matches in the corpus). The real connection used that host. The verdict used `events.kiloapps.io`, matched the older Route rule `ui-1794344181` (created 2026-11-11 00:26:21, 26 matches), and the Deny never applied.

The two names resolve to the identical four addresses (`188.114.98.0`, `188.114.99.0`, `2a06:98c1:3122::`, `2a06:98c1:3123::`), so neither IP nor port distinguishes them. Cloudflare anycast makes this a general class, not a one-off.

A post-restart verdict at 2026-11-12 23:45:58 shows the Deny working again (`id=ui-1794398999 … synara → …workers.dev`), which confirms that the rule is correct and that the earlier verdict was a misclassification, not an intentional allow.

### 4.4 The `brave` / `synara` report: the process was right, the destination was borrowed

At 12:05 on 2026-11-12 the report was a dialog about `brave` while the connection belonged to `synara`. The logs do not support that exact pairing, and the final diagnosis is narrower: the `brave` verdict below was a real `brave` connection, and the separate `synara` connection had the right process but a borrowed destination.

```
2026-11-12T12:05:13  policy: id=ui-1793008069 action=Route process=Some("brave") (brave-bin) domain=Some("clerk.sailresearch.com") dst=188.114.98.0:443 src=:36094
2026-11-12T12:05:13  transparent proxy: 192.168.1.101:36094 -> clerk.sailresearch.com:443 via 192.168.1.108:1082
2026-11-12T12:05:27  sweep_pending: auto-resolving pending-30 (Some("synara") → Route)
2026-11-12T12:05:27  sweep_pending: auto-resolving pending-31 (Some("synara") → Route)
2026-11-12T12:05:48  policy: id=ui-1794472527 action=Route process=Some("synara") domain=Some("clerk.sailresearch.com") dst=188.114.99.0:443 src=:50140
2026-11-12T12:05:48  transparent proxy: 192.168.1.101:50140 -> synara-account-api-trial.synara-orgs.workers.dev:443 via 192.168.1.108:1082
```

`brave` was a separate, correctly attributed connection. The `synara` connection was attributed to the correct process but inherited `clerk.sailresearch.com` as its destination. In the same second that `ui-1794472527` (`synara → clerk.sailresearch.com`) was created, the sweep resolved two `synara` pendings; at 12:05:48 a `synara` connection to `workers.dev` was labelled `clerk` and routed. `ui-1794472527` is absent from the post-restart dump; its stored duration was never captured, but disappearance at a restart is the `UntilRestart` signature.

The proxy log at 12:05:48 also shows the fallback behavior that makes a single proxy line ambiguous as evidence: it first dials `…workers.dev`, then retries CONNECT with `clerk.sailresearch.com`. Both names were present as candidates for that connection. The policy must not decide from either candidate list; it needs the in-band name with provenance.

### 4.5 The `kilo` / `synara` report: the domain was right, the process was borrowed

The 22:44–22:51 sequence on 2026-11-12 shows the other direction of the same class:

```
22:44:23–24  policy: id=ui-1794398999 action=Deny process=Some("synara") domain=Some("synara-account-api-trial.synara-orgs.workers.dev")
             on 188.114.99.0, 188.114.98.0, 2a06:98c1:3122::, 2a06:98c1:3123::   (4 correct Deny verdicts)
22:45:38     sweep_pending: auto-resolving pending-10 (Some("kilo") → Deny)
             … pending-11, pending-12, pending-13, all in the same second
22:45:38     policy: id=ui-1794344181 action=Route process=Some("synara") domain=Some("events.kiloapps.io") dst=188.114.98.0:443
22:51:13     policy: id=ui-1793009835 action=Deny process=Some("kilo") domain=Some("events.kiloapps.io") … (4 addresses)
22:51:24     policy: id=ui-1794510938 action=Deny process=Some("kilo") domain=Some("…workers.dev") … (4 addresses)
23:45:58     policy: id=ui-1794398999 action=Deny process=Some("synara") domain=Some("…workers.dev")   (correct Deny resumes after restart)
```

`ui-1794510938` (`kilo → …workers.dev`, Deny) was created at 22:45:38, the exact second of the four `kilo` sweeps. `kilo` never resolved `workers.dev` anywhere in the journal — zero `dns-forwarder` lines and zero policy lines before 22:51:24 — and the only lines that attribute that name to `kilo` are the four 22:51:24 verdicts. **Inferred:** those four connections were `synara` flows to `workers.dev`, and the `(dst_ip, 443)` keys had just been refilled as `kilo` by the 22:51:13 `events.kiloapps.io` connections. The attribution step itself was not logged.

This is the `AttrCache` shape: the domain is correct, the process is borrowed from the previous user of the same four addresses. The rule was gone after the 23:45 restart (duration not captured, but consistent with `UntilRestart`); the permanent `synara` Deny resumed immediately.

### 4.6 `ssh → models.dev`: a rule for a connection that cannot exist

Rule `ui-1794205260`:

| Field | Value |
|---|---|
| Action / duration | `Route` / `Permanent` |
| Process | `ssh` (`/usr/bin/ssh`) |
| Destination | `DomainExact models.dev` |
| Egress | `eg-1790749737` |
| Created | 2026-11-09 09:51:00 (rule id epoch) |
| Journal matches | **0** |

At 2026-11-09 09:51:00, the same second:

```
sweep_pending: auto-resolving pending-16 (Some("ssh") → Route)
```

The rule and the auto-resolution share one second, which is the signature of a dialog answer followed immediately by `sweep_pending()`. `ssh` only ever reaches `:22` (and one structured `:52176` endpoint); `models.dev` only resolves on 443. The two names never share a connection. Because the sweep evaluates each pending against the new rule, pending-16 must already have carried `ssh` + `models.dev` before the sweep.

Which upstream step fabricated the pair is **not established**. The candidates are:

- the pending fallback upgrade (`decision-engine/src/lib.rs:121-155`), which accepts a name/domain from any later packet to the same `(dst_ip, dst_port, protocol)`; or
- the eBPF port-only fallback (`sock_tracker.rs:202-260`), which can attribute a flow to a process that used the same source port within 10 s.

The sweep log does not include the rule id or the domain, so the exact step cannot be reconstructed. The important part is established: the pair is impossible, it was persisted, and the creation second is a sweep second.

`codex → api.zed.dev` (`ui-1793013554`, created 2026-10-26 14:49:14) is the same shape: zero matches in the corpus. `api.zed.dev` appears with `zed-editor`, plus isolated `codium` / `gvfsd-http` / `synara` lines that are themselves mislabels.

### 4.7 `synara → api.zed.dev`: a rule created during a sweep burst

`ui-1794433438` (`Allow`, `synara`, `DomainExact api.zed.dev`) has rule-id time 2026-11-12 01:13:58. At that second:

```
01:13:45  policy: id=ui-1792233615 action=Deny process=Some("zed-editor") domain=Some("api.zed.dev") dst=188.114.99.0:443
01:13:50  policy: id=ui-1792233615 action=Deny process=Some("zed-editor") domain=Some("api.zed.dev") dst=188.114.98.0:443
01:13:58  sweep_pending: auto-resolving pending-106 (Some("synara") → Allow)
01:13:58  sweep_pending: auto-resolving pending-107 (Some("synara") → Allow)
01:14:08  policy: id=ui-1794433438 action=Allow process=Some("synara") domain=Some("api.zed.dev") dst=188.114.98.0:443 src=:48268
```

`zed-editor` was denied on `api.zed.dev`; eight seconds after the last Deny, two `synara` pendings were auto-allowed in the second the new rule was created; ten seconds after that, the new Allow matched a `synara` connection to the same anycast IP. The rule has exactly one match. Whether that `synara` flow was really `api.zed.dev` or inherited the name from the `zed-editor` connection is **not established**, but the timing and the single match make "inherited" the parsimonious explanation.

### 4.8 Accumulation in the rule store

The dialog writes a new rule per answer; there is no dedupe on `(process, destination)`.

At the 09:41 snapshot:

| Domain | Rules | Distinct processes |
|---|---|---|
| `models.dev` | 19 | 12 |
| `events.kiloapps.io` | 12 | 7 |
| `sm.logicamp.dev` | 11 | 10 |
| `ingest.kilosessions.ai` | 11 | 5 |
| `registry.npmjs.org` | 10 | 7 |
| `github.com` | 10 | 9 |
| `raw.githubusercontent.com` | 8 | 7 |
| `clerk.sailresearch.com` | 7 | 7 |

By process: `kilo` 128, `betterbird-bin` 45, `codium` 40, `codex` 27, `synara` 24, none 22, `java` 21, `gvfsd-http` 21, `helm` 18.

`gvfsd-http` is a GVFS file helper, yet it owns 21 rules including `api.zeroeval.com`, `llm-stats.com`, `events.kiloapps.io`, `ingest.kilosessions.ai`, `clerk.sailresearch.com`, `api.ipify.org`, `cdn.tapsell.xyz`, and `r2.dev`. Four of those account for 238 logged matches between them: `api.zeroeval.com` 72, `events.kiloapps.io` 65, `clerk.sailresearch.com` 62, `ingest.kilosessions.ai` 39. §4.2 shows at least one of those flows was really `api.ipify.org`.

22 rules have `process_name: null`; because `process_matches` treats `(None, _)` as "any process", they are global. Three are global **Deny**: `events.kiloapps.io` (`ui-1793692455`), `flagcdn.com` (`ui-1794391353`), `ingest.t3.codes` (`ui-1794383216`). 116 rules are name-only (`process_exe: null`), so they follow a name across binary updates — intended, but it also makes a wrong name durable.

71 rules never matched a journal line, including the two impossible pairs above, two `gvfsd-http` routes to `cdn.tapsell.xyz` / `auth.tokenharbor.ai`, and several routes for binaries that no longer run (old Betterbird and Kilo paths under `/opt.old` and `/tmp/Downloads`).

### 4.9 Scale of the shared-IP problem

- `188.114.98.0` carries **137** distinct domains in policy lines; `188.114.99.0` carries **147**; `5.202.198.83` carries **22**.
- Across all policy lines, **2,070 of 7,070** destination IPs carry more than one domain. Restricting to 443: **1,876 of 6,546**.
- **57** same-4-tuple domain changes within 15 s; **17** of those also changed the action. The full table is in the evidence file.
- **11,908** domain-bearing verdicts are on a non-443 port (5,324 on `:80`, 2,046 on `:22`, 1,026 on `:123`, 919 on `:53782`, 691 on `:5228`, 407 on `:993`, …). A name learned for an HTTPS flow can therefore be attached to DNS, NTP, IMAP, SSH, or a Kubernetes proxy flow.
- The policy↔proxy join found 7,649 differing pairs (1,362 triples), 6,041 of them across registrable domains. This is an upper bound because of CNAME aliasing (§2.3). The conclusive subset is the flip analysis and the case studies.

### 4.10 Sweep amplification

`sweep_pending()` is a global re-evaluation, not a targeted application of the rule the user just created.

- **3,674** pendings auto-resolved in the corpus: Allow 2,497, Route 910, Deny 267.
- Per process: `kilo` 779, `curl` 386, `codium` 375, none 209, `synara` 184, `gvfsd-http` 122, `trae` 122, `betterbird-bin` 116, `codex` 103, `keepassxc` 100.
- Bursts: **100 in one second** (2026-10-04 12:30:13, all `keepassxc`, all `Allow`), 29 (2026-11-07 18:11:20, all `trae`, all `Deny`), 24, 23, 22, 19, 16, 16, 16, 14.
- The 29-`Deny` burst is a clean demonstration that the sweep is global: the only rule created at 18:11:20 was `ui-1794062480` (`trae → Any`, **Route**), yet every resolved pending became `Deny`. The Deny came from another rule already in the set (the process-less `events.kiloapps.io` Deny is the candidate), not from the answer the user had just given.
- The sweep log line omits the rule id and the domain, which is why reconstructing "which answer approved this connection" requires the rule-id epoch and the surrounding policy lines.

A user answering one dialog can therefore approve connections they never saw, including a Deny or a Route that changes egress.

### 4.11 Dialog queue

`apps/gpui/src/monitor.rs:12` allows exactly one decision window at a time (`DECISION_WINDOW_OPEN`); other pendings are deferred (`:31-52`) and the flag is cleared when the window closes (`:83`). The dialog fetches its content by pending id, so it is internally consistent, but during a burst it can be several pendings behind the flow that triggered it. Around `01:20:59` on 2026-11-12 the flow dump holds 72 events in eight seconds, 70 of them on the four Cloudflare addresses and 51 of them still `Pending`; the tray log shows interleaved `pending-1 … pending-21` spawns.

This is a low-severity UX amplifier, not a source of wrong data. It becomes dangerous only because the data itself can be wrong (§4.4–4.5).

---

## 5. Root causes, ranked

| # | Cause | Where | What it explains | Confidence |
|---|---|---|---|---|
| RC-1 | Destination cache is keyed by IP only, shared by all processes, ignores port, mixes SNI/Host with DNS, and `lookup` returns the newest entry | `crates/flow-classifier/src/lib.rs:53-126` | wrong destination in `ssh`, QUIC, CDN, and shared-hosting flows; 57 flips | High |
| RC-2 | SNI deferral is gated on `destination_domain.is_none()`, so any cached name decides the SYN | `crates/control-service/src/lib.rs:880` | verdict before the real ClientHello; §4.2–4.4 | High |
| RC-3 | Pending name/domain upgrade keys on `(dst_ip, dst_port, protocol)` and accepts a later packet's fields | `crates/decision-engine/src/lib.rs:121-155` | foreign process/domain in a dialog; `ssh → models.dev` (candidate) | High |
| RC-4 | `AttrCache` restore is destination-keyed; ambiguity compares only the process name, removes the entry, and allows refill | `crates/enforcer/src/nfqueue.rs:131-200,538` | `gvfsd-http` inheriting other apps; `kilo`/`synara` §4.5 | Medium-high |
| RC-5 | eBPF `PORT_PIDS` is used for TCP and preferred when newer, with no destination check | `crates/dns-tracker/src/sock_tracker.rs:202-260` | wrong process under port reuse; `ssh → models.dev` (candidate) | Medium |
| RC-6 | `sweep_pending` re-evaluates every pending against every rule | `crates/control-service/src/lib.rs:651` | one answer approves unseen connections; 100-per-second burst | High (mechanism) |
| RC-7 | Dialog copies fields verbatim, defaults to `Permanent`, dedupes nothing, and offers no correction | `apps/gpui/src/components/action_footer.rs:55-63,622,732` | wrong pair becomes durable; 19 `models.dev` rules | High |
| RC-8 | `process_matches` accepts name-only equality and applies specific destinations to unattributed flows | `crates/policy-engine/src/lib.rs:77-97` | a wrong name/domain generalizes to another app; global Deny | Medium |
| RC-9 | One dialog at a time with an unbounded deferral queue | `apps/gpui/src/monitor.rs:12-83` | user answers a stale pending | Low |

---

## 6. The `ssh` / no-SNI question: what can name a destination?

The question was whether `~/.ssh/known_hosts` plus `dig` (reverse DNS) can seed a cache that names `ssh` destinations. **They can seed candidates for the UI; they cannot seed a cache that policy uses.** The measurements:

- `known_hosts` has 32 host entries: 3 hashed (`|1|`, unusable without the hostname), 5 plaintext names (`git.logicamp.dev`, `git.logicamp.tech`, `github.com`, `localhost`, `sm.logicamp.dev`), and 7 IPs. Entries for `5.202.198.83` are all `[5.202.198.83]:52176`.
- `ssh` verdicts carry 30 distinct `(ip, port, domain)` triples. 1,445 of 2,051 (70.4%) have a name that appears literally in `known_hosts` (name-only match, port ignored), but 1,431 of those are just `sm.logicamp.dev` (1,126) and `github.com` (305). The coverage is concentrated in two names, not general.
- For `5.202.198.83`, `ssh` used **14** names; `known_hosts` contributes **2** names (`sm.logicamp.dev`, `git.logicamp.dev`, both stored only as `[5.202.198.83]:52176`), reverse DNS contributes **3** (`files.logicamp.dev`, `searxng.kaariiz.com`, `m.tameshk-company.ir`). The candidate set is 5 names for 14 observed names, with no way to choose.
- `ssh` made **zero** DNS queries through the forwarder (`process=ssh` lines: 0; `oevaite` queries: 0) and has no `~/.ssh/config`. At connect time Netkeep has no resolver observation to fall back on.

Why a cache would recreate the same bug:

1. **A prior is not an observation.** `known_hosts` records where the user connected *before*; `dig -x` records the current PTR. Neither says which host this connection is for. Treating either as authoritative is the same category error as treating the shared IP→domain map as authoritative.
2. **One IP, many names.** The exact case that broke `ssh` (22 domains on one address) cannot be resolved by a prior that lists two of them.
3. **Staleness and drift.** Hosts get renamed, reused, or renumbered; `known_hosts` entries persist.
4. **Wrong-name durability.** Any name that enters the policy path can be swept into a `Permanent` rule, which is the failure mode this investigation is about.

The accurate order for a no-SNI client is:

1. **Command line at connect time.** For `ssh`, read `/proc/<pid>/cmdline` when the connection is attributed: `ssh user@host` is the user's declared intent. Store it as a *hint* with provenance `cmdline`, not as an observation. Handle `ssh -J`, `ProxyJump`, and `ControlMaster` explicitly (the master connection carries the name; multiplexed sessions reuse it).
2. **eBPF uprobe on `getaddrinfo` / `gethostbyname`.** Pair the resolver call's PID/TID with the subsequent `connect` on the same thread/process. This generalizes beyond `ssh` and covers any libc-resolver client. It misses static Go/Rust resolvers and direct-IP connects; those remain unnamed.
3. **Bare `IP:port` when nothing is known.** Show the truthful value and let the user supply a name in the dialog. Do not guess.
4. **`known_hosts` / `/etc/hosts` / PTR only as unselected UI candidates**, clearly labelled "prior, not observed". A click fills the field; it does not create a rule by itself.

This is also the acceptance criterion for the fix: every `(process, domain)` pair in a rule must be backed by an observation for that process and that connection, or by an explicit user edit.

---

## 7. Fix plan (not applied)

Ordered by impact per unit of risk. Stage 0 is designed to close the proven cases without a schema migration.

### Stage 0 — surgical hotfix

**0.1 Carry domain provenance and defer on it.**

- Add a `DomainSource` to `FlowContext` (`crates/core-types/src/lib.rs:86`): `None | Sni | Host | Dns | Cmdline`.
- Set it in `resolve_domain` (`crates/flow-classifier/src/lib.rs:296`) and in the DNS-cache insert path.
- Change the deferral condition (`crates/control-service/src/lib.rs:880`) from `destination_domain.is_none()` to `domain_source` not being in-band (`Sni` / `Host`). Every TCP:443 SYN whose name is only a DNS/cache prior is deferred; the ClientHello then supplies the authoritative SNI and the existing re-classification path runs without a dialog.
- **Closes:** §4.2, §4.3, §4.4. A cached name can no longer decide a TLS connection.

**0.2 Make the destination cache process-scoped and ambiguity-aware.**

- Add `process_name` / `process_exe` to `DomainEntry` (`crates/flow-classifier/src/lib.rs:53`).
- The forwarder already knows the resolving app (`resolve_process`, `crates/dns-tracker/src/forwarder.rs:334`); store it with the DNS answer (`:290`).
- Add `lookup_for(ip, port, process)` and use it for policy paths. Return `None` when the IP has more than one live domain and none belongs to this process.
- Keep `lookup()` for display-only callers.
- **Closes:** the cross-process half of RC-1; removes the `ssh` inheritance.

**0.3 Require the source port and domain agreement for a pending upgrade.**

- In `register_unknown_flow` (`crates/decision-engine/src/lib.rs:121-155`), the fallback `find` must also match `source_ip` and `source_port`.
- Refuse to fill a domain when the pending already has a different one; refuse to fill a process when the pending already has a different one.
- **Closes:** RC-3 with a predicate change; prevents a retransmit from another socket from completing the dialog.

**0.4 Restrict the eBPF port-only fallback to UDP.**

- In `lookup_pid` (`crates/dns-tracker/src/sock_tracker.rs:202`), ignore `port_hit` when `protocol == Tcp` (and for QUIC where a full key exists). Keep it for UDP, where the full key genuinely cannot be built.
- **Closes:** RC-5 for TCP, including the second candidate mechanism for `ssh → models.dev`.

**0.5 Harden `AttrCache`.**

- Include `pid` and `exe` in the ambiguity comparison, not just `process_name` (`insert_unless_ambiguous`, `crates/enforcer/src/nfqueue.rs:131`). A different pid/exe on the same key poisons it even under the same name.
- Keep a poisoned key poisoned for the remainder of its TTL instead of removing it and letting the next successful resolve refill it.
- In `restore` (`:155`), when the flow has an **in-band** domain, try `(domain, port)` first and use the IP key only when there is no domain. The IP key is the weaker identity on shared anycast addresses.
- **Closes:** RC-4 and the §4.5 oscillation.

Acceptance for Stage 0:

- Unit tests listed in §9 pass.
- Replay of the journal shows no same-4-tuple domain change within 15 s.
- A `synara` connection to `188.114.98.0/99.0` is either labelled `synara-orgs.workers.dev` or has no domain — never `api.zed.dev` / `events.kiloapps.io`.
- `ssh` verdicts on `:22` carry no HTTPS domain unless the user explicitly supplied one.

### Stage 1 — ambiguity policy

1. **Refuse ambiguous IPs entirely.** If an IP has more than one live domain and no process match, return `None`. A pending then shows `IP:port` (truthful) instead of a fabricated hostname.
2. **Port-scope non-443 fallbacks.** Key DNS-derived answers by destination port where the port is meaningful (22, 25, 5432, …), or refuse to attach a web-domain answer to a non-web port. Today `ssh:22` can inherit any HTTPS name on the host.
3. **Scope `sweep_pending`.** Only resolve pendings that match the rule just added **and** belong to the same process as the answered flow. Add the rule id, domain, and provenance to the sweep log. Optionally require an explicit "apply to similar" opt-in.
4. **Narrow `process_matches`.** Keep the `(Some(_), None)` fallback for `Allow` / `Route` only; a `Deny` on an unattributed flow must not silently block a different app. Re-check the name-only widening against the provenance rules above.

### Stage 2 — accurate naming for no-SNI clients

5. **Command line at connect time** (`/proc/<pid>/cmdline`) for `ssh` and similar tools, stored as a `Cmdline` hint. Handle `ProxyJump` and `ControlMaster`.
6. **eBPF uprobe** on `getaddrinfo` / `gethostbyname`, paired with the `connect` on the same thread/process. This is the only general source that survives shared IPs and ports. Document the static-resolver and direct-IP gaps.
7. **UI candidate hints** from `known_hosts`, `/etc/hosts`, and PTR, always unselected and labelled as priors.

### Stage 3 — product and UX

8. **Show and correct provenance in the dialog.** "domain from SNI / DNS cache / cmdline / user" and editable process/destination fields. A wrong pair should not require a database edit to fix.
9. **Dedupe on insert** by `(process identity, destination)` and update the existing rule's action/egress instead of appending a new `ui-<epoch>`.
10. **Batch dialogs** per process/destination burst instead of a queue of single windows.

### Do not

- Do not key destination identity on `(dst_ip, dst_port)` alone; Cloudflare anycast makes four addresses serve hundreds of names.
- Do not use a `known_hosts`/PTR candidate as an authoritative name or let it suppress the SNI deferral.
- Do not fix `ssh` by banning domains on `:22` only; the same cache feeds DNS, NTP, IMAP, and Kubernetes proxy ports (11,908 non-443 verdicts).
- Do not broaden `process_matches` further to compensate for missing attribution.

---

## 8. Rule-store cleanup candidates (read-only list, awaiting approval)

Do this **after** Stage 0, not before: cleaning the store while the classifier still fabricates pairs will just refill it.

**Impossible / zero-match, delete:**

| Rule | Pair | Evidence |
|---|---|---|
| `ui-1794205260` | `ssh → models.dev`, Route | impossible; 0 matches; §4.6 |
| `ui-1793013554` | `codex → api.zed.dev`, Route | 0 matches; `api.zed.dev` belongs to `zed-editor` |
| `ui-1794433438` | `synara → api.zed.dev`, Allow | 1 match, 10 s after creation, in a sweep second; §4.7 |
| `ui-1794344181` | `synara → events.kiloapps.io`, Route | substitutes for the denied `workers.dev`; 26 matches; §4.3 |
| `ui-1794240746` | `gvfsd-http → cdn.tapsell.xyz`, Route | 0 matches, implausible for gvfsd |
| `ui-1793702653` | `gvfsd-http → auth.tokenharbor.ai`, Route | 0 matches, implausible for gvfsd |

**Review before deleting:**

- Three process-less Denys: `ui-1793692455` (`events.kiloapps.io`), `ui-1794391353` (`flagcdn.com`), `ui-1794383216` (`ingest.t3.codes`). They are global by construction; confirm intent.
- 22 process-less rules, especially the `IpExact` ones (`ui-1792666817` on `5.202.198.83`, `ui-1794317019` on `34.107.238.235`, `ui-1794461661` on `172.18.0.5`). A process-less `IpExact` Allow applies to every app on that IP.
- `ui-1793008069` (`brave → Any`, Route, 25,566 matches) and `ui-1790749270` (`chromium → Any`, Route, 28,906 matches) are broad; they are why mislabelled flows still get a plausible action.

**Collapse:**

- 19 `models.dev` rules across 12 processes; 8 `kilo` variants that differ only by extension release path; 11 `sm.logicamp.dev` rules across 10 processes. Keep the pair the user actually needs, one per process/destination.

**Already gone:** `ui-1794472527` and `ui-1794510938` disappeared at the 23:45 restart (duration not captured; consistent with `UntilRestart`). They are evidence, not cleanup items.

The live count is 602 at 2026-11-13 00:25 (599 `Permanent`, 3 `UntilRestart`). Re-export and verify ids immediately before any deletion; rule ids are timestamps, and the store changed during the investigation.

---

## 9. Verification plan

**Replay checks** (offline, using the journal):

1. No same-4-tuple domain change within 15 s.
2. Every `synara` flow to `188.114.98.0/99.0` carries `synara-orgs.workers.dev` or no domain; never `api.zed.dev` / `events.kiloapps.io`.
3. Every `ssh` flow on `:22` has no HTTPS domain unless the user supplied one.
4. For every `(process, domain)` pair in a verdict, there is a DNS/SNI/cmdline observation for that process and that flow — or the domain is absent.

**Unit tests:**

- `SniDnsCache::lookup_for` returns `None` for a different process and for an ambiguous IP; returns the entry for the owning process.
- Deferral triggers when the only domain is `Dns`; does not trigger for `Sni` / `Host`.
- Pending upgrade refuses a different source port and a contradicting domain.
- `AttrCache` poisons on a different pid/exe and stays poisoned for the TTL; `restore` prefers the domain key when the domain is in-band.
- `sweep_pending` touches only the same process and the just-added rule; the log contains the rule id.
- `(Some(_), None)` applies `Allow`/`Route` but not `Deny`.
- `PORT_PIDS` is not consulted for TCP.

**Metric:** policy verdicts whose `(process, domain)` pair has no observation for that process. Target 0. Emit it next to `netkeep.domain.resolved{source}`.

**Manual end-to-end:**

- `ssh` to `5.202.198.83` by IP, by name, and through `ProxyJump`; confirm the dialog shows `IP:port` or the cmdline name, never a random HTTPS name.
- Two apps on the same anycast IP, one allowed and one denied; confirm the Deny applies to the right process and does not leak.
- Answer a dialog during a burst; confirm only the intended pending resolves.

---

## 10. Open decisions

1. **`synara → synara-account-api-trial.synara-orgs.workers.dev`: allow or deny?** The current `Permanent` Deny (`ui-1794398999`) is being bypassed by the `events.kiloapps.io` Route. The fix will make the Deny effective, so the answer changes user-visible behavior.
2. **Are the broad `Any` routes intentional?** `brave → Any` and `chromium → Any` Route every flow for those apps through the proxy, which hides destination mistakes behind a plausible action.
3. **Should an IP-only `ssh` connection prompt with `IP:port`?** The alternative is to allow it silently until a name is known, which weakens the deny-by-default story.
4. **When to clean the store?** Recommendation: after Stage 0 is deployed and replayed clean, then delete the impossible rules and collapse clusters in one reviewed pass.
5. **Is the `(Some(_), None)` fallback still wanted for `Route`?** It was added for UX (avoid re-prompting the same host), but it also lets a Route apply to an unattributed flow.
6. **How should CNAME aliases be represented?** The proxy dials the requested name while DNS observes the canonical name; one flow can legitimately have two names. Decide whether rules match either, or only the requested name.

---

## 11. Tracking

Two Synara tasks were created in project `netkeep` (`e9321962-5312-4343-bc9d-95b63a3896c3`), priority high, no thread and no agent started:

| Task | Scope |
|---|---|
| `todo:830c7b0ec57f3243730edda08ec251a4` | `ssh` / no-SNI attribution: cmdline at connect → eBPF `getaddrinfo` uprobe → bare `IP:port`; `known_hosts` / `/etc/hosts` only as unselected UI hints; read-only precision measurement first. Acceptance: no same-4-tuple domain flip in 15 s; every `(process, domain)` backed by an observation. |
| `todo:417d6f3aef8a732ce6efce38eea35303` | Stage 0 hotfix: provenance + deferral, process-bound `SniDnsCache`, source-port-scoped pending upgrade, `PORT_PIDS` UDP-only, `AttrCache` hardening. Notes carry the proven cases, file:line pointers, tests, and the `no DB writes` constraint. |

The Stage 0 task notes were later extended with the 12:05 `brave`/`synara` reproduction and the `AttrCache` hardening changes. The full evidence is in this file and the companion.

**Base and artifacts.** This branch starts at `83d0499` (`main`) and is a temporary documentation branch; it can be deleted after review without affecting `main`. The investigation used `/tmp/opencode/netkeep-investigation/` (`rules.json`, `rules_now.json`, `rules_live_2026-11-13.json`, `flows.json`, `journal.txt`, `parsed.json`, `mismatches.json`). Those files are not committed; the evidence tables reproduce every number cited here.

**Related reading:** `docs/process-attribution-races.md`, `docs/process-resolver.md`, `docs/decision-dialog-ux.md`, `docs/nfqueue-domain-inference.md`.
