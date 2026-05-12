# LogiGuard Testing Strategy

## Principle

Every unit is testable in isolation. All OS/system effects behind traits. No rule logic coupled to netfilter code.

## Testability Traits (Dependency Injection)

| Trait | Purpose | Fake impl |
|---|---|---|
| `PacketSource` | NFQUEUE packet ingestion | in-memory channel |
| `VerdictSink` | Kernel verdict write | `FakeVerdictSink` |
| `RuleRepository` | Rule CRUD | Vec<Rule> |
| `FlowRepository` | Flow event append/list | Vec<FlowEvent> |
| `PendingRepository` | Pending decisions | HashMap<id, PendingDecision> |
| `Clock` | Time source | `FakeClock` (step manually) |
| `Notifier` | UI notification push | no-op |
| `ProcessResolver` | Process lookup via /proc | `FakeProcessResolver` |
| `DnsSniResolver` | Domain inference | fake lookups |
| `NftablesBootstrap` | nftables programming | `FakeBootstrap` (success/fail modes) |

## Unit Test Matrix

### `policy-engine`
- [x] exact IP match
- [x] CIDR match positive/negative cases
- [x] exact domain match
- [x] wildcard subdomain match
- [x] wildcard does not match apex
- [x] process + destination combined match
- [x] precedence: specific beats general
- [x] action precedence: deny beats allow for same specificity
- [x] tie-break: equal specificity + equal action rank → greater `rule.id` wins
- [x] disabled rule ignored
- [x] invalid rule rejected by validator
- [x] **unknown-process + specific destination** (`IpExact`/`DomainExact`) → rule matches (proc-attribution race tolerance)
- [x] **unknown-process safety negatives:** wildcard / `Any` / CIDR rules do **not** apply when the flow's process is unknown
- [x] known-process *mismatch* (different name) still does not match a specific rule

### `decision-engine`
- [x] unknown flow creates pending decision
- [x] duplicate flow (retransmit / domain-inference variance) returns existing pending
- [x] different destination port creates separate pending
- [x] resolve cleans up flow dedup index (same flow can be re-prompted after resolve)
- [x] expire cleans up flow dedup index (same flow can be re-prompted after timeout)
- [x] **unknown → named** retransmit upgrades the existing pending (one dialog with the real process name, not two)
- [x] **named → unknown** retransmit reuses the existing pending (no new dialog)
- [x] distinct *known* process names to the same destination create separate pendings (chrome vs firefox)
- [x] pending decision resolved by user allow
- [x] pending decision resolved by user deny
- [x] pending timeout → auto-deny at 100s default
- [x] custom timeout respected
- [x] queue cap at 100 enforced
- [x] queue overflow default → deny new flow
- [x] overflow policy configurable
- [x] until-restart decision expires on restart
- [ ] permanent decision persists
- [x] protocol-specific pending behavior (TCP vs UDP/QUIC) follows configured policy
- [x] pending countdown/deadline metadata surfaced for UI/CLI

### `flow-classifier`
- [x] host process attribution success
- [x] host process attribution missing fallback behavior
- [x] DNS-derived domain association positive
- [x] SNI-derived domain association positive
- [x] DNS/SNI conflict → IP-only classification
- [x] QUIC best-effort domain inference fallback to IP/CIDR
- [x] gateway flow device label attachment
- [x] `/proc/net/tcp` IPv4/IPv6 parsing, port-only UDP wildcard fallback, IPv6 word byte order
- [x] **`ProcProcessResolver` cache:** cache hit short-circuits `/proc` reads; cache misses on different port or protocol; expired entries are not served

### `enforcer`
- [x] nftables programming success path (SystemNftablesBootstrap + FakeBootstrap)
- [x] nftables apply failure handled fail-close (FakeBootstrap fail=true)
- [x] NFQUEUE message parsing valid packet (parse_raw_packet IPv4/TCP/UDP)
- [x] invalid queue packet safely denied (malformed payload returns None → Drop)
- [x] verdict commit allow path (PacketProcessor allow test)
- [x] verdict commit deny path (PacketProcessor deny test)
- [x] SNI extraction from TLS ClientHello
- [x] non-TLS payload ignored gracefully
- [x] loopback detection including IPv4-mapped `::ffff:127.x.x.x`
- [ ] daemon-not-ready blocks traffic (boot gate)

### `state-store`
- [ ] migration bootstrap on empty DB
- [x] rule insert/read/update/delete
- [x] flow event append/read
- [x] pending decision persistence
- [ ] transaction rollback on failure
- [ ] concurrent access behavior

### `control-api` and `cli`
- [ ] local socket auth/permission checks
- [x] add/list/delete rules command flow
- [x] resolve pending decision command flow
- [x] health status command output contract
- [ ] malformed request handling

### Recovery / fail-close
- [ ] boot blocks network until daemon healthy
- [ ] daemon crash keeps fail-close policy
- [x] physical-console unlock command path
- [x] unlock denied from non-console context

## Integration Test Matrix

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

## CI Quality Gates

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Coverage threshold:
  - policy and decision crates: ≥ 95%
  - rest of workspace: ≥ 85%
