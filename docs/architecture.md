# LogiGuard Architecture

Network flow authorization system for Linux: intercept unknown flows, prompt user, enforce rules.

**Repository:** https://github.com/mohammadreza-khani/logiguard  
**Language:** Rust  
**Platforms:** Linux desktop first  
**Status:** Phase 4 (GPUI UI, 93 tests passing)

## System Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    User Desktop                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ logiguard-gpui (GPUI app)                              │  │
│  │  - Displays pending decisions                          │  │
│  │  - Countdown timer with auto-deny                     │  │
│  │  - Allow/Deny buttons with scope toggle               │  │
│  │  - Segmented pill: THIS SESSION / PERMANENTLY         │  │
│  └────────────────────────────────────────────────────────┘  │
│             ▲                                                 │
│             │ Unix socket JSON RPC                           │
│             │ /tmp/logiguard.sock                            │
│             ▼                                                 │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ logiguard-cli (terminal CLI)                           │  │
│  │  - add-rule, list-rules, delete-rule                  │  │
│  │  - list-pendings, resolve-pending                     │  │
│  │  - health, unlock (console-only)                      │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
             ▲
             │ systemd user/system daemon
             │
┌────────────────────────────────────────────────────────────────┐
│ Root Context (logiguardd daemon)                               │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ ControlService                                           │ │
│  │  - Unix socket server                                   │ │
│  │  - Request routing (AddRule, ListPending, etc.)        │ │
│  │  - Response formatting                                 │ │
│  │  - Health/config endpoint                              │ │
│  └──────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ PacketProcessor (NFQUEUE)                               │ │
│  │  - Receives packets from nftables                       │ │
│  │  - Classifies flows (process, domain, IP)              │ │
│  │  - Queries decision engine                             │ │
│  │  - Issues verdicts (allow/deny/pending)                │ │
│  └──────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ DecisionEngine                                           │ │
│  │  - Rule matching & precedence                          │ │
│  │  - Pending queue management                            │ │
│  │  - Timeout state machine                               │ │
│  │  - Pending decision creation                           │ │
│  └──────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ StateStore (SQLite)                                     │ │
│  │  - Rules persistence                                   │ │
│  │  - Flow history                                        │ │
│  │  - Pending decisions                                   │ │
│  │  - Migrations & journaling                             │ │
│  └──────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ nftables integration                                     │ │
│  │  - Kernel policy programming (QUEUE target)           │ │
│  │  - Verdict feedback to kernel                          │ │
│  │  - Fail-close gate (block on daemon unhealthy)        │ │
│  └──────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

## Workspace Structure

```
logiguard/
├── crates/
│   ├── core-types/            # Shared types (Rule, Flow, etc.)
│   ├── policy-engine/         # Rule matching & precedence
│   ├── decision-engine/       # Pending queue + timeout state
│   ├── flow-classifier/       # Process & domain attribution
│   ├── enforcer/              # nftables + NFQUEUE integration
│   ├── state-store/           # SQLite repositories
│   └── control-api/           # Unix socket protocol schema
├── apps/
│   ├── daemon/                # logiguardd (root systemd service)
│   ├── cli/                   # logiguard-cli (operator interface)
│   └── gpui/                  # logiguard-gpui (GPUI decision UI)
├── design/                    # HTML design reference files
├── docs/                      # Architecture and API documentation
├── Cargo.toml                 # Workspace root
├── rust-toolchain.toml        # Pinned Rust version + components
├── justfile                   # Task runner
└── develop.md                 # This implementation guide
```

## Core Crates

### `core-types`

Shared data models, no dependencies on other crates.

**Key Types:**
- `Rule` — policy rule with action, scope, duration
- `FlowContext` — network flow metadata (process, IPs, domain, protocol, direction, port)
- `PendingDecision` — user decision queue item
- `FlowEvent` — audit log entry
- `RuleAction` — {Allow, Deny, Ask}
- `RuleDuration` — {UntilRestart, Permanent}
- `DestinationMatcher` — {IpExact, Cidr, DomainExact, DomainWildcard}
- `TransportProtocol` — {Tcp, Udp, Quic, Other}

**Serialization:** All types derive `Serialize`/`Deserialize` for JSON RPC.

### `policy-engine`

Rule matching and precedence logic.

**Key Functions:**
- `resolve(rules: &[Rule], flow: &FlowContext) -> Option<RuleAction>` — find best matching rule
- Specificity ranking: process + exact IP > process + wildcard > exact IP > wildcard > global
- Action precedence: Deny > Allow > Ask (when specificity tied)
- Wildcard matching: `*.example.com` matches subdomains, not apex

**Traits:**
- `RuleRepository` — mock-friendly interface for rule lookups

**Tests:** Exact match, CIDR, domain, wildcard, precedence, disabled rules.

### `decision-engine`

Pending queue and timeout state machine.

**Key Behaviors:**
- Unknown flow (no rule match) → create `PendingDecision`
- Pending decision lifetime: created → user resolves (Allow/Deny) OR timeout expires → auto-deny
- Queue cap: 100 items (configurable)
- Timeout: default 100s (configurable per protocol: TCP/UDP/QUIC/Other)
- UntilRestart rules: expire on daemon startup

**Traits:**
- `Clock` — deterministic time (system clock in prod, fake in tests)
- `PendingRepository` — persistence interface

**Functions:**
- `register_unknown_flow()` → pending ID
- `resolve_pending()` → apply user decision
- `expire_timeouts()` → auto-deny expired pendings
- `purge_session_rules()` → delete UntilRestart rules

**Tests:** Unknown flow, timeout, queue overflow, user resolve, protocol-specific behavior.

### `flow-classifier`

Process and domain attribution.

**Key Functions:**
- Determine source process (via netstat/procfs lookup)
- Determine destination domain (via DNS or SNI hints)
- Handle DNS/SNI conflict (fallback to IP-only)
- QUIC best-effort domain inference

**Traits:**
- `ProcessResolver` — lookup process by src IP:port
- `DnsResolver` — lookup domain by IP (from DNS cache)
- `SniResolver` — lookup domain from SNI
- `DeviceLabelResolver` — attach device labels (e.g., "vpn-work")

**Implementation:** Currently uses fake resolvers for testing. Real implementations need OS integration (read `/proc/net/tcp`, extract SNI from QUIC Initial packet).

### `enforcer`

nftables programming and NFQUEUE packet handling.

**Key Components:**
- `NftablesBootstrap` trait — program nftables rules (SystemNftablesBootstrap shells to `nft`)
- `PacketProcessor` — parse NFQUEUE packets, classify flows, query decision engine
- `parse_raw_packet()` — IPv4/IPv6, TCP/UDP, QUIC detection from raw bytes
- `NfqueueProcessor` — accepts packets from `nfq` crate, feeds to PacketProcessor

**Data Flow:**
1. nftables kernel module sends packet to NFQUEUE
2. `NfqueueProcessor` reads from queue
3. `PacketProcessor` parses, classifies, queries decision engine
4. `VerdictSink` writes verdict back to kernel (accept/drop)

**Tests:** Packet parsing, verdict paths, nftables programming (with FakeBootstrap).

### `state-store`

SQLite-backed persistence.

**Key Repositories:**
- `RuleRepository` — CRUD rules, `purge_session_rules()` on startup
- `FlowRepository` — append flow events, list with limit
- `PendingRepository` — create/delete pending decisions, restore on startup

**Schema:**
- `rules` table — id, enabled, action, duration, process_name, destination, created_at, updated_at
- `flow_events` table — id, process_name, device_label, destination_ip, destination_domain, protocol, state, timestamp_secs
- `pending_decisions` table — id, flow_id, created_at, deadline_at, default_action

**Migrations:** Auto-run on startup via schema versioning.

### `control-api`

Unix socket protocol schema (JSON-RPC style).

**Requests:**
```
AddRule(Rule)
ListRules
DeleteRule { id }
ListPending
ListFlows { limit }
RegisterUnknownFlow { flow, now_secs }
AwaitPendingDecision { pending_id }
ResolvePending { pending_id, action }
Health
Unlock
```

**Responses:**
```
Ok
RuleList(Vec<Rule>)
PendingList(Vec<PendingDecision>)
FlowList(Vec<FlowEvent>)
PendingCreated { pending_id, created_at, deadline_at, protocol }
ImmediateVerdict { action }
PendingStillWaiting { pending_id }
PendingResolved { action }
Health { ready, fail_close_active, timeout_secs, ... }
Unlocked
Error(String)
```

**Transport:** JSON lines (newline-delimited JSON) over Unix socket.

## Data Flow

### Rule Creation (User → Daemon)

```
User (CLI/GPUI)
  │ add-rule / AddRule request
  ├─→ ControlService (Unix socket)
        │ validate request
        ├─→ RuleRepository::insert()
              │ write to SQLite
              └─ return Ok
        └─→ send ControlResponse::Ok
  └─ return result
```

### Unknown Flow Decision

```
Kernel packet → nftables QUEUE
    │ (to userspace)
    ├─→ NfqueueProcessor
          │ parse packet bytes
          ├─→ PacketProcessor::process()
                │ classify (flow context)
                ├─→ Classifier::classify() (DnsResolver, ProcessResolver)
                ├─→ DecisionEngine::decide()
                      │ lookup rule match (RuleRepository)
                      ├─→ RuleAction::Allow → VerdictSink::accept()
                      ├─→ RuleAction::Deny → VerdictSink::drop()
                      └─→ RuleAction::Ask → PendingRepository::insert()
                                             FlowRepository::append()
                └─→ VerdictSink (send verdict back to kernel)
```

### Pending Decision Resolution

```
GPUI polls ListPending every 1s
  │
  └─→ ControlService::list_pending()
        │ query PendingRepository
        ├─→ DecisionEngine::expire_timeouts() (auto-deny expired)
        └─→ return PendingList
            │
            └─→ GPUI renders decision cards with countdown
                  │ User clicks Allow or Deny
                  └─→ ControlRequest::ResolvePending { pending_id, action }
                        │
                        └─→ ControlService::resolve_pending()
                              │ update PendingRepository
                              │ if scope == PERMANENTLY: add permanent rule
                              └─→ return PendingResolved { action }
```

## Testing Strategy

**Non-negotiable principle:** All logic testable without OS dependencies.

### Trait-Based Abstraction

Every system effect behind a trait:

- `RuleRepository` — mock with Vec<Rule>
- `FlowRepository` — mock with Vec<FlowEvent>
- `PendingRepository` — mock with HashMap<id, PendingDecision>
- `Clock` — mock with FakeClock (step time manually)
- `ProcessResolver` — mock with FakeProcessResolver
- `DnsResolver` — mock with fake lookups
- `NftablesBootstrap` — FakeBootstrap (with success/failure modes)
- `VerdictSink` — FakeVerdictSink (capture verdicts for assertions)

### Unit Test Coverage

**policy-engine:** 10+ tests (matching, precedence, disabled)  
**decision-engine:** 8+ tests (pending lifecycle, timeout, queue overflow)  
**flow-classifier:** 7+ tests (process attribution, domain inference, conflicts)  
**enforcer:** 8+ tests (packet parsing, verdict paths, nftables programming)  
**state-store:** 8+ tests (CRUD, persistence, migrations)  
**control-api:** 5+ tests (request validation)

**Current:** 93 tests passing.

### Integration Tests

Planned (Phase 2 onward):
- Flow with allow rule → passes
- Flow with deny rule → blocked
- Unknown flow → pending, user approves → passes
- Unknown flow → timeout → denied
- TCP pending flow before deadline → passes
- UDP pending flow timeout → denied
- Rule creation from decision → persists
- Restart with permanent rule → rule survives
- Boot gate → blocks traffic until daemon ready
- Queue overflow → default denies

## Key Design Decisions

1. **Fail-close:** Default deny on any decision engine error. Traffic blocked until daemon recovers.

2. **Wildcard semantics:** `*.example.com` does NOT match `example.com`. Apex requires explicit rule.

3. **DNS/SNI conflict:** Discard domain inference. Treat as IP-only. Prevents spoofing.

4. **Protocol-specific timeouts:** Different defaults for TCP (may retry) vs UDP (fire-and-forget).

5. **UntilRestart expiry:** Automatic cleanup on daemon startup. Prevents leaking session rules across boots.

6. **Permanent rule on scope toggle:** User decision + "PERMANENTLY" scope → new Permanent rule with inferred destination. Applies to both Allow and Deny.

7. **SQLite for state:** ACID transactions, journaling, simple schema. No external DB dependency.

8. **Unix socket + JSON:** Local IPC, no network exposure. Simple text protocol for debugging.

## Systemd Integration

**Daemon unit file** (planned):
```ini
[Unit]
Description=LogiGuard Network Authorization Daemon
Before=network.target

[Service]
Type=simple
ExecStart=/usr/bin/logiguardd
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

**Boot Gate:** nftables rules block all traffic until daemon signals readiness (health check).

## Environment Variables

- `LOGIGUARD_DB_PATH` — SQLite database file (default: `/var/lib/logiguard/db.sqlite`)
- `LOGIGUARD_NFQUEUE` — NFQUEUE number to listen on (default: 0)
- `LOGIGUARD_DEFAULT_TIMEOUT` — default pending timeout in seconds (default: 100)
- `LOGIGUARD_TCP_TIMEOUT` — TCP-specific timeout (default: 100)
- `LOGIGUARD_UDP_TIMEOUT` — UDP-specific timeout (default: 5)
- `LOGIGUARD_QUIC_TIMEOUT` — QUIC-specific timeout (default: 5)
- `LOGIGUARD_OTHER_TIMEOUT` — Other protocols timeout (default: 3)

## Recovery

**Fail-close boot gate:** nftables rule blocks all traffic until daemon health endpoint returns ready=true.

**Physical console unlock:** `logiguard unlock` command checks:
1. Peer credential (SO_PEERCRED)
2. Peer process stdin is /dev/console (from /proc/<pid>/fd/0)
3. If both check, tear down nftables policy

Prevents remote unlock attempts.

## Performance Characteristics

- **Rule matching:** O(n) linear scan (n=rules). For <100 rules, acceptable.
- **Pending queue:** O(1) insert/lookup (HashMap-backed). Cap at 100 to bound memory.
- **Timeout expiry:** O(m) scan (m=pending). Called every 1s, max 100 pendings = fast.
- **Packet processing:** O(n) rule lookup per packet. Expect <100 µs per verdict.
- **SQLite writes:** Async journaling. Should not block packet processing.

## Future Enhancements (Out of MVP Scope)

- Real ProcessResolver (netstat, /proc/net integration)
- SNI extraction from QUIC Initial packets
- DNS query interception (collect domain hints)
- Device routing targets (route to specific TUN/VPN)
- Rule templates and groups
- Web UI (phase 5)
- Integration with systemd user services
- Config file support (TOML/YAML)
- Rate limiting / anomaly detection
- Audit logging (syslog integration)
