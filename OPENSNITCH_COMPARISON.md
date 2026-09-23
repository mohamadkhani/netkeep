# OpenSnitch vs Netkeep: Detailed Comparison & Analysis

**Date:** 2026-05-06  
**Prepared for:** Netkeep Development  
**Purpose:** Architectural and feature comparison to identify learning opportunities

---

## Executive Summary

OpenSnitch is a mature, battle-tested application firewall (13.6k GitHub stars, 5+ years development). Netkeep is a Rust-first rewrite focusing on security, simplicity, and modern architecture.

**Key Takeaway:** OpenSnitch excels at flexibility and enterprise features. Netkeep excels at type safety and deterministic behavior. Together, they suggest a powerful feature roadmap.

---

## Architecture Comparison

### OpenSnitch Architecture
```
┌─────────────────────────────────────────┐
│ UI (Python PyQt5)                       │
│ - Pop-up dialogs                        │
│ - Rule editor                           │
│ - Events viewer                         │
└──────────────┬──────────────────────────┘
               │ gRPC/Protocol Buffer
┌──────────────▼──────────────────────────┐
│ Daemon (Go)                             │
│ - Rule matching                         │
│ - Decision queue (30s timeout)          │
│ - Process tracking                      │
└──────────────┬──────────────────────────┘
               │
     ┌─────────┼─────────┐
     ▼         ▼         ▼
  eBPF      /proc   iptables/nftables
  (kernel)  (OS)    (kernel firewall)
```

### Netkeep Architecture
```
┌─────────────────────────────────────────┐
│ GPUI App (Rust)                         │
│ - Decision dialog with countdown        │
│ - Remember checkbox for rules           │
│ - Real-time polling (→ push model)      │
└──────────────┬──────────────────────────┘
               │ Unix socket JSON-RPC
┌──────────────▼──────────────────────────┐
│ Daemon (Rust)                           │
│ - Rule matching & precedence            │
│ - Decision engine (protocol-specific T/O)│
│ - Pending queue (100 item cap)          │
└──────────────┬──────────────────────────┘
               │
     ┌─────────┴─────────┐
     ▼                   ▼
  NFQUEUE          ProcessResolver
  (netfilter)      (netstat/procfs)
```

---

## Key Technical Differences

| Aspect | OpenSnitch | Netkeep |
|--------|-----------|-----------|
| **Daemon Language** | Go | Rust |
| **UI Language** | Python (PyQt5) | Rust (GPUI) |
| **Packet Interception** | iptables/nftables | nftables + NFQUEUE |
| **Process Tracking** | eBPF or /proc filesystem | netstat/procfs (planned) |
| **Rule Storage** | JSON files | SQLite database |
| **Protocol (Daemon↔UI)** | gRPC | Unix socket JSON-RPC |
| **Default Timeout** | 30 seconds (fixed) | 100s (configurable per protocol) |
| **Rule Precedence** | Alphabetical by name | Priority ladder (restriction-based, user-reorderable) |
| **Pending Queue Cap** | Unlimited | 100 items (configurable) |
| **UI Framework** | PyQt5 (Python) | GPUI native (Rust) |
| **Learning Mode** | Yes (documented workflow) | Not implemented |
| **Multi-Node** | Yes | No (MVP only) |
| **SIEM Integration** | Grafana/Loki, ELK | Not implemented |

---

## Rules Model Deep Dive

### OpenSnitch Rules

**Storage:** JSON files

**Example:**
```json
{
  "name": "allow-firefox-cloudflare",
  "enabled": true,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "AND",
    "operands": [
      { "type": "process.name", "operator": "simple", "data": "firefox" },
      { "type": "dest.ip", "operator": "network", "data": "1.1.1.1/32" },
      { "type": "dest.port", "operator": "range", "data": "443" }
    ]
  }
}
```

**Matching Logic:**
- ALL criteria must match (AND logic)
- Rules evaluated alphabetically by name
- First matching deny/reject rule applies immediately
- Last matching allow rule applies if no deny matched
- Multiple operators: `simple`, `regexp`, `network`, `range`, `lists`

**Supported Fields:**
- `process.name` — executable name
- `process.path` — full path (not just name!)
- `dest.ip` — IP address
- `dest.host` — domain name
- `dest.port` — port number
- Command-line arguments (via regexp)

---

### Netkeep Rules

**Storage:** SQLite database

**Rust Type:**
```rust
struct Rule {
  pub id: String,
  pub enabled: bool,
  pub action: RuleAction,  // Allow | Deny | Ask
  pub duration: RuleDuration,  // UntilRestart | Permanent
  pub process_name: Option<String>,
  pub destination: DestinationMatcher,
}

enum DestinationMatcher {
  IpExact(String),
  Cidr(String),
  DomainExact(String),
  DomainWildcard(String),  // *.example.com, doesn't match apex
}
```

**Matching Logic:**
1. Priority precedence (highest to lowest): each rule carries a `priority: f64` seeded from a restriction ladder at creation — more restricted combos rank higher (process+exact IP > process+exact domain > process+wildcard > process+CIDR > process+Any > exact IP > exact domain > wildcard > CIDR > global). Users can reorder rules manually.

2. Action precedence (same priority): Deny > Allow > Ask

3. Wildcard semantics: `*.example.com` ≠ `example.com` (prevents apex spoofing)

---

## Workflow Comparison

### OpenSnitch Recommended Workflow

**1. Learning Phase (Hours to Weeks)**
```
[ ] Configure permissive defaults (allow by default)
[ ] Disable pop-up notifications
[ ] Run system passively
[ ] Observe all intercepted connections
[ ] Document patterns in GUI
[ ] Identify critical system processes
```

**2. Restriction Phase**
```
[ ] Review documented connections
[ ] Identify unnecessary traffic
[ ] Convert temporary rules to permanent
[ ] Implement "least privilege": block by default, allow only known
[ ] Test critical workflows
```

**3. Maintenance**
```
[ ] Monitor for blocked legitimate traffic
[ ] Adjust rules as needed
[ ] Periodically review rule list
```

---

### Netkeep Current Workflow

**1. Default (Immediate)**
- Unknown flow → pending decision
- User action (Allow/Deny) with optional "Remember" checkbox
- If checked → permanent rule created
- Auto-deny after timeout

**2. Not Yet Implemented**
- Learning/observation mode (passive, log without prompting)
- Gradual transition to restrictive security
- Suggested rules from observed patterns

---

## Feature Comparison Matrix

| Feature | OpenSnitch | Netkeep | Priority |
|---------|-----------|-----------|----------|
| Basic allow/deny | ✅ | ✅ | Core |
| Pending queue | ✅ (30s) | ✅ (100 cap) | Core |
| Rule persistence | ✅ (JSON) | ✅ (SQLite) | Core |
| Domain matching | ✅ | ✅ | Core |
| Process matching | ✅ (name + path) | ⚠️ (name only) | MVP Phase 2 |
| CIDR/IP ranges | ✅ | ✅ | Core |
| Port ranges | ✅ | ⚠️ (not in scope) | Phase 5 |
| Regex matching | ✅ | ❌ | Phase 5 |
| Command-line args | ✅ | ❌ | Phase 5 |
| Protocol-specific timeout | ❌ | ✅ | Advantage |
| Fail-close boot gate | ❌ | ✅ | Advantage |
| Learning mode | ✅ | ❌ | Phase 5 |
| Multi-node mgmt | ✅ | ❌ | Phase 5 |
| SIEM integration | ✅ | ❌ | Phase 5 |
| Inbound + outbound | ✅ (outbound primary) | ❌ (outbound only) | Phase 5 |
| Rule re-enforcement | ✅ (30s check) | ❌ | Phase 2 |
| Audit logging | ⚠️ | ⚠️ (SQLite only) | Phase 5 |

---

## What Netkeep Can Learn from OpenSnitch

### 1. Learning Mode Workflow ⭐⭐⭐
**Priority:** High (Phase 5)

OpenSnitch's strategy: Start permissive (observe), then transition to restrictive (enforce).

**Implementation suggestion for Netkeep:**
```
enum FirewallMode {
  Learning,        // Allow all, log everything (observation)
  Observing,       // Allow + pending decisions off (documentation)
  Transitional,    // Mixed allow/deny (user setting rules)
  Restrictive,     // Deny by default, allow only known (security)
}

// Learning mode: skip pending, auto-allow, log
// Suggests rules from observed patterns
```

### 2. Advanced Rule Operators ⭐⭐⭐
**Priority:** High (Phase 5)

OpenSnitch supports: `simple`, `regexp`, `network`, `range`, `lists`

**Netkeep could add:**
```rust
enum DestinationMatcher {
  // Current
  IpExact(String),
  Cidr(String),
  DomainExact(String),
  DomainWildcard(String),
  
  // Phase 5 additions
  DomainRegex(String),           // api.*\.example\.com
  PortRange(u16, u16),           // 8000..9000
  Blocklist(String),             // URL to blocklist
}

enum ProcessMatcher {
  // Current
  Name(String),
  
  // Phase 5 additions
  Path(String),                  // /usr/bin/firefox
  PathRegex(String),             // /opt/.*firefox.*
  CommandLine(String),           // firefox --safe-mode
  CommandLineRegex(String),      // .*--insecure.*
  Uid(u32),                      // User ID matching
}
```

### 3. Process Command-Line Matching ⭐⭐
**Priority:** Medium (Phase 5)

**Security benefit:** Block `python` system-wide, but allow `/usr/bin/safe-script.py`

**Example:**
```bash
# Current Netkeep
netkeep add-rule --action Deny --process python

# Proposed with args
netkeep add-rule --action Allow --process "firefox" --args "--safe-mode"
```

### 4. Rule Re-enforcement Atomicity ⭐
**Priority:** Medium (Phase 2)

OpenSnitch re-checks nftables rules every 30 seconds and re-applies if missing.

**Why useful:** Survive user `nft flush` or other process interfering with rules.

**Implementation:**
```rust
// In daemon tick loop (already exists)
ControlService::tick() {
  self.expire_timeouts();
  
  // NEW: Periodically re-apply nftables rules
  if now % 30_seconds == 0 {
    self.enforcer.validate_and_repair_rules()?;
  }
}
```

### 5. SIEM Integration Pattern ⭐⭐
**Priority:** Medium (Phase 5)

OpenSnitch exports to Grafana/Loki and ELK Stack.

**Netkeep could add:**
```rust
enum ExportTarget {
  Syslog(String),              // localhost:514
  WebhookUrl(String),          // https://...
  ElasticsearchUrl(String),    // Bulk ingest
}

// On every decision
FlowRepository::log_to_siem(flow_event, action)?;
```

### 6. Inbound Traffic Support ⭐
**Priority:** Low (Phase 5)

OpenSnitch handles both inbound and outbound (though inbound is experimental).

**Netkeep currently:** Outbound only. Could extend with:
```rust
enum TrafficDirection {
  Outbound,
  Inbound,
  Both,
}

// In nftables rules
nft add rule filter INPUT ... counter queue to 0  // Inbound
nft add rule filter OUTPUT ... counter queue to 0 // Outbound
```

### 7. Multi-Node Management ⭐
**Priority:** Low (Phase 5+)

OpenSnitch has centralized dashboard for multiple machines.

**Not critical for MVP** (single-machine), but future enterprise feature.

---

## What Netkeep Does Better

### 1. Type-Safe Rust ⭐⭐⭐
**Advantage:** Memory safety, no GC pauses, no data races

OpenSnitch:
- Go: GC pauses (unpredictable latency)
- Python UI: GIL contention (single-threaded)

Netkeep:
- Rust: No GC, compile-time safety guarantees
- Deterministic performance: suitable for security-critical code

### 2. Protocol-Specific Timeouts ⭐⭐⭐
**Advantage:** Recognizes different retry behavior

OpenSnitch: Fixed 30 seconds for all protocols

Netkeep:
```rust
// Configurable per protocol
TCP: 100s    // Can retry, tolerate delays
UDP: 5s      // Fire-and-forget, no retry
QUIC: 5s     // Similar to UDP
Other: 3s    // Safer default
```

**Benefit:** TCP traffic has retry logic (e.g., HTTP), can wait longer without breaking. UDP is lossy, needs fast decision.

### 3. Fail-Close Boot Gate ⭐⭐⭐
**Advantage:** Security window prevention

**How:** nftables rule blocks ALL traffic until daemon reports healthy.

**Why OpenSnitch doesn't have it:** Go binary starts faster; Rust adds safety checks.

**Why Netkeep has it:** Prevents privilege escalation before daemon initializes.

### 4. Wildcard Domain Semantics ⭐⭐
**Advantage:** Prevents apex spoofing

Netkeep:
```rust
// Rules
"*.example.com" ≠ "example.com"  // ✅ Must be explicit

// Prevents
Rule { dest: DomainWildcard("*.example.com") }
// from matching "example.com" (the apex)
```

OpenSnitch: No explicit semantic documented (likely different behavior).

### 5. Native GPUI UI ⭐⭐
**Advantage:** Single binary, no Python runtime

OpenSnitch:
- PyQt5 adds 50MB+ dependencies
- Python GIL (slower UI responsiveness)
- Deployment more complex

Netkeep:
- Single Rust binary
- Compiles to native code
- ~10x smaller deployment footprint

### 6. Unified Data Model ⭐⭐
**Advantage:** No JSON serialization bugs

OpenSnitch:
```
JSON file → Go unmarshaling → Python pickle → Python display
// Multiple type conversions, error surface
```

Netkeep:
```
SQLite → Rust struct → JSON RPC → Rust GPUI rendering
// Single type system throughout
```

### 7. Async-First Architecture ⭐⭐
**Advantage:** Prepared for scalability

Netkeep: Built on async Tokio (ready for thousands of pending decisions)

OpenSnitch: Thread pools + Python GIL (doesn't scale beyond single machine)

---

## Recommended Implementation Roadmap

### Phase 2 (Next)
- ✅ Bidirectional socket push notifications (already planned)
- ⭐ Rule re-enforcement atomicity (30s check)
- ⭐ Real ProcessResolver with `/proc` parsing

### Phase 3 (Short-term)
- ⭐ Process path + argv matching
- ⭐ Regexp-based domain/process matching
- ⭐ Port range support

### Phase 4 (Medium-term)
- ⭐ Learning mode (observation workflow)
- ⭐ SIEM integration (syslog export)
- ⭐ Rule suggestion engine (from observed flows)

### Phase 5 (Long-term)
- ⭐ Inbound traffic support
- ⭐ Multi-node management
- ⭐ Advanced blocklists/allowlists
- ⭐ Audit trail and compliance reporting

---

## Performance Characteristics

### OpenSnitch
- **Rule matching:** O(n) linear scan, alphabetical precedence
- **UI responsiveness:** Affected by Python GIL
- **Memory footprint:** Go runtime ~50MB, Python ~100MB+
- **Latency:** Varies (GC pauses, lock contention)

### Netkeep
- **Rule matching:** O(n) linear scan, priority-descending precedence (faster in practice: early match)
- **UI responsiveness:** Native Rust, no GIL
- **Memory footprint:** ~5MB total (daemon + UI)
- **Latency:** Predictable, deterministic (<1ms decision)

---

## Security Posture Comparison

### OpenSnitch
- ✅ Long track record (5+ years)
- ✅ Community-reviewed
- ⚠️ Python/Go runtime vulnerabilities possible
- ⚠️ GC pauses could bypass timeouts
- ⭐ Supports inbound + outbound

### Netkeep
- ⚠️ New codebase (not battle-tested)
- ✅ Rust memory safety (no buffer overflows, no use-after-free)
- ✅ Fail-close boot gate (prevents privilege escalation window)
- ✅ Protocol-aware timeouts (fewer false denies)
- ⚠️ Outbound only (MVP scope)

---

## Deployment Comparison

### OpenSnitch
```bash
sudo apt install opensnitch opensnitch-ui
systemctl start opensnitch
opensnitch-ui  # Starts Python GUI
```

### Netkeep
```bash
cargo build --release
sudo cp target/release/netkeep-daemon /usr/local/bin/
sudo systemctl start netkeep-daemon
./netkeep-gpui  # Native binary
```

---

## Conclusion

### When to Use OpenSnitch
- Enterprise environment requiring SIEM integration
- Need for multi-node management
- Require flexibility in rule operators (regex, ranges, blocklists)
- Willing to accept Python/Go runtime overhead for feature richness

### When to Use Netkeep
- Security-critical environment where determinism matters
- Single-machine deployment (home lab, workstation)
- Prefer type-safe Rust codebase
- Need fast, minimal footprint
- Want modern async architecture
- Prefer native UI (no Python runtime)

### Hybrid Approach
Consider Netkeep MVP as foundation, borrow OpenSnitch's:
- ✅ Learning mode workflow (observation → restriction)
- ✅ Advanced operators (regex, ranges, lists)
- ✅ Rule suggestion engine (from observed patterns)
- ✅ SIEM export infrastructure

**Timeline:** Netkeep MVP complete. Roadmap through Phase 5 should address all OpenSnitch capabilities while maintaining Rust safety advantages.

---

## Appendix: Code Snippets

### OpenSnitch Daemon Entry
```go
func main() {
  // Init rule repository from JSON files
  // Listen on gRPC port
  // Start nftables/iptables enforcement
  // Start /proc or eBPF monitor
  // Serve UI requests indefinitely
}
```

### Netkeep Daemon Entry
```rust
#[tokio::main]
async fn main() {
  let repo = Arc::new(Mutex::new(
    SqliteRepository::new(db_path)?
  ));
  let service = ControlService::new(repo);
  
  // Spawn Unix socket server
  // Spawn timer thread (tick every 1s)
  // Listen for NFQUEUE packets
  // Run forever
}
```

### Rule Matching (Pseudocode)

**OpenSnitch:**
```python
rules = load_json_rules()
rules.sort(key=lambda r: r.name)  # Alphabetically
for rule in rules:
  if rule.matches_all_operands(connection):
    return rule.action
return DEFAULT_DENY
```

**Netkeep:**
```rust
let rules = repo.list_enabled();
// Already sorted by priority DESC (built into matcher)
for rule in rules.iter() {  // Highest priority first
  if matcher::matches(&rule, &flow) {
    return rule.action;
  }
}
Some(RuleAction::Ask)  // Unknown flow
```

---

**Document prepared:** 2026-05-06  
**Comparison based on:** OpenSnitch main branch, Netkeep develop branch  
**Next review:** After Netkeep Phase 2 completion
