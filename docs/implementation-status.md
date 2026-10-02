# Netkeep Current Implementation State

**Status snapshot** — phases 0–4 complete, 247 tests passing (`just test`), CI green on main.
**Open work is tracked in GitHub Issues, not here:**
https://github.com/mohamadkhani/netkeep/issues (board: Backlog → Ready → In Progress → In Review → Done).

**History:** the detailed session journal and bug-fix write-ups that used to live in this
file were moved to git history (`git log -p -- docs/implementation-status.md`). New fix
write-ups belong in the PR description that fixes them.

**Last Updated:** 2026-10-02

## Phase Summary

| Phase | Scope | State |
|---|---|---|
| 0 | Foundation (workspace, toolchain, CI runner, core-types) | Done |
| 1 | Policy + decision core (matching, precedence, pending timeout machine) | Done |
| 2 | Enforcement (nftables + NFQUEUE, SNI/HTTP/DNS domain inference, process attribution) | Done; kernel integration tests tracked in #3 |
| 3 | Persistence + CLI (SQLite repos, Unix-socket JSON-RPC, CLI) | Done; schema migrations via `PRAGMA user_version` runner in `state-store` |
| 4 | GPUI interface (decision dialog, settings, tray, monitor mode) | Done |
| 5 | Packaging & hardening (systemd user unit, boot gate, eBPF DNS forwarder shipped) | In progress → milestone "Phase 5" |
| 7 | Web UI | Not started → milestone "Phase 7" |

Key shipped subsystems beyond the original phases: routed relay with per-egress DNS,
proxy support (SOCKS5 / HTTP CONNECT / Shadowsocks / TUN / device) across daemon + CLI +
settings UI, eBPF DNS tracker + DNS forwarder (`docs/dns-forwarder.md`), ksni tray with
Wayland focus fix (`docs/tray-window-focus-wayland.md`).

## Critical Data Structures

### Rule

```rust
struct Rule {
    pub id: String,                    // Unique identifier (user-set or UUID)
    pub enabled: bool,
    pub action: RuleAction,            // Allow | Deny | Ask | Route
    pub duration: RuleDuration,        // UntilRestart | Permanent
    pub process_name: Option<String>,  // Process name matcher (e.g., "firefox", "ssh")
    pub destination: DestinationMatcher, // IpExact | Cidr | DomainExact | DomainWildcard | Any
    pub egress_id: Option<String>,     // References Egress entity (Route action)
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
    pub destination_domain: Option<String>, // SNI / HTTP Host (authoritative) or DNS cache
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

`process_exe` is added via migration (`ALTER TABLE rules ADD COLUMN process_exe TEXT NULL`)
on startup for existing databases. It enables exe-path rule matching which is immune to
`/proc/<pid>/comm` 15-char truncation and basename collisions.

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

Plus `egresses`, `egress_targets`, `egress_dns_servers`, `proxies` tables (see
`crates/state-store`). Schema versioning: `PRAGMA user_version` + ordered
idempotent migrations (`MIGRATIONS` in `crates/state-store/src/lib.rs`); fresh
DBs are stamped at `CURRENT_VERSION` directly, legacy DBs get guarded
`ALTER TABLE` backfills, and the priority ladder backfill stays a one-time
data migration at version 2.

## Test Coverage

~247 tests across the workspace (`just test`). Coverage concentrated on: rule matching and
precedence (policy-engine), pending lifecycle/dedup/timeouts (decision-engine),
`/proc` + netlink + `ss` attribution and domain resolution (flow-classifier), packet
parsing + SNI/HTTP host extraction + NFQUEUE error recovery (enforcer), CRUD + persistence
(state-store), RPC handlers (control-service), CLI parsing, SOCKS5/HTTP CONNECT protocol
encoding and transparent proxy (proxy-client), plus daemon/emulator route-target e2e tests.

## CLI Commands

All commands support `--json` flag for structured output.

```bash
netkeep add-rule --action Allow --duration Permanent --process firefox 8.8.8.8
netkeep add-rule --action Deny 1.1.1.1/24
netkeep list-rules --json
netkeep delete-rule my-rule-id

netkeep list-pendings
netkeep resolve-pending pending-123 allow

netkeep health
netkeep show-config --json   # Detailed config + timeouts
netkeep unlock               # Console-only recovery
```

## Environment Variables

Currently used by the daemon (see also `apps/daemon/src/main.rs`):

- `NETKEEP_SOCKET_PATH` — Unix socket path (default `/tmp/netkeep.sock`)
- `NETKEEP_DB_PATH` — SQLite DB location (default `~/.config/netkeep/netkeep.db`; directory created automatically)
- `NETKEEP_NFQUEUE` — NFQUEUE number when packet interception enabled (optional)
- `NETKEEP_DNS_FORWARDER` — set to `1` to enable the egress-aware DNS forwarder (`docs/dns-forwarder.md`)
- `NETKEEP_DEFAULT_TIMEOUT_SECS` — Default pending timeout (default 100)
- `NETKEEP_TCP_TIMEOUT_SECS`, `NETKEEP_UDP_TIMEOUT_SECS`, `NETKEEP_QUIC_TIMEOUT_SECS`, `NETKEEP_OTHER_TIMEOUT_SECS` — protocol overrides (fall back to default timeout when unset)
- `NETKEEP_DEVICE_ROUTE_FALLBACK` — set to `1`/`true`/`yes` to allow routed device path to fall back to plain connect after failure (diagnostics only; weakens strict routing)

## Build and Run

```bash
just check           # fast workspace compile check
just test            # unit + integration tests
just ci              # fmt + clippy (-D warnings) + tests
just e2e             # black-box suite against a running daemon

# Daemon (requires root)
NETKEEP_DB_PATH=/var/lib/netkeep/db.sqlite NETKEEP_NFQUEUE=0 sudo ./target/debug/netkeep-daemon

# GPUI app
netkeep-gpui                         # monitor mode (default)
netkeep-gpui --pending-id <id>       # single decision mode
```

eBPF crates need: `rustup toolchain install nightly --component rust-src`,
`rustup target add bpfel-unknown-none --toolchain nightly`, `cargo install bpf-linker`,
then `cargo xtask build-ebpf-release` before `cargo build --workspace`.
