# Process Resolver: Mapping Network Packets to Processes

This document explains how LogiGuard identifies which process owns an intercepted network connection, using the Linux `/proc` filesystem and optional system tools (`ss`, package managers).

> **Adjacent reading.** Race interactions between this resolver, the decision engine, and the policy engine — and the three layers of defense that absorb them — are in [`docs/process-attribution-races.md`](process-attribution-races.md). Read that doc *too* if you are touching the resolver and the failure modes are not just an isolated parse bug.

---

## The Problem

When a packet arrives at NFQUEUE, you have:
- Source IP and port (e.g. `192.168.1.5:54321`)
- Destination IP and port
- Protocol (TCP/UDP)

You do **not** have the process name. The kernel knows which process opened the socket, but NFQUEUE does not expose it. To show "Allow **firefox** → api.example.com?" in the dialog, you need to resolve the socket back to a process.

---

## The Lookup Chain

```
(src_ip, src_port, protocol)
        │
        ▼
┌────────────────────────────────────────────────┐
│  per-socket cache  (60 s TTL, 4096 entries)   │
│  hit → return cached ProcessInfo              │
└──────────────────────┬─────────────────────────┘
                       │ miss
                       ▼
eBPF socket tracker (sock_tracker.rs)
  BPF map lookup by (src_ip, src_port, protocol)
  PID captured at socket creation (TCP SYN_SENT) or
  send time (udp_sendmsg) — before NFQUEUE delivery
  → returns (pid, uid) with zero TOCTOU race
        │
        │ miss (tracker not loaded, old kernel, etc.)
        ▼
SOCK_DIAG netlink (sock_diag.rs)
  inet_diag by (src_ip, src_port) — kernel socket table
  dual-family query (AF_INET + AF_INET6) for mapped sockets
  UDP wildcard retry (INADDR_ANY) for wildcard-bound sockets
  returns inode + uid in one round-trip (no /proc race)
        │
        │ miss → fallback
        ▼
/proc/net/{tcp,tcp6,udp,udp6}
  find row where local_address matches
  retry [0, 5, 15, 40] ms — TOCTOU with kernel publishing
        │
        └── inode + uid
                │
                ▼
        /proc/*/fd/*
          scan symlinks for socket:[inode]
          UID-filtered first pass, full scan fallback
          retry [0, 3, 8, 20] ms — fork/exec fd-visibility gap
                │
                └── pid
                        │
                        ▼
                /proc/<pid>/exe  (symlink → full binary path)
                /proc/<pid>/comm (fallback — kernel truncates to 15 chars)
                for "electron"/"AppRun" names:
                  APPIMAGE env var → strip version suffix (AppImage installs)
                  exe parent directory (e.g. /opt/cursor/electron → "cursor")
                  parent-process exe basename (filtered, non-generic only)
                for single-char or shell wrapper names:
                  parent-process exe basename
                        │
                        ▼
                package manager lookup (exe path)
                  pacman -Qo <exe>     (Arch Linux — current)
                  dpkg -S <exe>        (Debian/Ubuntu — planned)
                  rpm -qf <exe>        (RHEL/Fedora/openSUSE — planned)
                  apk info --who-owns  (Alpine — planned)
                  → app_name (e.g. "cursor-bin") stored in ProcessInfo
                  cached per exe-path in pacman_cache
                        │
                        ▼
         if /proc miss: ss fallback
           ss -Hnp [-t|-u] src :<port>
           extract pid= from users field
           re-enter from /proc/<pid>/exe above
                        │
                        ▼
            insert ProcessInfo into per-socket cache
```

---

## Step 0: eBPF Socket Tracker (instant PID — zero TOCTOU)

The eBPF socket tracker hooks into kernel tracepoints and kprobes to capture the PID at the exact moment a socket is created or a packet is sent — **before** NFQUEUE delivers the packet to userspace. This eliminates the TOCTOU race entirely.

### How it works

| Hook | Type | Trigger | What it captures |
|---|---|---|---|
| `sock:inet_sock_set_state` | tracepoint | TCP enters `SYN_SENT` | PID, UID, src_ip, src_port |
| `udp_sendmsg` | kprobe | Every UDP send | PID, UID, src_ip, src_port |
| `udp_lib_unhash` | kprobe | UDP socket close | Removes stale map entry |

The eBPF program stores `(src_ip, src_port, protocol) → (pid, uid, timestamp_ns)` in a BPF `HashMap` (`SOCK_EVENTS`, 16384 entries). IPv4 addresses are normalized to IPv4-mapped IPv6 (`::ffff:a.b.c.d`) in the key.

### Userspace loader

`dns_tracker::SockTracker` (in `crates/dns-tracker/src/sock_tracker.rs`) loads the BPF ELF, attaches the three programs, and exposes `lookup_pid(src_ip, src_port, protocol) → Option<TrackedProcess>`. It implements the `flow_classifier::SocketTracker` trait for dependency inversion.

### Integration

`ProcProcessResolver::find_pid()` checks the eBPF map **first** (Step 0). If it returns a PID, the entire `/proc` lookup chain is skipped. Metrics: `logiguard.proc.resolver.ebpf.hits` / `logiguard.proc.resolver.ebpf.misses`.

### Graceful degradation

If the eBPF program fails to load (missing `CAP_BPF`, old kernel, etc.), the daemon falls back to SOCK_DIAG + `/proc` + `ss` as before. The `SockTracker::load()` error is logged and the resolver is created without a tracker.

### Build

The eBPF bytecode is compiled separately via `cargo xtask build-ebpf-release` and embedded with `include_bytes!` at compile time. The build produces two BPF binaries: `dns-tracker-ebpf` (DNS snooping) and `sock-tracker-ebpf` (socket tracking).

---

## Step 1: Find the Socket Inode

### SOCK_DIAG netlink (primary — with dual-family + UDP wildcard)

`sock_diag::query_socket_inode` opens a `NETLINK_SOCK_DIAG` socket and sends an `InetRequest` with `SocketId` set to the flow's `(src_ip, src_port)` (destination fields wildcarded). The kernel returns `InetResponse` with `inode` and `uid` from its internal socket structures — the same data `ss` uses, but without a subprocess and without waiting for `/proc/net/tcp` to be updated.

**Dual-family query:** Many applications use `AF_INET6` sockets with `IPV6_V6ONLY=0` even for IPv4 destinations. The kernel records these in the IPv6 socket table as `::ffff:a.b.c.d`. Querying only `AF_INET` for an IPv4 source address misses these entries. The resolver now queries both `AF_INET` and `AF_INET6` for any source IP, returning the first match.

**UDP wildcard retry:** UDP sockets often bind to `0.0.0.0` (`INADDR_ANY`) rather than a specific source IP. If the specific-IP query returns nothing for UDP/QUIC, the resolver retries with the wildcard address in both address families.

On failure (permission denied, parse error, no matching socket), lookup falls through to `/proc/net` and then `ss`.

### `/proc/net` (fallback)

The kernel also exposes open sockets in `/proc/net/`:

| File | Covers |
|---|---|
| `/proc/net/tcp` | IPv4 TCP sockets |
| `/proc/net/tcp6` | IPv6 TCP sockets (also holds IPv4-mapped) |
| `/proc/net/udp` | IPv4 UDP sockets |
| `/proc/net/udp6` | IPv6 UDP sockets |

Each file has one row per open socket. The columns are:

```
sl  local_address  rem_address  st  tx_queue  rx_queue  tr  tm  uid  timeout  inode
 0: 0F02000A:1F90  00000000:0000  01  ...                              1000     0  99001
```

The `local_address` field is `ADDRESS:PORT` where both are hexadecimal. The `inode` column (index 9) uniquely identifies the socket across the whole system.

**Which files to read** depends on the packet's IP family and protocol:

| Protocol | IP family | Files checked |
|---|---|---|
| TCP | IPv4 | `/proc/net/tcp` |
| TCP | IPv6 | `/proc/net/tcp6`, then `/proc/net/tcp` |
| UDP/QUIC | IPv4 | `/proc/net/udp` |
| UDP/QUIC | IPv6 | `/proc/net/udp6`, then `/proc/net/udp` |

IPv6 files are checked first because an IPv4-mapped address (`::ffff:10.0.2.15`) can appear in either file.

---

## Address Encoding

### IPv4 (`/proc/net/tcp`)

The address is an 8-character hex string encoding a **little-endian 32-bit integer**.

Example: `10.0.2.15` → bytes `[0x0A, 0x00, 0x02, 0x0F]` → stored LE as `0x0F02000A` → hex string `0F02000A`.

To decode:
```rust
let n = u32::from_str_radix(hex, 16)?;  // parse as number: 0x0F02000A
Ipv4Addr::from(n.to_be())               // to_be() swaps to 0x0A00020F = 10.0.2.15
```

### IPv6 (`/proc/net/tcp6`)

The address is a 32-character hex string made of **four consecutive little-endian 32-bit words**.

Example: `::1` = `[0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1]`
- Split into four 32-bit groups: `00000000 00000000 00000000 00000001`
- Each word stored LE: `00000000 00000000 00000000 01000000`
- Hex string: `00000000000000000000000001000000`

To decode each 8-char chunk:
```rust
let word = u32::from_str_radix(&hex[i*8..(i+1)*8], 16)?;
// word.to_le_bytes() reverses the LE encoding back to network order
bytes[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
```

**The critical detail:** use `to_le_bytes()`, not `to_be_bytes()`. The hex string represents the LE byte layout directly. Parsing it as a number and taking LE bytes recovers the original network-order bytes.

### Port

The port is always a 4-character big-endian hex string: `1F90` = 8080.

---

## Step 2: Find the PID

Once you have the inode, scan `/proc/*/fd/` for a process that has a file descriptor pointing to `socket:[inode]`.

```
/proc/1234/fd/
  0 → /dev/pts/0
  3 → socket:[99001]   ← match
  4 → pipe:[12345]
```

Each entry in `/proc/<pid>/fd/` is a symlink. Read the symlink target with `fs::read_link()`. If it equals `"socket:[inode]"`, you have the owning pid.

```rust
for entry in fs::read_dir("/proc")? {
    let pid: u32 = entry.file_name().parse()?;  // skip non-numeric entries
    for fd in fs::read_dir(format!("/proc/{pid}/fd"))? {
        if fs::read_link(fd.path())? == format!("socket:[{inode}]") {
            return Some(pid);
        }
    }
}
```

**Performance note:** This is an O(processes × fds) scan, hot-path-reduced by a UID-filtered first pass (see `find_pid_for_inode`). On a desktop system with typical process counts (<500 processes, <50 fds each), it completes in under a millisecond. It is also called at most once per `(src_ip, src_port, protocol)` socket within the per-socket cache's TTL — retransmits and follow-up segments hit the cache; the NFQUEUE 5-tuple verdict cache further short-circuits subsequent packets at the enforcement layer.

---

## Step 3: Build ProcessInfo

`resolve()` no longer returns `Option<String>`. It returns `Option<ProcessInfo>`:

```rust
pub struct ProcessInfo {
    pub name: String,           // user-facing process name (e.g. "cursor", "chromium")
    pub exe: Option<String>,    // full /proc/<pid>/exe path — used for rule identity
    pub app_name: Option<String>, // package manager name when it differs from `name`
}
```

### Name

The primary name comes from `/proc/<pid>/exe` (basename preferred over `/proc/<pid>/comm` which the kernel truncates at 15 characters). For generic names (`"electron"`, `"AppRun"`, single-char names, shell wrappers) the fixup strategies described in Bug 23 apply.

### Exe path

`read_exe_path(pid)` reads the symlink at `/proc/<pid>/exe`, returning the full path (e.g. `/opt/cursor/resources/app.asar.unpacked/node_modules/@cursor-arm/cursor-linux-x64/cursor`). A trailing ` (deleted)` suffix (kernel notation for a binary replaced by an update while running) is stripped. The exe path is stored in `Rule.process_exe` and `FlowContext.process_exe` and used as the primary identity for rule matching when both the rule and the incoming flow have it — it is immune to `/proc/<pid>/comm`'s 15-character truncation and basename collisions between packages with the same executable name.

### App name (package manager lookup)

After resolving the name and exe, `lookup_pacman(exe_path)` is called:

1. Check `pacman_cache: Mutex<HashMap<String, Option<String>>>` — returns cached result (including cached `None`) without spawning a subprocess.
2. Run `pacman -Qo -- <exe_path>` — parses "owned by PKG" from stdout.
3. Store result (success or `None`) in cache.
4. Suppress `app_name` when it equals `name` (avoids showing "firefox (firefox)").

The result is stored in `ProcessInfo.app_name` and propagated to `FlowContext.app_name`. The decision dialog shows it as a secondary line under the process name (`pkg: cursor-bin`). Daemon logs include it as `(cursor-bin)` when present.

### ss fallback

When the full `/proc/net` + inode scan returns `None` (all retries exhausted), `try_ss_fallback(ip, port, protocol)` is attempted:

1. Run `ss -Hnp [-t|-u] src :<port>` — `-t` for TCP, `-u` for UDP.
2. Filter lines where the local address matches `(ip, port)` using `ss_local_matches` (handles IPv4, IPv6, IPv4-mapped).
3. Extract `pid=N` from the `users:(("name",pid=N,...))` field via `extract_pid_from_ss_line`.
4. If a pid is found, re-enter the `/proc/<pid>/exe` → name → app_name path.

`ss` is a last resort — it spawns a subprocess. It fires when both SOCK_DIAG and the `/proc/net` retry loop fail to yield an inode, or when the inode is found but `/proc/*/fd` cannot map it to a pid.

---

## Race Conditions

There are **three** TOCTOU windows that produce `process_name = None`:

1. **Kernel-publishing race (`/proc/net` only).** The kernel writes socket rows to `/proc/net/{tcp,udp}*` asynchronously. NFQUEUE can deliver a packet before the row exists. SOCK_DIAG avoids this for inode lookup; the `/proc/net` retry loop (`[0, 5, 15, 40]` ms) remains as fallback when netlink is unavailable.
2. **Fork/exec fd-visibility gap.** Multi-process apps (e.g. Electron, Chromium) spawn a dedicated network-service subprocess. During the brief `fork`→`exec` transition, the new process's file descriptors are not yet visible in `/proc/<pid>/fd/`, so `find_pid_for_inode` returns `None`. The retry loop in `find_pid_for_inode` (`[0, 3, 8]` ms) covers this window for most apps; very slow forks may still miss.
3. **Process-exit race.** Between packet delivery and `/proc` lookup the process exits: the inode disappears from `/proc/net/tcp*`, the fd symlink under `/proc/<pid>/fd/` is gone, and the lookup returns `None`.

All three look identical from the resolver's perspective — `Option<String>` returns `None` — but their *frequencies* differ. The kernel-publishing race and fork/exec gap fire on the **first packet of a brand-new connection**; the process-exit race fires on **packets in flight after the process has died** and is uncommon.

### Per-socket cache (in-memory, 60 s TTL)

To stop the kernel-publishing race from producing inconsistent results *across retransmits of the same connection*, every successful resolution is cached by `(src_ip, src_port, protocol)`. A retransmit of the same socket within the TTL returns the cached `ProcessInfo` without re-reading `/proc/net/*`. Implementation lives in `ProcProcessResolver::cache` (`Mutex<HashMap<SocketKey, CachedEntry>>`); entries past TTL are evicted lazily on the next insert that crosses the 4096-entry cap.

`CachedEntry` stores `{ name, exe, app_name, inserted_at }` — the full `ProcessInfo` including the exe path and package name, so repeated lookups for the same socket do not re-query `pacman` or re-read `/proc/<pid>/exe`.

Even with this cache, the **first** packet of a *new* connection still runs a live lookup (SOCK_DIAG → `/proc/net` → fd scan). Residual misses (fork/exec gap, process exit) are absorbed by `decision-engine` and `policy-engine` fallbacks; see [`docs/process-attribution-races.md`](process-attribution-races.md).

### What happens when attribution fails outright

A packet that loses the kernel race *and* gets no help from any later layer is still safe:

- The flow is classified with `process_name: None`.
- The rule engine falls back to destination-only matching (rules with `process_name=None` apply; rules with a specific process name only apply when the destination matcher is `IpExact` or `DomainExact` — see `policy-engine::process_matches`).
- If no rule matches, the flow enters the pending queue under `process_name = None` and the user is prompted with `(unknown)` in the dialog.

---

## Testing Strategy

`parse_proc_net()` is a **pure function** that takes a `&str` and returns `Option<u64>`. It has no I/O and can be tested with static string fixtures:

```rust
const TCP_SAMPLE: &str = "
  sl  local_address rem_address   st ...  inode
   0: 0F02000A:1F90 00000000:0000 01 ...  99001 ...";

#[test]
fn parses_ipv4_local_address() {
    let ip: IpAddr = "10.0.2.15".parse().unwrap();
    assert_eq!(parse_proc_net(TCP_SAMPLE, ip, 8080), Some(99001));
}
```

The inode→pid scan (`find_pid_for_inode`) and comm read (`read_comm`) are I/O-only wrappers with no logic — they do not need unit tests. Integration behavior is covered by the `ProcessResolver` trait abstraction: the rest of the system uses `FakeProcessResolver` in tests and `ProcProcessResolver` at runtime.

---

## Multi-Package-Manager Support Plan

Currently only `pacman` (Arch Linux) is supported. The goal is a single `query_package_owner(exe_path) -> Option<String>` function that works transparently across all major Linux distributions.

### Planned backends

| Package manager | Command | Output to parse | Distros |
|---|---|---|---|
| `pacman` | `pacman -Qo -- <exe>` | `<exe> is owned by <pkg> <ver>` | Arch, Manjaro, EndeavourOS |
| `dpkg` | `dpkg -S <exe>` | `<pkg>: <exe>` | Debian, Ubuntu, Mint |
| `rpm` | `rpm -qf <exe>` | `<pkg>-<ver>.<arch>` (trim version) | RHEL, Fedora, CentOS, openSUSE |
| `apk` | `apk info --who-owns <exe>` | `<exe> is owned by <pkg>-<ver>` | Alpine |
| `pacman` (also covers) | same | same | Parabola, Artix, CachyOS |

### Implementation approach

1. **Probe once on startup.** Check `which pacman dpkg rpm apk` (or try each binary) and cache which ones exist. Store the result in `ProcProcessResolver` as an enum `PackageManager`. Cost: one shell lookup on daemon start.
2. **Abstract behind one function.** `query_package_owner(exe_path, pm: PackageManager) -> Option<String>` dispatches to the right command and parser. The per-exe `pacman_cache` field is renamed to `pkg_cache`.
3. **Parse defensively.** Each parser trims version suffixes (`-1.2.3-4` for pacman, `-<ver>.<arch>` for rpm) and lowercases the result so display is consistent.
4. **Fallback order.** If the probed package manager returns `None` for an exe (AppImage, manually installed binary), `None` is cached and the display falls back to the process `name`. No multi-PM chaining — each distro has one primary package manager.
5. **Unknown distro.** If none of the above are found, `query_package_owner` always returns `None`. The feature degrades gracefully; the rest of the attribution pipeline is unaffected.

### Current state

Only `pacman` is wired. The probe/dispatch layer does not exist yet. To add a new package manager: (a) add a `PackageManager` variant, (b) add a `query_<pm>` function with parser, (c) add the variant to `probe_package_manager()`, (d) add unit tests for the parser with representative `dpkg -S` / `rpm -qf` / `apk info` output.

---

## Platform Note

This entire mechanism is Linux-specific:

- `/proc/net/tcp` — Linux only (not on macOS or Windows)
- `/proc/*/fd/` symlinks — Linux only
- `/proc/<pid>/comm` — Linux only

On macOS, the equivalent is `proc_pidinfo()` with `PROC_PIDLISTFDS` (private API, restricted). On Windows, `GetExtendedTcpTable()` from `iphlpapi.dll` returns a table mapping connections to PIDs directly — no fd scanning needed.
