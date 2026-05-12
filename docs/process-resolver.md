# Process Resolver: Mapping Network Packets to Processes

This document explains how LogiGuard identifies which process owns an intercepted network connection, using only the Linux `/proc` filesystem — no external tools or libraries required.

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
│  hit → return cached name, skip everything    │
└──────────────────────┬─────────────────────────┘
                       │ miss
                       ▼
/proc/net/{tcp,tcp6,udp,udp6}
  find row where local_address matches
  retry [0, 3, 8] ms — TOCTOU with kernel publishing
        │
        └── inode + uid
                │
                ▼
        /proc/*/fd/*
          scan symlinks for socket:[inode]
          UID-filtered first pass, full scan fallback
                │
                └── pid
                        │
                        ▼
                /proc/<pid>/exe  (preferred)
                /proc/<pid>/comm (fallback — kernel truncates to 15 chars)
                parent-process exe basename for short names (≤3 chars)
                  process name
                        │
                        ▼
            insert into per-socket cache
```

---

## Step 1: Find the Socket Inode

The kernel exposes all open sockets in `/proc/net/`:

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

## Step 3: Read the Process Name

```
/proc/<pid>/comm   →   "firefox\n"
```

`comm` contains the short process name (up to 15 characters), newline-terminated. Trim and return.

```rust
fs::read_to_string(format!("/proc/{pid}/comm"))?.trim().to_string()
```

For the full executable path, `/proc/<pid>/exe` is a symlink to the binary. For command-line arguments, `/proc/<pid>/cmdline` has null-separated args. `comm` is sufficient for display and rule matching.

---

## Race Conditions

There are **two** TOCTOU windows that produce `process_name = None`:

1. **Kernel-publishing race.** The kernel writes the socket entry to `/proc/net/{tcp,udp}*` asynchronously. NFQUEUE can hand a packet to userspace before the row is visible. The retry loop in `retry_find_socket` (`[0, 3, 8]` ms) closes most of this window; under load or for very fast resolvers some packets still miss.
2. **Process-exit race.** Between packet delivery and `/proc` lookup the process exits: the inode disappears from `/proc/net/tcp*`, the fd symlink under `/proc/<pid>/fd/` is gone, and the lookup returns `None`.

Both look identical from the resolver's perspective — `Option<String>` returns `None` — but their *frequencies* differ. The kernel-publishing race fires on the **first packet of a brand-new connection** under contention. The process-exit race fires on **packets in flight after the process has died** and is uncommon.

### Per-socket cache (in-memory, 60 s TTL)

To stop the kernel-publishing race from producing inconsistent results *across retransmits of the same connection*, every successful resolution is cached by `(src_ip, src_port, protocol)`. A retransmit of the same socket within the TTL returns the cached name without re-reading `/proc/net/*`. Implementation lives in `ProcProcessResolver::cache` (`Mutex<HashMap<SocketKey, CachedName>>`); entries past TTL are evicted lazily on the next insert that crosses the 4096-entry cap.

Even with this cache, the **first** packet of a *new* connection still has to win or lose the `/proc` race on its own. The fallback paths in `decision-engine` and `policy-engine` absorb that residual loss; see [`docs/process-attribution-races.md`](process-attribution-races.md) for the full picture.

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

## Platform Note

This entire mechanism is Linux-specific:

- `/proc/net/tcp` — Linux only (not on macOS or Windows)
- `/proc/*/fd/` symlinks — Linux only
- `/proc/<pid>/comm` — Linux only

On macOS, the equivalent is `proc_pidinfo()` with `PROC_PIDLISTFDS` (private API, restricted). On Windows, `GetExtendedTcpTable()` from `iphlpapi.dll` returns a table mapping connections to PIDs directly — no fd scanning needed.
