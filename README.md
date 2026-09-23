# Netkeep

**Every connection asks the keeper.**

Netkeep is network control for Linux. It watches the connections your apps make at the packet level, attributes each one to a process and — for TLS and DNS traffic — to a domain, then applies your rules: **allow**, **deny**, or **route**.

Unknown connections open a decision dialog with a countdown. No answer means deny. Rules match by app, domain, IP/CIDR, or port, and can apply once, for the session, or permanently.

> If you know Little Snitch (macOS) or OpenSnitch (Linux), Netkeep belongs to the same family: interactive, per-connection control. What it adds on top is routing — rules don't just say yes or no, they can steer traffic somewhere else entirely.

## See, decide, steer

| | |
|---|---|
| **See** | Process attribution via `/proc` socket lookup and eBPF DNS tracking. Domain attribution via TLS SNI inspection and DNS query correlation. |
| **Decide** | Rule matchers for process, domain (with wildcards), IP/CIDR, and port. Priorities, session vs permanent scopes, interactive dialog with auto-deny. |
| **Steer** | Per-rule egress routing: SOCKS5, HTTP CONNECT, or Shadowsocks proxy, TUN device, or named interface — with DNS resolved through the same path. |
| **Survive** | Fail-close: if the daemon stops answering, the firewall closes instead of opening. |

## How it works

nftables hands new connections to the daemon over NFQUEUE. The daemon attributes the flow, asks the decision engine, and returns a verdict to the kernel: accept, drop, mark-and-route, or *pending* while the dialog waits for you.

```
netkeep-gpui ─┐
              ├─ Unix socket ─── netkeepd ─── NFQUEUE (nftables) ─── kernel
netkeep-cli ──┘
```

## Routing: rule-bound egress

The part most firewalls don't do. A rule's action is not limited to allow or deny — it can bind matching traffic to an **egress**:

- **Route targets** — SOCKS5 proxy, HTTP CONNECT proxy, Shadowsocks, TUN device, or a named network interface
- **Fallback chains** — an egress holds an ordered list of targets; the first available one wins at enforcement time
- **Egress-aware DNS** — the built-in DNS forwarder resolves names through the same egress as the TCP traffic, so routed apps never leak queries to the local resolver
- **Same matchers as any rule** — route one app, one domain, one CIDR, or one port

Example: send `spotify` through the Shadowsocks proxy, keep `ssh` on the wire, drop everything else — three rules, no iptables scripts.

## Components

| Binary | Role |
|---|---|
| `netkeepd` | Root daemon: NFQUEUE processing, rules, pending queue, control API, DNS forwarder |
| `netkeep-cli` | Terminal interface: rules, pending decisions, health |
| `netkeep-gpui` | Desktop UI (GPUI): decision dialogs, rules editor, settings, tray |

## Status

**Early / work in progress.** Linux desktop first, Arch Linux as the primary target. See [`docs/`](docs/) for the architecture and [`docs/implementation-status.md`](docs/implementation-status.md) for what works today.

## Install (Arch Linux)

```bash
git clone https://github.com/mohamadkhani/netkeep
cd netkeep/packaging/archlinux
makepkg -sf
sudo pacman -U netkeep-*.pkg.tar.zst
sudo systemctl enable --now netkeepd.service
```

Optional: kernel interception (`NETKEEP_NFQUEUE`) and the egress-aware DNS forwarder (`NETKEEP_DNS_FORWARDER`) are enabled via systemd drop-ins — see [`packaging/archlinux/README.md`](packaging/archlinux/README.md).

## From source

Requires the pinned stable Rust toolchain (`rust-toolchain.toml`), `clang`/`llvm` for the eBPF crate, and [`just`](https://github.com/casey/just):

```bash
just check           # fast workspace compile check
just test            # unit + integration tests
just dev-install     # release build + install binaries + restart netkeepd
```

## Usage

```bash
netkeep-cli add-rule --help     # create rules: process / domain / CIDR / port matchers
netkeep-cli list-rules
netkeep-cli list-pendings
netkeep-cli list-flows
netkeep-cli health

netkeep-gpui                    # dialogs, rules editor, settings, tray
```

## Development

- [`docs/architecture.md`](docs/architecture.md) — components, data flow, design decisions
- [`develop.md`](develop.md) — developer guide; read the relevant doc before touching an area
- `just ci` — fmt + clippy (`-D warnings`) + tests
- `just e2e` — black-box suite against a running daemon

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
