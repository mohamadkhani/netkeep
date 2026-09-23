# Netkeep

**Every connection asks the keeper.**

Netkeep is a per-application network firewall for Linux. When an app opens a connection you haven't seen before, Netkeep intercepts it, shows you who is calling where, and lets you **allow**, **deny**, or **route** it — once, for the session, or permanently.

Think *Little Snitch* or *OpenSnitch*, built in Rust with kernel-level enforcement and domain-level awareness.

## How it works

1. **Intercept** — nftables sends new connections to the daemon via NFQUEUE.
2. **Attribute** — the flow is attributed to a process (via `/proc` socket lookup + eBPF DNS tracking) and to a domain (SNI inspection on TLS, DNS query correlation).
3. **Decide** — the decision engine matches rules by process, domain, IP/CIDR, and port. Unknown flows open a decision dialog with a countdown (auto-deny).
4. **Enforce** — verdicts are issued back to the kernel. `Route` verdicts can steer matching traffic through a SOCKS5/HTTP/Shadowsocks proxy, a TUN device, or a network interface — with egress-aware DNS forwarding so names resolve through the same path.
5. **Fail close** — if the daemon dies, the firewall closes instead of opening.

## Components

| Binary | Role |
|---|---|
| `netkeepd` | Root daemon: NFQUEUE processing, rules, pending queue, Unix-socket control API, DNS forwarder |
| `netkeep-cli` | Terminal interface: rules, pending decisions, health |
| `netkeep-gpui` | Desktop UI (GPUI): decision dialogs, rules, settings, tray |

```
 netkeep-gpui ─┐
               ├─ Unix socket (/tmp/netkeep.sock) ── netkeepd ── NFQUEUE/nftables (kernel)
 netkeep-cli ──┘
```

## Status

**Early / work in progress.** Linux desktop first (Arch Linux is the primary target). Expect rough edges; the [docs/](docs/) directory tracks architecture and learned patterns in detail.

Feature highlights that already work: process & SNI/DNS domain attribution, interactive allow/deny with scope toggles, rule priorities and wildcards, CIDR matching, per-session vs permanent rules, proxy/TUN/device egress routing, eBPF-based DNS process attribution, SQLite persistence.

## Install (Arch Linux)

```bash
git clone https://github.com/mohamadkhani/netkeep
cd netkeep/packaging/archlinux
makepkg -sf
sudo pacman -U netkeep-*.pkg.tar.zst
sudo systemctl enable --now netkeepd.service
```

Optional: enable kernel interception with `Environment=NETKEEP_NFQUEUE=0` (a drop-in on `netkeepd.service`), and the egress-aware DNS forwarder with `NETKEEP_DNS_FORWARDER=1`. See [`packaging/archlinux/README.md`](packaging/archlinux/README.md).

## From source

Requires a pinned stable Rust toolchain (see `rust-toolchain.toml`), `clang`/`llvm` for the eBPF crate, and `just`:

```bash
just check           # fast workspace compile check
just test            # unit + integration tests
just dev-install     # build release + install binaries + restart netkeepd
```

## Usage

```bash
# CLI
netkeep-cli add-rule --help        # create rules (process / domain / CIDR scopes)
netkeep-cli list-rules
netkeep-cli list-pendings
netkeep-cli health

# UI
netkeep-gpui                       # decision dialogs, rules editor, settings, tray
```

When a new connection appears, the dialog shows process, destination, domain, and IP — choose **Allow** or **Deny**, scope it to this session or permanently, and optionally bind it to an egress (proxy/TUN/device).

## Development

- [`docs/architecture.md`](docs/architecture.md) — components, data flow, design decisions
- [`develop.md`](develop.md) — developer guide; read the relevant doc before touching an area
- `just ci` — fmt + clippy (`-D warnings`) + tests
- `just e2e` — black-box suite against a running daemon

## License

GPL-3.0-or-later — see [LICENSE](LICENSE). Netkeep is free software: you can use, study, share, and improve it; derived work must stay free under the same license.
