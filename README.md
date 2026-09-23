# Netkeep

**Every connection asks the keeper.**

Netkeep is network control for Linux. It sees every connection your apps make — attributed to the process, the domain, and the address — and gives you the say: **allow**, **deny**, or **route** it, matched by app, domain, IP/CIDR, or port, scoped to once, the session, or permanently. Unknown connections open a decision dialog: who is calling, where, and what to do about it.

Where a firewall only answers yes or no, Netkeep goes further: any rule can **reroute** matching traffic through a SOCKS5/HTTP/Shadowsocks proxy, a TUN device, or a network interface — with DNS resolved through the same path. Decide not just *whether* an app talks, but *where it talks through*.

Think *Little Snitch* or *OpenSnitch*, built in Rust with kernel-level enforcement and domain-level awareness.

## How it works

1. **Intercept** — nftables sends new connections to the daemon via NFQUEUE.
2. **Attribute** — the flow is attributed to a process (via `/proc` socket lookup + eBPF DNS tracking) and to a domain (SNI inspection on TLS, DNS query correlation).
3. **Decide** — the decision engine matches rules by process, domain, IP/CIDR, and port. Unknown flows open a decision dialog with a countdown (auto-deny).
4. **Enforce** — verdicts are issued back to the kernel. `Route` verdicts can steer matching traffic through a SOCKS5/HTTP/Shadowsocks proxy, a TUN device, or a network interface — with egress-aware DNS forwarding so names resolve through the same path.
5. **Fail close** — if the daemon dies, the firewall closes instead of opening.

## Routing: rule-bound egress

The differentiating feature. Rules don't just allow or deny — they can bind traffic to an **egress**:

- **Route targets:** SOCKS5 proxy, HTTP CONNECT proxy, Shadowsocks, TUN device, or a named network interface
- **Fallback chains:** an egress holds an ordered target list; the first available target wins at enforcement time
- **Egress-aware DNS:** the built-in DNS forwarder resolves names through the same egress as the TCP traffic, so routed apps never leak queries to the local resolver
- **Per scope:** route one app, one domain, one CIDR, or one port — chosen per rule like any other action

Example: send `spotify` through the Shadowsocks proxy, keep `ssh` on the wire, and drop everything else — all in rules, no iptables scripts.

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
