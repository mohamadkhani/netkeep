# Arch Linux package (makepkg)

This directory contains a **PKGBUILD** that builds the workspace from a **copy** of the repository root (two levels up from this folder).

## Build

```bash
cd packaging/archlinux
makepkg -sf
sudo pacman -U netkeep-*.pkg.tar.zst
```

Requirements: `base-devel` and the `makedepends` from the PKGBUILD (`rustup`, `clang`, `llvm`, …).

The build installs a single **stable** Rust toolchain (pinned to 1.96.1 via `rust-toolchain.toml`) in a build-only directory and uses it for everything: the workspace, `bpf-linker`, and the eBPF DNS tracker. The eBPF step's `-Z build-std=core` is unlocked on stable via `RUSTC_BOOTSTRAP=1`, so no nightly toolchain is needed.

## After install

1. **Daemon (root, systemd)**
   ```bash
   sudo systemctl enable --now netkeepd.service
   ```
   Default paths: socket `/run/netkeep/netkeep.sock`, database `/var/lib/netkeep/netkeep.db`.

2. **Kernel interception (optional)**
   Edit `/usr/lib/systemd/system/netkeepd.service` (or use a drop-in) to set e.g. `Environment=NETKEEP_NFQUEUE=0`, then `sudo systemctl daemon-reload && sudo systemctl restart netkeepd`.

3. **DNS forwarder (optional, egress-aware DNS)**
   For proxy/tun/device routing, DNS must resolve through the same egress as TCP traffic. Enable the forwarder in a systemd drop-in:

   ```bash
   sudo mkdir -p /etc/systemd/system/netkeepd.service.d
   sudo tee /etc/systemd/system/netkeepd.service.d/dns-forwarder.conf <<'EOF'
   [Service]
   Environment=NETKEEP_DNS_FORWARDER=1
   EOF
   sudo systemctl daemon-reload && sudo systemctl restart netkeepd
   ```

   Then point the system resolver at the daemon (port 53 must be free):

   ```bash
   # If systemd-resolved owns 127.0.0.53, disable its stub listener first, e.g.:
   # sudo mkdir -p /etc/systemd/resolved.conf.d
   # echo -e '[Resolve]\nDNSStubListener=no' | sudo tee /etc/systemd/resolved.conf.d/netkeep.conf
   # sudo systemctl restart systemd-resolved

   echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf
   ```

   The daemon runs as root and loads an eBPF kprobe on `udp_sendmsg` for per-process DNS attribution. See [`docs/dns-forwarder.md`](../../docs/dns-forwarder.md).

4. **Desktop / tray GUI**
   A `.desktop` entry installs as **Netkeep** with icon `io.logicamp.Netkeep`. It uses the packaged socket path via `/etc/environment.d/netkeep.conf`; log out/in or reboot so the session picks it up, or set `NETKEEP_SOCKET_PATH` yourself.

   **Desktop compatibility:** The system tray icon works on both **KDE Plasma** (native support) and **GNOME** (requires the "AppIndicator and KStatusNotifierItem Support" extension, or equivalent). Other desktops implementing the freedesktop StatusNotifierItem specification are also supported.

5. **CLI**
   `netkeep-cli` is on `PATH`. Alias if you want a shorter name:
   `alias netkeep=netkeep-cli`

## AUR / publishing

For the AUR, typically publish a `-git` PKGBUILD that clones this repository and sets `pkgver()` from `git describe`; reuse the same `package()` install layout and `resources/linux/` files.
