# Arch Linux package (makepkg)

This directory contains a **PKGBUILD** that builds the workspace from a **copy** of the repository root (two levels up from this folder).

## Build

```bash
cd packaging/archlinux
makepkg -sf
sudo pacman -U logiguard-*.pkg.tar.zst
```

Requirements: `base-devel`, `rust` (stable), and the `makedepends` from the PKGBUILD.

## After install

1. **Daemon (root, systemd)**
   ```bash
   sudo systemctl enable --now logiguardd.service
   ```
   Default paths: socket `/run/logiguard/logiguard.sock`, database `/var/lib/logiguard/logiguard.db`.

2. **Kernel interception (optional)**
   Edit `/usr/lib/systemd/system/logiguardd.service` (or use a drop-in) to set e.g. `Environment=LOGIGUARD_NFQUEUE=0`, then `sudo systemctl daemon-reload && sudo systemctl restart logiguardd`.

3. **Desktop / tray GUI**
   A `.desktop` entry installs as **LogiGuard** with icon `io.logicamp.LogiGuard`. It uses the packaged socket path via `/etc/environment.d/logiguard.conf`; log out/in or reboot so the session picks it up, or set `LOGIGUARD_SOCKET_PATH` yourself.

   **Desktop compatibility:** The system tray icon works on both **KDE Plasma** (native support) and **GNOME** (requires the "AppIndicator and KStatusNotifierItem Support" extension, or equivalent). Other desktops implementing the freedesktop StatusNotifierItem specification are also supported.

4. **CLI**
   `logiguard-cli` is on `PATH`. Alias if you want a shorter name:
   `alias logiguard=logiguard-cli`

## AUR / publishing

For the AUR, typically publish a `-git` PKGBUILD that clones this repository and sets `pkgver()` from `git describe`; reuse the same `package()` install layout and `resources/linux/` files.
