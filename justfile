set shell := ["bash", "-cu"]

default:
  @just --list

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

lint:
  cargo clippy --workspace --all-targets -- -D warnings

check:
  cargo check --workspace

test:
  cargo test --workspace

# Black-box e2e suite against the running daemon. Requires: daemon up
# (`just run-daemon` or systemctl), CLI built (`cargo build -p netkeep-cli`).
# The process-detection scenario additionally needs interception enabled
# (NETKEEP_NFQUEUE set on the daemon) and self-skips otherwise.
e2e:
  cargo test -p e2e -- --test-threads 1 --ignored

ci:
  just fmt-check
  just lint
  just test

run-daemon:
  cargo run -p netkeep-daemon

run-cli *args:
  cargo run -p netkeep-cli -- {{args}}

run-gpui:
  cargo run -p netkeep-gpui

run-emulator:
  cargo run -p netkeep-emulator

# Fast local install for testing edits on this machine. Builds in the repo, so
# the warm `target/` is reused and only changed crates recompile. Prefer this
# over `makepkg` in packaging/archlinux for dev iteration — that build rsyncs a
# clean copy without `target/` and recompiles the whole workspace every time.
#
# This overwrites the pacman-owned binaries in place, so `pacman -Qkk netkeep`
# reports them as modified until the next real `makepkg -i`.
#
# Build and install the daemon, CLI and tray, then restart the daemon and tray.
dev-install:
  cargo xtask build-ebpf-release
  cargo build --workspace --release
  sudo install -Dm755 target/release/netkeep-daemon /usr/bin/netkeepd
  sudo install -Dm755 target/release/netkeep-cli    /usr/bin/netkeep-cli
  sudo install -Dm755 target/release/netkeep-gpui   /usr/bin/netkeep-gpui
  sudo systemctl restart netkeepd
  @just dev-restart-tray

# `dev-install` overwrites /usr/bin/netkeep-gpui while the tray keeps running
# the old image, so UI changes would only appear after the next login.
# No-op when the tray is not running, or when the shell has no graphical
# session to relaunch into (ssh, cron).
#
# Restart the GPUI tray so it loads the installed binary.
dev-restart-tray:
  #!/usr/bin/env bash
  set -uo pipefail

  if ! pgrep -x netkeep-gpui >/dev/null; then
    echo "==> tray not running; nothing to restart"
    exit 0
  fi
  if [ -z "${WAYLAND_DISPLAY:-}${DISPLAY:-}" ]; then
    echo "==> no graphical session in this shell; restart the tray from the desktop"
    exit 0
  fi

  # Stop the old process and wait for it to exit so the SNI name is released
  # before the new instance claims it.
  pkill -x netkeep-gpui || true
  for _ in $(seq 1 50); do
    pgrep -x netkeep-gpui >/dev/null || break
    sleep 0.1
  done
  if pgrep -x netkeep-gpui >/dev/null; then
    echo "==> tray did not stop after 5 s; quit it from the tray menu and rerun" >&2
    exit 1
  fi

  # Prefer the desktop entry: the process then lands in a proper application
  # scope, so the icon and window focus behave as after a login.
  if command -v gtk-launch >/dev/null 2>&1 &&
     gtk-launch io.logicamp.Netkeep >/dev/null 2>&1; then
    echo "==> tray relaunched via the desktop entry"
    exit 0
  fi

  setsid /usr/bin/netkeep-gpui >/dev/null 2>&1 </dev/null &
  echo "==> tray relaunched"

