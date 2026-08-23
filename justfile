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

ci:
  just fmt-check
  just lint
  just test

run-daemon:
  cargo run -p logiguard-daemon

run-cli *args:
  cargo run -p logiguard-cli -- {{args}}

run-gpui:
  cargo run -p logiguard-gpui

run-emulator:
  cargo run -p logiguard-emulator

# Fast local install for testing edits on this machine. Builds in the repo, so
# the warm `target/` is reused and only changed crates recompile. Prefer this
# over `makepkg` in packaging/archlinux for dev iteration — that build rsyncs a
# clean copy without `target/` and recompiles the whole workspace every time.
#
# This overwrites the pacman-owned binaries in place, so `pacman -Qkk logiguard`
# reports them as modified until the next real `makepkg -i`.
dev-install:
  cargo xtask build-ebpf-release
  cargo build --workspace --release
  sudo install -Dm755 target/release/logiguard-daemon /usr/bin/logiguardd
  sudo install -Dm755 target/release/logiguard-cli    /usr/bin/logiguard-cli
  sudo install -Dm755 target/release/logiguard-gpui   /usr/bin/logiguard-gpui
  sudo systemctl restart logiguardd
  @echo "==> daemon restarted. The tray still runs the old binary — 'just dev-restart-tray' to pick up UI changes."

# Relaunch the GPUI tray so it picks up a freshly installed binary.
# No-op if the tray isn't already running.
dev-restart-tray:
  if pgrep -x logiguard-gpui >/dev/null; then \
    pkill -x logiguard-gpui; \
    sleep 0.5; \
    setsid /usr/bin/logiguard-gpui >/dev/null 2>&1 </dev/null & \
    echo "==> tray relaunched"; \
  else \
    echo "==> tray not running; nothing to restart"; \
  fi

