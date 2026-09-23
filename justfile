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
dev-install:
  cargo xtask build-ebpf-release
  cargo build --workspace --release
  sudo install -Dm755 target/release/netkeep-daemon /usr/bin/netkeepd
  sudo install -Dm755 target/release/netkeep-cli    /usr/bin/netkeep-cli
  sudo install -Dm755 target/release/netkeep-gpui   /usr/bin/netkeep-gpui
  sudo systemctl restart netkeepd
  @echo "==> daemon restarted. The tray still runs the old binary — 'just dev-restart-tray' to pick up UI changes."

# Relaunch the GPUI tray so it picks up a freshly installed binary.
# No-op if the tray isn't already running.
dev-restart-tray:
  if pgrep -x netkeep-gpui >/dev/null; then \
    pkill -x netkeep-gpui; \
    sleep 0.5; \
    setsid /usr/bin/netkeep-gpui >/dev/null 2>&1 </dev/null & \
    echo "==> tray relaunched"; \
  else \
    echo "==> tray not running; nothing to restart"; \
  fi

