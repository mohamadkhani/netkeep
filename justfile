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

run-cli:
  cargo run -p logiguard-cli -- {{args}}

run-gpui:
  cargo run -p logiguard-gpui

