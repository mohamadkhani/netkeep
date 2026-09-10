//! Black-box end-to-end suite for LogiGuard.
//!
//! The suite never launches the app: it drives the developer's running daemon
//! through the real `logiguard-cli` binary and asserts on its `--json` output.
//! See the spec (issue #1) for the design contract.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Process-wide guard so scenarios never run concurrently against the shared
/// live daemon, even under a bare `cargo test -p e2e` without
/// `--test-threads 1` (which `just e2e` passes).
pub fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let mutex = LOCK.get_or_init(|| Mutex::new(()));
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Locate the CLI binary. Prefers `E2E_CLI_BIN`, then an already-built debug
/// binary, so the suite tests the real operator-facing binary, not a linked crate.
fn cli_bin() -> String {
    if let Ok(path) = std::env::var("E2E_CLI_BIN") {
        return path;
    }
    // Cargo places sibling workspace binaries in the same target dir as this test.
    // CARGO_BIN_EXE_ only works for bins of the same crate, so fall back to the
    // conventional workspace layout.
    let manifest = env!("CARGO_MANIFEST_DIR");
    for dir in ["../target/debug", "../target/release"] {
        let candidate = format!("{manifest}/{dir}/logiguard-cli");
        if std::path::Path::new(&candidate).exists() {
            return candidate;
        }
    }
    // Last resort: whatever is on PATH (e.g. the installed /usr/bin/logiguard-cli).
    "logiguard-cli".to_string()
}

/// Run the real CLI binary with the given arguments and capture its output.
pub fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(cli_bin())
        .args(args)
        .env("LOGIGUARD_SOCKET_PATH", socket_path())
        .output()
        .expect("failed to spawn logiguard-cli (is it built? try `cargo build -p logiguard-cli`)")
}

/// Run the CLI with `--json` and parse stdout as a JSON object.
pub fn run_cli_json(args: &[&str]) -> Result<serde_json::Value, String> {
    let mut full: Vec<&str> = vec!["--json"];
    full.extend_from_slice(args);
    let out = run_cli(&full);
    if !out.status.success() {
        return Err(format!(
            "cli {args:?} failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).map_err(|e| {
        format!(
            "cli {args:?} emitted invalid JSON {:?}: {e}",
            String::from_utf8_lossy(&out.stdout).trim()
        )
    })
}

/// Assert the response is the named externally-tagged variant
/// (`{"Health": {…}}`) and return its inner payload.
pub fn expect_variant(resp: &serde_json::Value, variant: &str) -> serde_json::Value {
    match resp.get(variant) {
        Some(payload) => payload.clone(),
        None => panic!("expected response variant {variant}, got: {resp}"),
    }
}

/// The socket the suite talks to — the daemon's control socket, overridable
/// for pointing the suite at a non-default instance.
pub fn socket_path() -> String {
    std::env::var("LOGIGUARD_SOCKET_PATH").unwrap_or_else(|_| "/tmp/logiguard.sock".to_string())
}

/// Preflight: fail the whole suite loudly when the daemon is down, with an
/// actionable hint. Never let a broken environment masquerade as a green run.
pub fn require_daemon() {
    match run_cli_json(&["health"]) {
        Ok(resp) => {
            let health = expect_variant(&resp, "Health");
            assert_eq!(
                health["ready"].as_bool(),
                Some(true),
                "daemon reported non-ready health: {health}"
            );
        }
        Err(err) => panic!(
            "logiguard daemon is not reachable at {socket}.\n\
             Start it first, e.g. `systemctl start logiguardd` or `just run-daemon`, \
             then re-run the suite.\nUnderlying error: {err}",
            socket = socket_path(),
        ),
    }
}

/// Uniqueness source for per-run artifact names (probe processes, rule ids)
/// so a run never collides with artifacts of a previous run in the operator's
/// real database.
static PROBE_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Unique probe process name per run (used as the copied binary's basename —
/// the resolver reads `/proc/<pid>/exe` basename, so this IS the attributed
/// name under test).
pub fn next_process() -> String {
    let n = PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("e2e-probe-{now}-{n}")
}

/// Unique `e2e-`-prefixed rule id so test artifacts are greppable in the
/// operator's real database.
pub fn next_rule_id(label: &str) -> String {
    let n = PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("e2e-{label}-{n}")
}

/// List recent flow events as a JSON array.
pub fn list_flows(limit: usize) -> Vec<serde_json::Value> {
    match run_cli_json(&["list-flows", "--limit", &limit.to_string()]) {
        Ok(v) => expect_variant(&v, "FlowList")
            .as_array()
            .cloned()
            .unwrap_or_default(),
        Err(err) => panic!("list-flows failed: {err}"),
    }
}

/// Blocking read helper: poll `f` every 250 ms until it returns `Some` or the
/// timeout elapses (returns `None` on timeout).
pub fn poll_until<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
