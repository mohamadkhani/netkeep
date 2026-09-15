//! Cross-attribution e2e: packets must NEVER be attributed to the wrong
//! process, even when many differently-named processes hammer the SAME
//! destination concurrently.
//!
//! Strategy: each probe binary is a uniquely-named copy of `nc` that binds a
//! FIXED source port (`-p`). Flow events now record `source_port`, so every
//! event can be mapped back to the exact probe that generated it. Any flow
//! whose `process_name` disagrees with the owner of its source port is a
//! misattribution — the test fails on the FIRST one, and prints a census.
//!
//! Scenarios:
//! * **UDP** — N probes × M datagrams to one `(gateway, 9)` destination,
//!   interleaved across all probes per round (shared-destination pressure:
//!   Layer-0 caches, port-only fallbacks, eBPF port map).
//! * **TCP** — same shape with connections.
//! * **Rounds** — `E2E_ROUNDS` (default 3) repeats each scenario to expose
//!   timing-dependent failures; raise it for stress runs.
//!
//! The UDP phase historically caught real misattributions: the destination
//! cache restored whichever process resolved last, and the /proc port-only
//! fallback picked an arbitrary socket among same-port candidates.
//!
//! Run via `just e2e` against a root daemon with NFQUEUE interception.

use std::process::{Command, Stdio};
use std::time::Duration;

use e2e::{expect_variant, list_flows, run_cli_json, serial_guard};

/// Distinctly-named probes (keep ports clear of the ephemeral range so the
/// kernel never hands them to unrelated apps mid-test).
const PROBE_COUNT: usize = 8;
const ROUNDS_DEFAULT: usize = 3;

fn rounds() -> usize {
    std::env::var("E2E_ROUNDS")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(ROUNDS_DEFAULT)
}

fn default_gateway() -> Option<String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .skip_while(|tok| *tok != "via")
        .nth(1)
        .map(|s| s.to_string())
}

struct CreatedRules(std::collections::HashSet<String>);

impl CreatedRules {
    fn add_rule(&mut self, id: &str, destination: &str, action: &str) {
        run_cli_json(&["add-rule", id, destination, "--action", action])
            .unwrap_or_else(|e| panic!("add-rule {id} failed: {e}"));
        self.0.insert(id.to_string());
    }
}

impl Drop for CreatedRules {
    fn drop(&mut self) {
        for id in self.0.drain() {
            if let Err(err) = run_cli_json(&["delete-rule", &id]) {
                eprintln!("warning: teardown could not delete rule {id}: {err}");
            }
        }
    }
}

fn preflight() -> Option<String> {
    let _guard = serial_guard();
    e2e::require_daemon();
    let health = expect_variant(
        &run_cli_json(&["health"]).expect("health must succeed"),
        "Health",
    );
    if health["nfqueue_enabled"].as_bool() != Some(true) {
        eprintln!("skipping: daemon has nfqueue_enabled=false");
        return None;
    }
    default_gateway()
}

fn make_nc_probe(name: &str) -> std::path::PathBuf {
    let probe_path = std::env::temp_dir().join(name);
    if std::fs::copy("/usr/bin/nc", &probe_path).is_err() {
        panic!("could not copy /usr/bin/nc as probe {name}");
    }
    probe_path
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One probe invocation: `nc [-u] -w1 -p SPORT gw 9` with one byte on stdin.
fn fire_probe(path: &std::path::Path, udp: bool, sport: u16, target: &str) {
    let mut cmd = Command::new(path);
    if udp {
        cmd.arg("-u");
    }
    let _ = cmd
        .args(["-w", "1", "-p", &sport.to_string(), target, "9"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(b"x");
            }
            child.wait()
        });
}

/// The strict cross-attribution assertion: every flow event to `target:9`
/// since `started` whose source port belongs to one of our probes must carry
/// that probe's process name. Returns (flows, misattributed, unknown).
fn audit_cross_attribution(
    target: &str,
    started: u64,
    sport_to_probe: &std::collections::HashMap<u16, String>,
    label: &str,
    budget: Duration,
) -> (usize, usize, usize) {
    let mut polls = 0usize;
    let events = e2e::poll_until(budget, || {
        polls += 1;
        let all = list_flows(5000);
        if polls == 1 {
            eprintln!(
                "  audit: started={started} target={target} total={} first={}",
                all.len(),
                all.first()
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| "none".into())
            );
        }
        let mine: Vec<_> = all
            .into_iter()
            .filter(|f| {
                f["destination_ip"].as_str() == Some(target)
                    && f["destination_port"].as_u64() == Some(9)
                    && f["timestamp_secs"].as_u64().is_some_and(|t| t >= started)
            })
            .collect();
        (!mine.is_empty() && mine.len() >= sport_to_probe.len()).then_some(mine)
    })
    .unwrap_or_default();

    let mut misattributed = Vec::new();
    let mut unknown = 0usize;
    for f in &events {
        let sport = f["source_port"].as_u64().map(|s| s as u16);
        let name = f["process_name"].as_str();
        match (sport, name) {
            (Some(sport), Some(name)) => match sport_to_probe.get(&sport) {
                Some(owner) if owner == name => {}
                Some(owner) => misattributed.push(format!(
                    "sport={sport} owned by {owner} but attributed to {name}"
                )),
                None => eprintln!("  note: flow sport={sport} not ours (foreign traffic?)"),
            },
            (Some(_), None) => unknown += 1,
            (None, n) => eprintln!("  note: flow without sport, name={n:?} (pre-migration row?)"),
        }
    }

    eprintln!(
        "== {label}: {} flows, {} unknown(None), {} MISATTRIBUTED ==",
        events.len(),
        unknown,
        misattributed.len()
    );
    for m in &misattributed {
        eprintln!("  MISATTRIBUTED: {m}");
    }
    assert!(
        misattributed.is_empty(),
        "{label}: {} flow(s) attributed to the WRONG process — first: {:?}",
        misattributed.len(),
        misattributed.first()
    );
    (events.len(), unknown, misattributed.len())
}

/// Drive N probes × R rounds against one shared destination, interleaving
/// probes within each round so their packets race in the same time window.
fn cross_attribution_scenario(udp: bool, label: &str) {
    let Some(target) = preflight() else { return };

    let mut rules = CreatedRules(std::collections::HashSet::new());
    rules.add_rule(
        &e2e::next_rule_id("xattr"),
        &format!("{target}/32"),
        "allow",
    );

    // Build probes with unique names and fixed source ports.
    let base_sport: u16 = if udp { 42420 } else { 42520 };
    let mut probes: Vec<(String, std::path::PathBuf, u16)> = Vec::new();
    for i in 0..PROBE_COUNT {
        let name = e2e::next_process();
        let path = make_nc_probe(&name);
        probes.push((name, path, base_sport + i as u16));
    }
    let sport_to_probe: std::collections::HashMap<u16, String> = probes
        .iter()
        .map(|(name, _, sport)| (*sport, name.clone()))
        .collect();

    let started = now_secs();
    for round in 0..rounds() {
        // Interleave: one datagram/connection per probe, looping, so all
        // probes have in-flight traffic simultaneously.
        for _ in 0..5 {
            for (_, path, sport) in &probes {
                fire_probe(path, udp, *sport, &target);
            }
        }
        eprintln!("{label}: round {}/{} fired", round + 1, rounds());
    }
    // Give the daemon a moment to drain, then audit strictly.
    std::thread::sleep(Duration::from_secs(2));

    audit_cross_attribution(
        &target,
        started,
        &sport_to_probe,
        label,
        Duration::from_secs(60),
    );

    for (_, path, _) in &probes {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
#[ignore = "needs a root logiguard daemon with NFQUEUE interception; run via `just e2e`"]
fn udp_shared_destination_never_cross_attributes() {
    cross_attribution_scenario(true, "udp-cross");
}

#[test]
#[ignore = "needs a root logiguard daemon with NFQUEUE interception; run via `just e2e`"]
fn tcp_shared_destination_never_cross_attributes() {
    cross_attribution_scenario(false, "tcp-cross");
}

/// Forwarded (routed) traffic has no local socket. Before the fix, such
/// packets were attributed to whatever local process last used the same
/// `(dst_ip, dst_port)` via the Layer-0 cache — e.g. a docker container's
/// wget showing up as the operator's local `curl`. Now: forwarded packets
/// must never carry a LOCAL process name (they stay unknown / device-labeled
/// unless the container's eBPF-captured PID resolves).
///
/// Uses docker when available; self-skips otherwise. The local probe fills
/// the Layer-0 cache for the destination first — the exact poison the fix
/// must resist.
#[test]
#[ignore = "needs a root logiguard daemon with NFQUEUE interception + docker; run via `just e2e`"]
fn forwarded_container_traffic_is_not_attributed_to_local_process() {
    let Some(target) = preflight() else { return };

    let docker = Command::new("docker")
        .arg("version")
        .output()
        .ok()
        .filter(|o| o.status.success());
    if docker.is_none() {
        eprintln!("skipping: docker not available");
        return;
    }

    let mut rules = CreatedRules(std::collections::HashSet::new());
    rules.add_rule(&e2e::next_rule_id("fwd"), &format!("{target}/32"), "allow");

    // Local probe: fill Layer-0 (dst, 9) with a uniquely-named curl copy.
    let local_name = e2e::next_process();
    let local_probe = std::env::temp_dir().join(&local_name);
    std::fs::copy("/usr/bin/curl", &local_probe).expect("copy curl");
    let _ = Command::new(&local_probe)
        .args([
            "-s",
            "-o",
            "/dev/null",
            "--max-time",
            "6",
            &format!("http://{target}/"),
        ])
        .status();
    std::thread::sleep(Duration::from_secs(1));

    // Container traffic to the SAME destination.
    let started = now_secs();
    let _ = Command::new("docker")
        .args([
            "run",
            "--rm",
            "alpine",
            "sh",
            "-c",
            &format!(
                "wget -q -O /dev/null -T 4 http://{target}/ ; wget -q -O /dev/null -T 4 http://{target}/"
            ),
        ])
        .output();
    std::thread::sleep(Duration::from_secs(2));

    // Any flow to (target, 80) recorded during the container window must NOT
    // carry the local probe's name (or any local name).
    let flows: Vec<_> = list_flows(2000)
        .into_iter()
        .filter(|f| {
            f["destination_ip"].as_str() == Some(target.as_str())
                && f["timestamp_secs"].as_u64().is_some_and(|t| t >= started)
        })
        .collect();
    eprintln!(
        "== forward-cross: {} flows during container window ==",
        flows.len()
    );
    let attributed: Vec<String> = flows
        .iter()
        .filter_map(|f| f["process_name"].as_str().map(str::to_string))
        .collect();
    eprintln!("  process names seen: {attributed:?}");
    assert!(
        !attributed.iter().any(|n| n == &local_name),
        "container traffic was attributed to the LOCAL probe {local_name:?} — \
         forwarded packets must never restore local-process attribution"
    );

    let _ = std::fs::remove_file(&local_probe);
}
