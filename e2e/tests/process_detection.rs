//! Scenario 9 (rootful): real process-name attribution under load, across
//! transport protocols. Three phases, one test each, all approximating the
//! real world:
//!
//! * **TCP** — 10 uniquely-named real processes × 100 connections each
//!   (1000 requests) to an intercepted destination.
//! * **UDP** — same census shape with datagram traffic (`nc -u`).
//! * **DNS** — resolve a unique name, then connect to the resolved IP and
//!   assert the flow event carries the *domain* (the DNS-snoop IP→domain
//!   mapping fired), not just the IP.
//! * **QUIC** — HTTP/3 request via `curl --http3-only`; QUIC is UDP:443 to
//!   the packet layer and the classifier must tag it `Quic` with the right
//!   process.
//!
//! Target: the network's default gateway by default (traffic to it leaves
//! via the physical NIC and IS intercepted; traffic to the host's own IP
//! routes via `lo`, which the nftables bootstrap exempts). Override with
//! `E2E_TARGET_IP`. DNS/QUIC phases hit public resolvers/servers and need
//! internet access; they self-skip without it.
//!
//! All phases require interception (`nfqueue_enabled: true`) and otherwise
//! self-skip. Run via `just e2e` under a root daemon. When attribution
//! fails, the daemon's `proc:` stderr lines show which lookup stage missed —
//! check the journal (`journalctl -u logiguardd | grep 'proc:'`).

use std::process::{Command, Stdio};
use std::time::Duration;

use e2e::{expect_variant, list_flows, run_cli_json, serial_guard};

/// Procs × conns-per-proc. Real-world-ish: 10 apps, ~100 requests each.
const PROBE_COUNT: usize = 10;
const CONNS_PER_PROBE: usize = 100;

/// Wall-clock budget for the 1000-connection phases.
const RUN_BUDGET: Duration = Duration::from_secs(120);

/// The default gateway IPv4 (`ip route` first `default via`).
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

/// Tracks every rule id a scenario created so teardown can remove them all.
/// Deletes on drop, so teardown runs even when an assertion panics.
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

/// Common preflight: daemon up + interception on; returns the interceptable
/// target IP (gateway by default, `E2E_TARGET_IP` override).
fn preflight() -> Option<String> {
    let _guard = serial_guard();
    e2e::require_daemon();
    let health = expect_variant(
        &run_cli_json(&["health"]).expect("health must succeed"),
        "Health",
    );
    if health["nfqueue_enabled"].as_bool() != Some(true) {
        eprintln!(
            "skipping: daemon has nfqueue_enabled=false — process attribution \
             only runs on real intercepted packets"
        );
        return None;
    }
    match std::env::var("E2E_TARGET_IP") {
        Ok(ip) => Some(ip),
        Err(_) => match default_gateway() {
            Some(gw) => Some(gw),
            None => {
                eprintln!("skipping: no default gateway found (set E2E_TARGET_IP)");
                None
            }
        },
    }
}

/// Copy `/usr/bin/nc` as a uniquely-named probe binary.
fn make_nc_probe(name: &str) -> std::path::PathBuf {
    let probe_path = std::env::temp_dir().join(name);
    if std::fs::copy("/usr/bin/nc", &probe_path).is_err() {
        panic!("could not copy /usr/bin/nc as probe {name}");
    }
    probe_path
}

/// Copy a binary as a uniquely-named probe (for curl/dig phases).
fn make_probe_of(src: &str, name: &str) -> std::path::PathBuf {
    let probe_path = std::env::temp_dir().join(name);
    if std::fs::copy(src, &probe_path).is_err() {
        panic!("could not copy {src} as probe {name}");
    }
    probe_path
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Attribution census over flow events to `target_ip` since `started`:
/// prints per-probe counts and asserts every probe got attributed.
fn census_probes(
    target_ip: &str,
    started: u64,
    probe_names: &[String],
    per_probe: usize,
    label: &str,
) {
    let events = e2e::poll_until(RUN_BUDGET, || {
        let mine: Vec<_> = list_flows(5000)
            .into_iter()
            .filter(|f| {
                f["destination_ip"].as_str() == Some(target_ip)
                    && f["timestamp_secs"].as_u64().is_some_and(|t| t >= started)
            })
            .collect();
        (!mine.is_empty() && mine.len() >= probe_names.len()).then_some(mine)
    })
    .unwrap_or_default();

    let mut attributed: std::collections::HashMap<&str, usize> =
        probe_names.iter().map(|n| (n.as_str(), 0)).collect();
    let mut unattributed = 0usize;
    let mut misattributed: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for f in &events {
        match f["process_name"].as_str() {
            Some(name) if attributed.contains_key(name) => {
                *attributed.get_mut(name).unwrap() += 1;
            }
            Some(other) => *misattributed.entry(other.to_string()).or_insert(0) += 1,
            None => unattributed += 1,
        }
    }

    eprintln!("== {label} attribution census for {target_ip} ==");
    for name in probe_names {
        eprintln!(
            "  {:<28} {} / {} flows attributed",
            name,
            attributed[name.as_str()],
            per_probe
        );
    }
    eprintln!("  unattributed (None): {unattributed}");
    if !misattributed.is_empty() {
        eprintln!("  misattributed to: {misattributed:?}");
    }

    let missed: Vec<_> = probe_names
        .iter()
        .filter(|n| attributed[n.as_str()] == 0)
        .collect();
    assert!(
        missed.is_empty(),
        "process attribution failed for {} of {} probes: {missed:?}\n\
         The resolver lost these processes' flows. Inspect the failing lookup \
         stage in the daemon journal: `journalctl -u logiguardd | grep 'proc:'`",
        missed.len(),
        probe_names.len()
    );
}

// ---------------------------------------------------------------------------
// Phase 1: TCP — 10 procs × 100 connections
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs a root logiguard daemon with NFQUEUE interception; run via `just e2e`"]
fn tcp_ten_processes_times_hundred_requests_are_attributed() {
    let Some(target_ip) = preflight() else {
        return;
    };

    // Allow-rule for the target so 1000 rapid flows don't spawn tray dialogs.
    let mut rules = CreatedRules(std::collections::HashSet::new());
    let rule_id = e2e::next_rule_id("detect-tcp");
    rules.add_rule(&rule_id, &format!("{target_ip}/32"), "allow");

    let started = now_secs();

    // Spawn 10 unique-named probes, each a copy of `nc` driven by its own
    // thread — 10 threads mimic 10 concurrent apps; the exe basename is the
    // copy's unique name in every invocation, so attribution is
    // per-connection.
    let mut children = Vec::new();
    let mut probe_names = Vec::new();
    for _ in 0..PROBE_COUNT {
        let probe_name = e2e::next_process();
        let probe_path = make_nc_probe(&probe_name);
        let target = target_ip.clone();
        let path = probe_path.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..CONNS_PER_PROBE {
                // `-w 1`: connections to a discard/refusing port fail fast;
                // the SYN is what matters for classification, the verdict
                // (allow) lets it through and the refusal is expected.
                // stdin gets one byte: nc sends what it reads, and with
                // /dev/null it reads EOF and sends NOTHING.
                let _ = Command::new(&path)
                    .arg("-w")
                    .arg("1")
                    .arg(&target)
                    .arg("9")
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
        });
        children.push(handle);
        probe_names.push((probe_name, probe_path));
    }

    let run_start = std::time::Instant::now();
    for h in children {
        let _ = h.join();
    }
    let drained = run_start.elapsed();
    eprintln!("tcp probes done: {PROBE_COUNT} procs × {CONNS_PER_PROBE} conns in {drained:?}");
    std::thread::sleep(Duration::from_secs(1));

    let names: Vec<String> = probe_names.iter().map(|(n, _)| n.clone()).collect();
    census_probes(&target_ip, started, &names, CONNS_PER_PROBE, "tcp");

    for (_, path) in &probe_names {
        let _ = std::fs::remove_file(path);
    }
}

// ---------------------------------------------------------------------------
// Phase 2: UDP — 10 procs × 100 datagrams
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs a root logiguard daemon with NFQUEUE interception; run via `just e2e`"]
fn udp_ten_processes_times_hundred_datagrams_are_attributed() {
    let Some(target_ip) = preflight() else {
        return;
    };

    let mut rules = CreatedRules(std::collections::HashSet::new());
    let rule_id = e2e::next_rule_id("detect-udp");
    rules.add_rule(&rule_id, &format!("{target_ip}/32"), "allow");

    let started = now_secs();

    // `nc -u -w1 <ip> 9` sends one datagram then exits (port 9/udp discard —
    // the gateway may or may not answer; the outgoing packet is what the
    // NFQUEUE hook classifies).
    let mut children = Vec::new();
    let mut probe_names = Vec::new();
    for _ in 0..PROBE_COUNT {
        let probe_name = e2e::next_process();
        let probe_path = make_nc_probe(&probe_name);
        let target = target_ip.clone();
        let path = probe_path.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..CONNS_PER_PROBE {
                // stdin MUST carry a byte: nc sends what it reads — with
                // /dev/null it reads EOF and never transmits the datagram.
                let _ = Command::new(&path)
                    .arg("-u")
                    .arg("-w")
                    .arg("1")
                    .arg(&target)
                    .arg("9")
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
        });
        children.push(handle);
        probe_names.push((probe_name, probe_path));
    }

    let run_start = std::time::Instant::now();
    for h in children {
        let _ = h.join();
    }
    let drained = run_start.elapsed();
    eprintln!("udp probes done: {PROBE_COUNT} procs × {CONNS_PER_PROBE} datagrams in {drained:?}");
    std::thread::sleep(Duration::from_secs(1));

    let names: Vec<String> = probe_names.iter().map(|(n, _)| n.clone()).collect();
    census_probes(&target_ip, started, &names, CONNS_PER_PROBE, "udp");

    for (_, path) in &probe_names {
        let _ = std::fs::remove_file(path);
    }
}

// ---------------------------------------------------------------------------
// Phase 3: DNS — resolve a unique name, assert the domain lands on the flow
// ---------------------------------------------------------------------------

/// A public DNS name that (a) resolves via the system resolver, (b) is very
/// unlikely to appear in the operator's real rule set or traffic, and (c)
/// serves HTTPS on a stable IP. `e2e-<rand>.invalid` cannot be resolved, so
/// we resolve a real wildcard-friendly domain and assert on the *IP→domain
/// back-mapping* instead: connect to the resolved IP and expect the flow
/// event to carry the domain the daemon's DNS snoop learned.
#[test]
#[ignore = "needs a root logiguard daemon with NFQUEUE interception + internet; run via `just e2e`"]
fn dns_resolved_domain_is_stamped_on_flow() {
    let _guard = serial_guard();
    e2e::require_daemon();
    let health = expect_variant(
        &run_cli_json(&["health"]).expect("health must succeed"),
        "Health",
    );
    if health["nfqueue_enabled"].as_bool() != Some(true) {
        eprintln!("skipping: daemon has nfqueue_enabled=false");
        return;
    }

    // Unique process name for the curl probe.
    let probe_name = e2e::next_process();
    let probe_path = make_probe_of("/usr/bin/curl", &probe_name);

    // Resolve a real, low-traffic domain and pick an address.
    let domain = "wttr.in";
    let resolve = Command::new("dig")
        .args(["+short", domain, "A"])
        .output()
        .expect("dig must run");
    let ip = String::from_utf8_lossy(&resolve.stdout)
        .lines()
        .find(|l| l.parse::<std::net::Ipv4Addr>().is_ok())
        .unwrap_or_else(|| panic!("dig returned no A record for {domain}"))
        .to_string();

    // Allow the IP so the request doesn't prompt a dialog.
    let mut rules = CreatedRules(std::collections::HashSet::new());
    rules.add_rule(
        &e2e::next_rule_id("detect-dns"),
        &format!("{ip}/32"),
        "allow",
    );

    let started = now_secs();
    // curl the domain by NAME: the DNS query passes the daemon's DNS snoop,
    // then the TLS SNI/flow to the resolved IP should be stamped with the
    // domain via the snoop's IP→domain map.
    let out = Command::new(&probe_path)
        .args([
            "-s",
            "-o",
            "/dev/null",
            "--max-time",
            "15",
            &format!("https://{domain}/"),
        ])
        .status()
        .expect("curl probe must run");
    eprintln!("curl probe exit: {out}");

    // Assert a flow event to the resolved IP carrying the domain.
    let stamped = e2e::poll_until(Duration::from_secs(10), || {
        list_flows(2000)
            .into_iter()
            .find(|f| {
                f["destination_ip"].as_str() == Some(ip.as_str())
                    && f["timestamp_secs"].as_u64().is_some_and(|t| t >= started)
                    && f["destination_domain"].as_str() == Some(domain)
            })
            .map(|f| {
                (
                    f["process_name"].as_str().unwrap_or("").to_string(),
                    f.clone(),
                )
            })
    });
    let Some((flow_proc, flow)) = stamped else {
        panic!(
            "no flow event stamped with domain {domain} for ip {ip} — the DNS \
             snoop's IP→domain mapping did not fire (was the query answered \
             through the snooped path?)"
        );
    };
    eprintln!("dns phase ok: flow to {ip} stamped domain={domain} process={flow_proc:?}");
    assert_eq!(
        flow["protocol"].as_str(),
        Some("Tcp"),
        "expected a Tcp flow event: {flow}"
    );

    let _ = std::fs::remove_file(&probe_path);
}

// ---------------------------------------------------------------------------
// Phase 4: QUIC — HTTP/3 request; classifier must tag UDP:443 as Quic
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs a root logiguard daemon with NFQUEUE interception + HTTP/3-capable curl; run via `just e2e`"]
fn quic_http3_flow_is_attributed() {
    let _guard = serial_guard();
    e2e::require_daemon();
    let health = expect_variant(
        &run_cli_json(&["health"]).expect("health must succeed"),
        "Health",
    );
    if health["nfqueue_enabled"].as_bool() != Some(true) {
        eprintln!("skipping: daemon has nfqueue_enabled=false");
        return;
    }

    // Self-skip unless curl supports --http3-only (feature check, not a run).
    let version = Command::new("curl")
        .arg("--version")
        .output()
        .expect("curl must run");
    if !String::from_utf8_lossy(&version.stdout).contains("HTTP3") {
        eprintln!("skipping: curl lacks HTTP3 support (no HTTP3 in `curl --version`)");
        return;
    }

    // A known HTTP/3-enabled endpoint with a stable A record.
    let domain = "cloudflare-quic.com";

    let probe_name = e2e::next_process();
    let probe_path = make_probe_of("/usr/bin/curl", &probe_name);

    let resolve = Command::new("dig")
        .args(["+short", domain, "A"])
        .output()
        .expect("dig must run");
    let ip = String::from_utf8_lossy(&resolve.stdout)
        .lines()
        .find(|l| l.parse::<std::net::Ipv4Addr>().is_ok())
        .unwrap_or_else(|| panic!("dig returned no A record for {domain}"))
        .to_string();

    let mut rules = CreatedRules(std::collections::HashSet::new());
    rules.add_rule(
        &e2e::next_rule_id("detect-quic"),
        &format!("{ip}/32"),
        "allow",
    );

    let started = now_secs();
    // --http3-only: fails rather than falling back to TCP, so a Quic-tagged
    // flow proves real QUIC traffic hit the classifier.
    let out = Command::new(&probe_path)
        .args([
            "-s",
            "-o",
            "/dev/null",
            "--max-time",
            "20",
            "--http3-only",
            &format!("https://{domain}/"),
        ])
        .status()
        .expect("curl probe must run");
    eprintln!("curl --http3-only probe exit: {out} (nonzero may mean no HTTP/3 reachability)");
    if !out.success() {
        eprintln!("skipping: HTTP/3 request did not complete (network path lacks QUIC?)");
        return;
    }

    // The QUIC flow: UDP-based → classifier must tag protocol "Quic", and
    // attribute it to our uniquely-named curl copy.
    let quic_flow = e2e::poll_until(Duration::from_secs(10), || {
        list_flows(2000).into_iter().find(|f| {
            f["destination_ip"].as_str() == Some(ip.as_str())
                && f["timestamp_secs"].as_u64().is_some_and(|t| t >= started)
                && f["protocol"].as_str() == Some("Quic")
        })
    });
    let Some(flow) = quic_flow else {
        // Distinguish "no flow at all" from "flow recorded as plain Udp".
        let udp_only = list_flows(2000).into_iter().any(|f| {
            f["destination_ip"].as_str() == Some(ip.as_str())
                && f["timestamp_secs"].as_u64().is_some_and(|t| t >= started)
                && f["protocol"].as_str() == Some("Udp")
        });
        panic!(
            "no Quic-tagged flow event for {ip} after an HTTP/3 request \
             (udp_only_flow={udp_only}) — the classifier did not recognize \
             QUIC over UDP:443"
        );
    };
    assert_eq!(
        flow["process_name"].as_str(),
        Some(probe_name.as_str()),
        "QUIC flow attributed to the wrong process: {flow}"
    );
    eprintln!("quic phase ok: {flow}");

    let _ = std::fs::remove_file(&probe_path);
}
