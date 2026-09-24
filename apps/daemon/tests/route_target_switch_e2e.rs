use std::env;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn run_cmd(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {program}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {:?} failed: status={}, stderr={}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn sqlite_query(db_path: &str, sql: &str) -> Result<String, String> {
    run_cmd("sqlite3", &[db_path, sql])
}

fn sqlite_exec(db_path: &str, sql: &str) -> Result<(), String> {
    let _ = run_cmd("sqlite3", &[db_path, sql])?;
    Ok(())
}

/// Get the egress IP as seen by an external service, through the proxy.
/// Uses ipmyp.ir which is accessible from both Iran and non-Iran networks.
fn egress_ip_via_proxy(proxy: &str) -> Result<String, String> {
    let output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "15",
            "--proxy",
            proxy,
            "https://ipmyp.ir/",
        ])
        .output()
        .map_err(|e| format!("failed to run curl: {e}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl ipmyp.ir failed: {err}"));
    }
    let body = String::from_utf8_lossy(&output.stdout);
    // Extract data-ip="x.x.x.x" from HTML
    if let Some(start) = body.find("data-ip=\"") {
        let rest = &body[start + 9..];
        if let Some(end) = rest.find('"') {
            let ip = &rest[..end];
            if ip.contains('.') || ip.contains(':') {
                return Ok(ip.to_string());
            }
        }
    }
    Err("could not extract data-ip from ipmyp.ir response".to_string())
}

/// Resolve a hostname to an IP address using system DNS.
/// This avoids the daemon needing to resolve it (VPN DNS may fail for .ir domains).
fn resolve_host(host: &str) -> Result<String, String> {
    let output = Command::new("dig")
        .args(["+short", host, "A"])
        .output()
        .map_err(|e| format!("failed to run dig: {e}"))?;
    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if ip.contains('.') {
        Ok(ip)
    } else {
        // Fallback to host command
        run_cmd("host", &["-t", "A", host, "-W", "5"])
    }
}

#[test]
fn route_target_switch_changes_observable_behavior() -> Result<(), String> {
    if env::var("NETKEEP_E2E_ROUTE_SWITCH").ok().as_deref() != Some("1") {
        eprintln!("skipping e2e test: set NETKEEP_E2E_ROUTE_SWITCH=1 to enable");
        return Ok(());
    }

    let db_path = env::var("NETKEEP_DB_PATH").unwrap_or_else(|_| "/tmp/netkeep.db".to_string());
    let proxy =
        env::var("NETKEEP_SOCKS_PROXY").unwrap_or_else(|_| "socks5h://127.0.0.1:1080".to_string());
    let tun_name = env::var("NETKEEP_TUN_TARGET").unwrap_or_else(|_| "X2265102_GERMN3".to_string());
    let device_name = env::var("NETKEEP_DEVICE_TARGET").unwrap_or_else(|_| "wlp0s20f3".to_string());

    // Resolve ipmyp.ir to IP so the daemon doesn't need DNS for it.
    // The curl to ipmyp.ir still uses the domain (via SOCKS domain forwarding),
    // but the rule in DB uses an IP-based destination to avoid daemon DNS issues.
    let probe_ip = resolve_host("ipmyp.ir")?;
    eprintln!("resolved ipmyp.ir => {probe_ip}");

    // Look for existing route rule, or create one using the resolved IP.
    let existing_rule = sqlite_query(
        &db_path,
        "SELECT id FROM rules WHERE action = 4 ORDER BY id DESC LIMIT 1;",
    )
    .unwrap_or_default();

    let (rule_id, created_rule_id) = if !existing_rule.is_empty() {
        (existing_rule, None)
    } else {
        let pid = std::process::id();
        let id = format!("e2e-route-{pid}");
        // destination_kind=1 (IpExact), route_target_kind=1 (Tun)
        sqlite_exec(
            &db_path,
            &format!(
                "INSERT INTO rules (id,enabled,action,duration,process_name,destination_kind,destination_value,route_target_kind,route_target_value) \
                 VALUES ('{id}',1,4,2,'socks-client',1,'{probe_ip}',1,'{tun_name}');"
            ),
        )?;
        eprintln!("created route rule: {id} for IP {probe_ip}");
        (id.clone(), Some(id))
    };

    let set_target = |target_kind: i32, target_value: &str| -> Result<(), String> {
        sqlite_exec(
            &db_path,
            &format!(
                "UPDATE rules SET route_target_kind={}, route_target_value='{}' WHERE id='{}';",
                target_kind,
                target_value.replace('\'', "''"),
                rule_id.replace('\'', "''")
            ),
        )?;
        thread::sleep(Duration::from_millis(500));
        Ok(())
    };

    // Test: get egress IP via TUN
    eprintln!("--- testing egress IP with Tun({tun_name}) ---");
    set_target(1, &tun_name)?;
    let tun_result = match egress_ip_via_proxy(&proxy) {
        Ok(ip) => format!("OK:{ip}"),
        Err(e) => format!("ERR:{e}"),
    };

    // Test: get egress IP via Device
    eprintln!("--- testing egress IP with Device({device_name}) ---");
    set_target(2, &device_name)?;
    let dev_result = match egress_ip_via_proxy(&proxy) {
        Ok(ip) => format!("OK:{ip}"),
        Err(e) => format!("ERR:{e}"),
    };

    // Cleanup
    if let Some(id) = &created_rule_id {
        let _ = sqlite_exec(
            &db_path,
            &format!("DELETE FROM rules WHERE id='{}';", id.replace('\'', "''")),
        );
    }

    if tun_result == dev_result {
        return Err(format!(
            "route target switch had no effect: tun({tun_name}) => {tun_result}; device({device_name}) => {dev_result}"
        ));
    }

    println!(
        "route switch verified: tun({tun_name}) => {tun_result}; device({device_name}) => {dev_result}"
    );
    Ok(())
}
