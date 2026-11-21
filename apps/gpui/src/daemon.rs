use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::Sender;

use control_api::{ControlRequest, ControlResponse, PushNotification};
use core_types::{Egress, PendingDecision};

/// Default control socket location. Matches the systemd unit's
/// `NETKEEP_SOCKET_PATH` (packaging/archlinux + /usr/lib/systemd/system).
pub const SOCKET_PATH: &str = "/run/netkeep/netkeep.sock";

/// Resolve the daemon socket path: explicit CLI arg > `NETKEEP_SOCKET_PATH`
/// env var > built-in default.
pub fn resolve_socket_path(explicit: Option<&str>) -> String {
    explicit
        .map(String::from)
        .or_else(|| std::env::var("NETKEEP_SOCKET_PATH").ok())
        .unwrap_or_else(|| SOCKET_PATH.to_string())
}

pub fn send_request(
    socket_path: &str,
    request: &ControlRequest,
) -> anyhow::Result<ControlResponse> {
    let stream = UnixStream::connect(socket_path)?;
    let mut writer = &stream;
    let payload = serde_json::to_string(&request)?;
    writer.write_all(format!("{payload}\n").as_bytes())?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response: ControlResponse = serde_json::from_str(line.trim_end())?;
    Ok(response)
}

/// Open a subscription to the daemon's notification channel. Sends
/// `ControlRequest::SubscribeToPending`, receives the ack, then keeps reading
/// newline-delimited `PushNotification` payloads and forwards them to the
/// channel. Returns an error if the socket connection or the ack fails.
pub fn subscribe_to_notifications(
    socket_path: &str,
    tx: Sender<PushNotification>,
) -> anyhow::Result<()> {
    let stream = UnixStream::connect(socket_path)?;

    let mut writer = &stream;
    let payload = serde_json::to_string(&ControlRequest::SubscribeToPending)?;
    writer.write_all(format!("{payload}\n").as_bytes())?;

    // Read the ack in blocking mode so we don't race the daemon's reply.
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response: ControlResponse = serde_json::from_str(line.trim_end())?;
    if !matches!(response, ControlResponse::SubscriptionAck) {
        return Err(anyhow::anyhow!(
            "unexpected subscription ack: {:?}",
            response
        ));
    }

    // Read with a short timeout instead of non-blocking polling: `read_line`
    // appends to `line`, so partial reads accumulate and are never dropped.
    stream.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;
    line.clear();
    loop {
        use std::io::ErrorKind;
        match reader.read_line(&mut line) {
            Ok(0) => return Ok(()), // socket closed
            Ok(_) => {
                if let Ok(notif) = serde_json::from_str(line.trim_end()) {
                    if tx.send(notif).is_err() {
                        return Ok(()); // viewer gone
                    }
                }
                line.clear();
            }
            Err(ref e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                // Keep any partial line buffered and try again.
                continue;
            }
            Err(e) => return Err(anyhow::anyhow!("subscription read error: {e}")),
        }
    }
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn fetch_pending(pending_id: &str) -> anyhow::Result<PendingDecision> {
    let socket_path =
        std::env::var("NETKEEP_SOCKET_PATH").unwrap_or_else(|_| SOCKET_PATH.to_string());

    match send_request(&socket_path, &ControlRequest::ListPending)? {
        ControlResponse::PendingList(mut items) => {
            items.sort_by_key(|p| p.deadline_at_secs);
            items
                .into_iter()
                .find(|p| p.id == pending_id)
                .ok_or_else(|| anyhow::anyhow!("pending decision '{pending_id}' not found"))
        }
        ControlResponse::Error(e) => Err(anyhow::anyhow!("daemon error: {e}")),
        other => Err(anyhow::anyhow!("unexpected response: {other:?}")),
    }
}

/// Return `(tun_ifaces, dev_ifaces)` by reading `/sys/class/net/`.
/// Used to populate the egress add-target selector.
pub fn list_net_interfaces() -> (Vec<String>, Vec<String>) {
    let mut tuns = Vec::new();
    let mut devs = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net/") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            let if_type: u32 = std::fs::read_to_string(format!("/sys/class/net/{name}/type"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(1);
            if if_type == 65534 {
                tuns.push(name);
            } else if if_type == 1
                && !name.starts_with("docker")
                && !name.starts_with("virbr")
                && !name.starts_with("br-")
            {
                devs.push(name);
            }
        }
    }
    tuns.sort();
    devs.sort();
    (tuns, devs)
}

/// Detect local network interfaces and return a list of default egress entries.
/// Always includes a "Default Route" entry (system routing table).
/// Interfaces whose operstate is "down" are marked as unavailable.
pub fn detect_egresses() -> Vec<core_types::Egress> {
    use core_types::{Egress, RouteTarget};

    let mut egresses = vec![Egress {
        id: "eg-default".to_string(),
        name: "Default Route".to_string(),
        color: "#6b7280".to_string(), // gray
        targets: vec![],
        dns_servers: vec![],
        is_system_default: true,
        is_available: true,
    }];

    // Read /sys/class/net/ to list interfaces
    if let Ok(entries) = std::fs::read_dir("/sys/class/net/") {
        let mut ifaces: Vec<(String, u32, String)> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            let if_type: u32 = std::fs::read_to_string(format!("/sys/class/net/{name}/type"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(1);
            let operstate = std::fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
                .unwrap_or_default()
                .trim()
                .to_string();
            ifaces.push((name, if_type, operstate));
        }

        for (name, if_type, operstate) in &ifaces {
            // "up" or "unknown" (TUN devices often report "unknown") = usable
            let is_up = operstate == "up" || operstate == "unknown";

            // type 65534 = ARPHRD_NONE (TUN/TAP device)
            if *if_type == 65534 {
                egresses.push(Egress {
                    id: format!("eg-{name}"),
                    name: format!("TUN: {name}"),
                    color: "#22c55e".to_string(), // green
                    targets: vec![RouteTarget::Tun(name.clone())],
                    dns_servers: vec![],
                    is_system_default: false,
                    is_available: is_up,
                });
            }
            // type 1 = Ethernet (physical NICs and bridges)
            // Skip known virtual bridges
            else if *if_type == 1
                && !name.starts_with("docker")
                && !name.starts_with("virbr")
                && !name.starts_with("br-")
            {
                let is_wireless = name.starts_with("wl") || name.starts_with("wlp");
                let label = if is_wireless {
                    format!("Wi-Fi: {name}")
                } else {
                    format!("LAN: {name}")
                };
                egresses.push(Egress {
                    id: format!("eg-{name}"),
                    name: label,
                    color: "#3b82f6".to_string(), // blue
                    targets: vec![RouteTarget::Device(name.clone())],
                    dns_servers: vec![],
                    is_system_default: false,
                    is_available: is_up,
                });
            }
        }
    }

    egresses
}

/// Fetch all egresses from the daemon and merge interface availability from the local system.
/// Falls back to `detect_egresses()` if the daemon is unreachable.
pub fn fetch_egresses() -> Vec<Egress> {
    let socket_path =
        std::env::var("NETKEEP_SOCKET_PATH").unwrap_or_else(|_| SOCKET_PATH.to_string());

    match send_request(&socket_path, &ControlRequest::ListEgresses) {
        Ok(ControlResponse::EgressList(egresses)) => merge_egress_availability(egresses),
        _ => detect_egresses(),
    }
}

/// Refresh `is_available` from a local interface scan; keeps daemon-persisted names, targets, and DNS.
pub fn merge_egress_availability(mut stored: Vec<Egress>) -> Vec<Egress> {
    let detected = detect_egresses();
    let by_id: HashMap<String, bool> = detected
        .into_iter()
        .map(|e| (e.id.clone(), e.is_available))
        .collect();
    for e in &mut stored {
        if let Some(av) = by_id.get(&e.id) {
            e.is_available = *av;
        }
    }
    stored
}

/// Get current NFQUEUE status from daemon.
pub fn get_nfqueue_status() -> anyhow::Result<(bool, Option<u16>)> {
    let socket_path =
        std::env::var("NETKEEP_SOCKET_PATH").unwrap_or_else(|_| SOCKET_PATH.to_string());

    match send_request(&socket_path, &ControlRequest::Health)? {
        ControlResponse::Health {
            nfqueue_enabled,
            nfqueue_num,
            ..
        } => Ok((nfqueue_enabled, nfqueue_num)),
        ControlResponse::Error(e) => Err(anyhow::anyhow!("daemon error: {e}")),
        other => Err(anyhow::anyhow!("unexpected response: {other:?}")),
    }
}

/// Toggle NFQUEUE on or off.
pub fn set_nfqueue_enabled(enabled: bool) -> anyhow::Result<()> {
    let socket_path =
        std::env::var("NETKEEP_SOCKET_PATH").unwrap_or_else(|_| SOCKET_PATH.to_string());

    match send_request(&socket_path, &ControlRequest::SetNfqueueEnabled { enabled })? {
        ControlResponse::Ok => Ok(()),
        ControlResponse::Error(e) => Err(anyhow::anyhow!("daemon error: {e}")),
        other => Err(anyhow::anyhow!("unexpected response: {other:?}")),
    }
}
