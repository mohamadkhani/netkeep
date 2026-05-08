use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use control_api::{ControlRequest, ControlResponse};
use core_types::{Egress, PendingDecision};

pub const SOCKET_PATH: &str = "/tmp/logiguard.sock";

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

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn fetch_pending(pending_id: &str) -> anyhow::Result<PendingDecision> {
    let socket_path = std::env::var("LOGIGUARD_SOCKET_PATH")
        .unwrap_or_else(|_| SOCKET_PATH.to_string());

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
            else if *if_type == 1 && !name.starts_with("docker") && !name.starts_with("virbr") && !name.starts_with("br-") {
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

/// Refresh `is_available` from a local interface scan; keeps daemon-persisted names, targets, and DNS.
pub fn merge_egress_availability(mut stored: Vec<Egress>) -> Vec<Egress> {
    let detected = detect_egresses();
    let by_id: HashMap<String, bool> =
        detected.into_iter().map(|e| (e.id.clone(), e.is_available)).collect();
    for e in &mut stored {
        if let Some(av) = by_id.get(&e.id) {
            e.is_available = *av;
        }
    }
    stored
}
