use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use control_api::{ControlRequest, ControlResponse};
use core_types::PendingDecision;

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
