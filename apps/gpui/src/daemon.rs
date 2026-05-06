use std::io::{BufRead, BufReader, Write as IoWrite};
use std::os::unix::net::UnixStream;
use std::time::{SystemTime, UNIX_EPOCH};

use control_api::{ControlRequest, ControlResponse};

pub const SOCKET_PATH: &str = "/tmp/logiguard.sock";

pub fn send_request(path: &str, req: &ControlRequest) -> Result<ControlResponse, String> {
    let mut stream =
        UnixStream::connect(path).map_err(|e| format!("connect failed: {e}"))?;
    let payload = serde_json::to_string(req).map_err(|e| e.to_string())?;
    stream
        .write_all(format!("{payload}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if line.trim().is_empty() {
        return Err("empty response from daemon".into());
    }
    serde_json::from_str(line.trim_end()).map_err(|e| e.to_string())
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
