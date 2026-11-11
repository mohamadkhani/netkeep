use control_api::ControlResponse;
use serde::Serialize;
use std::io::Write;
use std::os::unix::net::UnixStream;

/// Errors from talking to the netkeep daemon over the Unix socket.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("connection to daemon failed")]
    Connection,
    #[error("daemon protocol error: {0}")]
    Protocol(String),
}

/// Send a request to the daemon and deserialize its response.
pub fn send_request<T>(socket: &str, request: T) -> Result<ControlResponse, DaemonError>
where
    T: Serialize,
{
    let mut stream = connect(socket)?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| DaemonError::Protocol(format!("set write timeout: {e}")))?;

    let mut body = serde_json::to_vec(&request)
        .map_err(|e| DaemonError::Protocol(format!("serialize request: {e}")))?;
    body.push(b'\n');

    stream
        .write_all(&body)
        .map_err(|_| DaemonError::Connection)?;
    stream.flush().map_err(|_| DaemonError::Connection)?;

    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    use std::io::BufRead;
    reader
        .read_line(&mut line)
        .map_err(|_| DaemonError::Connection)?;

    serde_json::from_str(&line).map_err(|e| DaemonError::Protocol(format!("parse response: {e}")))
}

/// Open a Unix stream to the daemon.
fn connect(socket: &str) -> Result<UnixStream, DaemonError> {
    let stream = UnixStream::connect(socket).map_err(|_| DaemonError::Connection)?;
    Ok(stream)
}
