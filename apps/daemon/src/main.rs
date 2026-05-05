use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

use control_api::{ControlRequest, ControlResponse};
use control_service::ControlService;
use state_store::SqliteRuleRepository;

const DEFAULT_SOCKET_PATH: &str = "/tmp/logiguard.sock";
const DEFAULT_DB_PATH: &str = "/tmp/logiguard.db";

fn handle_client(
    stream: UnixStream,
    service: &Arc<Mutex<ControlService<SqliteRuleRepository>>>,
) -> Result<(), String> {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if bytes == 0 {
        return Err("empty request".to_string());
    }
    let request: ControlRequest = serde_json::from_str(line.trim_end()).map_err(|e| e.to_string())?;
    let response = {
        let mut svc = service.lock().map_err(|_| "service lock poisoned".to_string())?;
        svc.handle(request)
    };
    let mut writer = &stream;
    let payload = serde_json::to_string(&response).map_err(|e| e.to_string())?;
    writer
        .write_all(format!("{payload}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    let socket_path =
        std::env::var("LOGIGUARD_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
    let db_path = std::env::var("LOGIGUARD_DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.to_string());
    let _ = fs::remove_file(&socket_path);
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("failed to bind socket at {socket_path}: {err}");
            std::process::exit(1);
        }
    };

    let repo = match SqliteRuleRepository::open(&db_path) {
        Ok(repo) => repo,
        Err(err) => {
            eprintln!("failed to open sqlite db at {db_path}: {err}");
            std::process::exit(1);
        }
    };
    let service = Arc::new(Mutex::new(ControlService::new(repo)));
    let health = {
        let mut svc = service.lock().expect("service lock must work");
        svc.handle(ControlRequest::Health)
    };
    println!("daemon listening on {socket_path}, db={db_path} {health:?}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle_client(stream, &service) {
                    let fallback = ControlResponse::Error(err.clone());
                    let _ = serde_json::to_string(&fallback);
                    eprintln!("request handling error: {err}");
                }
            }
            Err(err) => {
                eprintln!("incoming socket error: {err}");
            }
        }
    }
}

