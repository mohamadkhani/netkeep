use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

use control_api::{ControlRequest, ControlResponse};
use control_service::{ControlService, HealthConfig, SharedService};
use decision_engine::{DecisionEngine, OverflowPolicy};
use enforcer::{NftablesBootstrap, SystemNftablesBootstrap};
use enforcer::nfqueue::NfqueueProcessor;
use flow_classifier::{
    FlowClassifier, FakeProcessResolver, FakeDnsResolver, FakeDeviceLabelResolver,
};
use state_store::SqliteRuleRepository;

const DEFAULT_SOCKET_PATH: &str = "/tmp/logiguard.sock";
const DEFAULT_DB_PATH: &str = "/tmp/logiguard.db";
const DEFAULT_TIMEOUT_SECS: u64 = 100;
const DEFAULT_PENDING_LIMIT: usize = 100;

fn parse_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default)
}

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
    let default_timeout_secs = parse_env_u64("LOGIGUARD_DEFAULT_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS);
    let tcp_timeout_secs = parse_env_u64("LOGIGUARD_TCP_TIMEOUT_SECS", default_timeout_secs);
    let udp_timeout_secs = parse_env_u64("LOGIGUARD_UDP_TIMEOUT_SECS", default_timeout_secs);
    let quic_timeout_secs = parse_env_u64("LOGIGUARD_QUIC_TIMEOUT_SECS", default_timeout_secs);
    let other_timeout_secs = parse_env_u64("LOGIGUARD_OTHER_TIMEOUT_SECS", default_timeout_secs);
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
    let decision_engine = DecisionEngine::new(
        DEFAULT_PENDING_LIMIT,
        default_timeout_secs,
        OverflowPolicy::DenyNew,
    )
    .with_protocol_timeouts(
        tcp_timeout_secs,
        udp_timeout_secs,
        quic_timeout_secs,
        other_timeout_secs,
    );
    let service = Arc::new(Mutex::new(ControlService::with_decision_engine_and_health(
        repo,
        decision_engine,
        HealthConfig {
            pending_limit: DEFAULT_PENDING_LIMIT,
            default_timeout_secs,
            tcp_timeout_secs,
            udp_timeout_secs,
            quic_timeout_secs,
            other_timeout_secs,
        },
    )));
    let health = {
        let mut svc = service.lock().expect("service lock must work");
        svc.handle(ControlRequest::Health)
    };
    println!(
        "daemon listening on {socket_path}, db={db_path}, timeouts(default={default_timeout_secs}, tcp={tcp_timeout_secs}, udp={udp_timeout_secs}, quic={quic_timeout_secs}, other={other_timeout_secs}) {health:?}"
    );

    // Optional NFQUEUE enforcement mode.
    // Set LOGIGUARD_NFQUEUE=<queue_num> (e.g. LOGIGUARD_NFQUEUE=0) to enable.
    // Requires root / CAP_NET_ADMIN.
    if let Ok(queue_str) = std::env::var("LOGIGUARD_NFQUEUE") {
        let queue_num: u16 = queue_str.trim().parse().unwrap_or(0);
        let bootstrap = SystemNftablesBootstrap;
        // The classifier uses no-op fakes for now; a real /proc resolver is Phase 3.
        let classifier = FlowClassifier::new(
            FakeProcessResolver { result: None },
            FakeDnsResolver { result: None },
            FakeDeviceLabelResolver { result: None },
        );
        let registrar = SharedService(Arc::clone(&service));
        let thread_result = NfqueueProcessor::open(queue_num, classifier, registrar);
        match thread_result {
            Err(e) => eprintln!("nfqueue open failed (are you root?): {e}"),
            Ok(mut processor) => {
                if let Err(e) = bootstrap.setup(queue_num) {
                    eprintln!("nftables setup failed: {e}");
                } else {
                    println!("nftables rules applied, nfqueue processor running on queue {queue_num}");
                    std::thread::spawn(move || {
                        if let Err(e) = processor.run_loop() {
                            eprintln!("nfqueue processor stopped: {e}");
                        }
                    });
                }
            }
        }
    }

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

