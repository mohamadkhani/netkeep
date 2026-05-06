use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use control_api::{ControlRequest, ControlResponse, PushNotification};
use control_service::{ControlService, HealthConfig, SharedService};
use decision_engine::{DecisionEngine, OverflowPolicy};
use enforcer::{NftablesBootstrap, SystemNftablesBootstrap};
use enforcer::nfqueue::NfqueueProcessor;
use flow_classifier::{
    FlowClassifier, FakeProcessResolver, FakeDnsResolver, FakeDeviceLabelResolver,
};
use state_store::{PendingRepository, RuleRepository, SqliteRuleRepository};
use tokio::sync::broadcast;

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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns true if the process `peer_pid` has stdin on a physical console
/// (/dev/tty[0-9]* or /dev/console), not a pseudo-terminal (/dev/pts/*).
fn is_physical_console(peer_pid: i32) -> bool {
    match fs::read_link(format!("/proc/{}/fd/0", peer_pid)) {
        Ok(target) => {
            let s = target.to_string_lossy();
            (s.starts_with("/dev/tty") && !s.starts_with("/dev/pts"))
                || s == "/dev/console"
        }
        Err(_) => false,
    }
}

fn peer_pid(stream: &UnixStream) -> Option<i32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 { Some(cred.pid) } else { None }
}

fn handle_client(
    stream: UnixStream,
    service: &Arc<Mutex<ControlService<SqliteRuleRepository>>>,
    bootstrap: Option<&dyn NftablesBootstrap>,
    notification_tx: &broadcast::Sender<PushNotification>,
) -> Result<(), String> {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if bytes == 0 {
        return Err("empty request".to_string());
    }
    let request: ControlRequest =
        serde_json::from_str(line.trim_end()).map_err(|e| e.to_string())?;

    let is_subscribe = matches!(request, ControlRequest::SubscribeToPending);

    let response = if matches!(request, ControlRequest::Unlock) {
        let on_console = peer_pid(&stream).map(is_physical_console).unwrap_or(false);
        if !on_console {
            ControlResponse::Error(
                "unlock rejected: must be run from a physical console (not SSH or pty)".to_string(),
            )
        } else if let Some(bs) = bootstrap {
            match bs.teardown() {
                Ok(()) => ControlResponse::Unlocked,
                Err(e) => ControlResponse::Error(format!("nftables teardown failed: {e}")),
            }
        } else {
            // No nftables active — nothing to tear down.
            ControlResponse::Unlocked
        }
    } else {
        let mut svc = service.lock().map_err(|_| "service lock poisoned".to_string())?;
        svc.handle(request)
    };

    let mut writer = &stream;
    let payload = serde_json::to_string(&response).map_err(|e| e.to_string())?;
    writer
        .write_all(format!("{payload}\n").as_bytes())
        .map_err(|e| e.to_string())?;

    // If client requested subscription, spawn a thread to push notifications.
    if is_subscribe {
        let stream_clone = stream.try_clone().map_err(|e| e.to_string())?;
        let mut rx = notification_tx.subscribe();
        std::thread::spawn(move || {
            let mut writer = &stream_clone;
            loop {
                match rx.try_recv() {
                    Ok(notif) => {
                        if let Ok(payload) = serde_json::to_string(&notif) {
                            let _ = writer.write_all(format!("{payload}\n").as_bytes());
                        }
                    }
                    Err(broadcast::error::TryRecvError::Lagged(_)) => {
                        // Buffer full, skip this message
                    }
                    Err(broadcast::error::TryRecvError::Empty) => {
                        // No message available, sleep briefly
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(broadcast::error::TryRecvError::Closed) => {
                        // Broadcast channel closed, exit
                        break;
                    }
                }
            }
        });
    }

    Ok(())
}

fn main() {
    let socket_path =
        std::env::var("LOGIGUARD_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
    let db_path =
        std::env::var("LOGIGUARD_DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.to_string());
    let default_timeout_secs =
        parse_env_u64("LOGIGUARD_DEFAULT_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS);
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

    let mut repo = match SqliteRuleRepository::open(&db_path) {
        Ok(repo) => repo,
        Err(err) => {
            eprintln!("failed to open sqlite db at {db_path}: {err}");
            std::process::exit(1);
        }
    };

    // Bug 2: delete all UntilRestart rules on every startup.
    repo.purge_session_rules();

    let startup_now = now_secs();

    // Bug 5: restore pending decisions that haven't expired.
    let live_pending = repo.list_live_pending(startup_now);

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

    // NEW: Create broadcast channel for push notifications (buffer 500 messages)
    let (notification_tx, _) = tokio::sync::broadcast::channel(500);

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
        notification_tx.clone(),  // Pass sender to service
    )));

    {
        let mut svc = service.lock().expect("service lock");
        svc.restore_pending(live_pending);
    }

    let health = {
        let mut svc = service.lock().expect("service lock");
        svc.handle(ControlRequest::Health)
    };
    println!(
        "daemon listening on {socket_path}, db={db_path}, \
         timeouts(default={default_timeout_secs}, tcp={tcp_timeout_secs}, \
         udp={udp_timeout_secs}, quic={quic_timeout_secs}, \
         other={other_timeout_secs}) {health:?}"
    );

    // Bug 1: tick every second so expired pending decisions are cleaned up.
    let service_for_timer = Arc::clone(&service);
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(mut svc) = service_for_timer.lock() {
            svc.tick(now_secs());
        }
    });

    // Optional NFQUEUE enforcement (set LOGIGUARD_NFQUEUE=<queue_num>).
    let bootstrap: Option<Arc<dyn NftablesBootstrap>> =
        if let Ok(queue_str) = std::env::var("LOGIGUARD_NFQUEUE") {
            let queue_num: u16 = queue_str.trim().parse().unwrap_or(0);
            let bs: Arc<dyn NftablesBootstrap> = Arc::new(SystemNftablesBootstrap);
            let classifier = FlowClassifier::new(
                FakeProcessResolver { result: None },
                FakeDnsResolver { result: None },
                FakeDeviceLabelResolver { result: None },
            );
            let registrar = SharedService(Arc::clone(&service));
            match NfqueueProcessor::open(queue_num, classifier, registrar) {
                Err(e) => {
                    eprintln!("nfqueue open failed (are you root?): {e}");
                    None
                }
                Ok(mut processor) => {
                    if let Err(e) = bs.setup(queue_num) {
                        eprintln!("nftables setup failed: {e}");
                        None
                    } else {
                        println!(
                            "nftables rules applied, nfqueue processor on queue {queue_num}"
                        );
                        std::thread::spawn(move || {
                            if let Err(e) = processor.run_loop() {
                                eprintln!("nfqueue processor stopped: {e}");
                            }
                        });
                        Some(bs)
                    }
                }
            }
        } else {
            None
        };

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let bs_ref = bootstrap.as_deref();
                if let Err(err) = handle_client(stream, &service, bs_ref, &notification_tx) {
                    eprintln!("request handling error: {err}");
                }
            }
            Err(err) => {
                eprintln!("incoming socket error: {err}");
            }
        }
    }
}
