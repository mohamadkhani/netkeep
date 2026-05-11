use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use control_api::{ControlRequest, ControlResponse};

use crate::daemon;

const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Global flag to prevent multiple decision windows from opening.
static DECISION_WINDOW_OPEN: AtomicBool = AtomicBool::new(false);

/// Poll the daemon and spawn a decision window for each new pending flow.
/// Only one decision window is allowed at a time to prevent user confusion.
pub fn poll_decision_spawner(socket_path: String, gui_command: String) {
    let mut shown_ids: HashSet<String> = HashSet::new();

    eprintln!("logiguard-gpui: pending poller, socket {socket_path}");

    loop {
        match daemon::send_request(&socket_path, &ControlRequest::ListPending) {
            Ok(ControlResponse::PendingList(items)) => {
                for item in &items {
                    if shown_ids.insert(item.id.clone()) {
                        // Only spawn if no decision window is currently open
                        if !DECISION_WINDOW_OPEN.load(Ordering::Relaxed) {
                            eprintln!(
                                "new pending: {} ({})",
                                item.id,
                                item.flow.process_name.as_deref().unwrap_or("unknown")
                            );
                            match std::process::Command::new(&gui_command)
                                .arg("--pending-id")
                                .arg(&item.id)
                                .env("LOGIGUARD_SOCKET_PATH", &socket_path)
                                .spawn()
                            {
                                Ok(child) => {
                                    eprintln!("spawned GUI for {} (pid {})", item.id, child.id());
                                    DECISION_WINDOW_OPEN.store(true, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    eprintln!("failed to spawn GUI '{gui_command}': {e}");
                                }
                            }
                        } else {
                            eprintln!(
                                "decision window already open, deferring pending {}",
                                item.id
                            );
                        }
                    }
                }
                let live: HashSet<String> = items.iter().map(|i| i.id.clone()).collect();
                shown_ids.retain(|id| live.contains(id));
            }
            Ok(_) => eprintln!("unexpected response from daemon"),
            Err(e) => eprintln!("poll error: {e}"),
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Mark the decision window as closed (called when window exits).
pub fn decision_window_closed() {
    DECISION_WINDOW_OPEN.store(false, Ordering::Relaxed);
}
