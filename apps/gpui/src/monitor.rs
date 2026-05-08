use std::collections::HashSet;
use std::time::Duration;

use control_api::{ControlRequest, ControlResponse};

use crate::daemon;

const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Poll the daemon and spawn a decision window for each new pending flow.
pub fn poll_decision_spawner(socket_path: String, gui_command: String) {
    let mut shown_ids: HashSet<String> = HashSet::new();

    eprintln!("logiguard-gpui: pending poller, socket {socket_path}");

    loop {
        match daemon::send_request(&socket_path, &ControlRequest::ListPending) {
            Ok(ControlResponse::PendingList(items)) => {
                for item in &items {
                    if shown_ids.insert(item.id.clone()) {
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
                            }
                            Err(e) => {
                                eprintln!("failed to spawn GUI '{gui_command}': {e}");
                            }
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
