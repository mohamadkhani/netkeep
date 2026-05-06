use std::time::Duration;

use gpui::{App, AppContext as _, Entity};
use control_api::{ControlRequest, ControlResponse};

use crate::daemon::{self, SOCKET_PATH};
use crate::state::AppState;

pub fn start_polling(state: Entity<AppState>, cx: &mut App) {
    cx.spawn(async move |cx| {
        loop {
            let result = cx
                .background_executor()
                .spawn(async move {
                    daemon::send_request(SOCKET_PATH, &ControlRequest::ListPending)
                })
                .await;

            cx.update_entity(&state, |s, cx| {
                s.now_secs = daemon::unix_now();
                match result {
                    Ok(ControlResponse::PendingList(items)) => {
                        s.daemon_connected = true;
                        let mut items = items;
                        items.sort_by_key(|p| p.deadline_at_secs);
                        let has_items = !items.is_empty();
                        s.pending = items;
                        if has_items {
                            s.should_show_window = true;
                        } else {
                            s.should_show_window = false;
                        }
                    }
                    _ => {
                        s.daemon_connected = false;
                    }
                }
                cx.notify();
            })
            .ok();

            cx.background_executor()
                .timer(Duration::from_secs(1))
                .await;
        }
    })
    .detach();
}
