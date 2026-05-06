use core_types::PendingDecision;

pub struct AppState {
    pub pending: Vec<PendingDecision>,
    pub now_secs: u64,
    pub daemon_connected: bool,
    pub make_permanent: bool,
    pub should_show_window: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            now_secs: crate::daemon::unix_now(),
            daemon_connected: false,
            make_permanent: false,
            should_show_window: false,
        }
    }
}

pub enum ViewState {
    Connecting,
    Empty,
    HasDecision(PendingDecision),
}

impl AppState {
    pub fn view_state(&self) -> ViewState {
        if !self.should_show_window || !self.daemon_connected {
            ViewState::Connecting
        } else if self.pending.is_empty() {
            ViewState::Empty
        } else {
            ViewState::HasDecision(self.pending[0].clone())
        }
    }
}
