use core_types::{Egress, PendingDecision};

pub struct AppState {
    pub item: PendingDecision,
    pub now_secs: u64,
    pub make_permanent: bool,
    pub resolved: bool,
    pub pending_count: usize,
    pub egresses: Vec<Egress>,
    pub selected_egress_index: usize,
}
