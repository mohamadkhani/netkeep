//! Real-time log viewer (`netkeep-gpui --log-viewer`).
//!
//! Subscribes to the daemon's notification channel over the Unix socket and
//! displays every event in a grouped log pane:
//!   * pending-created / pending-resolved / pending-expired
//!   * policy-match (immediate allow/deny/route)
//!
//! Rows are grouped by a key `(process_name, destination_ip:port)` so repeated
//! activity from the same app→destination pair collapses into a single record.
//! When that pair fires many times in quick succession the row flashes: a small
//! colored pulse on the left edge plus a repeated-event badge.
//!
//! Controls (top toolbar):
//!   * search — space-separated terms matched against process, destination, ID
//!   * action filter — Allow / Deny / Ask / Route / Any
//!   * group toggle — deduplicate by domain (default) or by IP
//!   * group by process — render rows under per-process section headers
//!     (GUI-only grouping; no rows are merged). Sections start folded.
//!
//! Deduplication is applied when rendering, so toggling the mode immediately
//! collapses or expands rows already on screen without losing any events.
//! Newest activity is always at the top.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use control_api::PushNotification;
use gpui::prelude::FluentBuilder as _;
use gpui::{
    div, px, AnyView, AppContext as _, Context, ElementId, Entity, EventEmitter, FontWeight,
    InteractiveElement, IntoElement, ParentElement, Render, StatefulInteractiveElement, Styled,
    Window,
};
use gpui_component::h_flex;
use gpui_component::input::{Input, InputState};
use gpui_component::label::Label;
use gpui_component::select::Select;
use gpui_component::select::SelectState;
use gpui_component::switch::Switch;
use gpui_component::v_flex;
use gpui_component::TitleBar;

use crate::colors;
use crate::components::badge;
use crate::daemon;

const MAX_ROWS: usize = 500;
const FLASH_WINDOW_SECS: u64 = 10;

/// Filter state for the log viewer toolbar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogFilter {
    pub search: String,
    pub action: Option<ActionFilter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionFilter {
    Allow,
    Deny,
    Ask,
    Route,
}

impl ActionFilter {
    fn from_rule_action(a: &core_types::RuleAction) -> Self {
        match a {
            core_types::RuleAction::Allow => ActionFilter::Allow,
            core_types::RuleAction::Deny => ActionFilter::Deny,
            core_types::RuleAction::Ask => ActionFilter::Ask,
            core_types::RuleAction::Route => ActionFilter::Route,
        }
    }
}

/// A single line displayed in the log pane.
#[derive(Clone)]
struct LogRow {
    event_type: &'static str,
    timestamp_secs: u64,
    process_name: Option<String>,
    destination_ip: String,
    destination_port: u16,
    destination_domain: Option<String>,
    /// Rule that decided this connection; clicking the row opens the Rules
    /// tab filtered to it. `None` for pending-lifecycle events.
    rule_id: Option<String>,
    action: Option<core_types::RuleAction>,
    /// The pending_id of a pending-decision row, if any.
    pending_id: Option<String>,
    /// Egress referenced by the deciding rule, rendered as `via <name>`.
    egress_id: Option<String>,
    /// Display name for `egress_id`, preferred over the id when present.
    egress_name: Option<String>,
    occurrences: usize,
    last_occurrence: Instant,
    flash_since: Option<Instant>,
}

impl LogRow {
    fn new(
        process_name: Option<String>,
        destination_ip: String,
        destination_port: u16,
        destination_domain: Option<String>,
        event_type: &'static str,
        now: u64,
        pending_id: Option<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp_secs: now,
            process_name,
            destination_ip,
            destination_port,
            destination_domain,
            rule_id: None,
            action: None,
            pending_id,
            egress_id: None,
            egress_name: None,
            occurrences: 1,
            last_occurrence: Instant::now(),
            flash_since: None,
        }
    }

    /// Merges a repeated event into this row. Returns true if the flash
    /// threshold was crossed by this merge.
    fn merge(&mut self, now: u64) -> bool {
        self.occurrences += 1;
        self.timestamp_secs = now;
        let just_flashed = self.flash_since.is_none();
        if self.last_occurrence.elapsed().as_secs() <= FLASH_WINDOW_SECS {
            self.flash_since = Some(Instant::now());
        }
        just_flashed
    }

    /// Upgrade a pending-created row with the decision that closed it.
    fn resolve(
        &mut self,
        rule_id: String,
        action: core_types::RuleAction,
        egress_id: Option<String>,
        egress_name: Option<String>,
    ) {
        self.event_type = "resolved";
        self.rule_id = Some(rule_id);
        self.action = Some(action);
        self.egress_id = egress_id;
        self.egress_name = egress_name;
    }

    /// Returns true when this row passes the toolbar filter. Applied at render
    /// time (not on arrival) so changing the search text or action facet
    /// immediately re-filters rows that are already on screen.
    fn matches_filter(&self, filter: &LogFilter) -> bool {
        // Search: space-separated terms, AND semantics over process, IP/domain,
        // port, and rule/pending id.
        if !filter.search.is_empty() {
            let terms: Vec<String> = filter
                .search
                .to_lowercase()
                .split_whitespace()
                .map(str::to_string)
                .collect();
            let matches_term = |needle: &str| {
                self.process_name
                    .as_deref()
                    .is_some_and(|p| p.to_lowercase().contains(needle))
                    || self.destination_ip.to_lowercase().contains(needle)
                    || self
                        .destination_domain
                        .as_deref()
                        .is_some_and(|d| d.to_lowercase().contains(needle))
                    || self
                        .rule_id
                        .as_deref()
                        .is_some_and(|r| r.to_lowercase().contains(needle))
                    || self
                        .pending_id
                        .as_deref()
                        .is_some_and(|id| id.to_lowercase().contains(needle))
                    || self
                        .egress_id
                        .as_deref()
                        .is_some_and(|e| e.to_lowercase().contains(needle))
                    || self
                        .egress_name
                        .as_deref()
                        .is_some_and(|e| e.to_lowercase().contains(needle))
                    || self.destination_port.to_string().contains(needle)
            };
            if !terms.iter().all(|t| matches_term(t)) {
                return false;
            }
        }
        // Action facet. Only decided events carry an action: policy-match rows
        // and resolved pending decisions. Pending requests / expirations have
        // no outcome yet, so they are hidden whenever an action is selected.
        if let Some(a) = filter.action {
            match &self.action {
                Some(action) if ActionFilter::from_rule_action(action) == a => {}
                _ => return false,
            }
        }
        true
    }

    /// Destination label used when deduplicating by domain. Flows with no
    /// resolved domain fall back to their IP so they stay identifiable.
    fn domain_group(&self) -> String {
        match &self.destination_domain {
            Some(domain) => domain.clone(),
            None if self.destination_port == 0 => "(no domain)".to_string(),
            None => self.destination_ip.clone(),
        }
    }

    /// Key used to collapse duplicate events in the activity list.
    fn dedup_key(&self, group_by_domain: bool) -> (Option<String>, String, u16) {
        let destination = if group_by_domain {
            self.domain_group()
        } else {
            self.destination_ip.clone()
        };
        (
            self.process_name.clone(),
            destination,
            self.destination_port,
        )
    }
}

/// Window-scoped log state: the row list plus the toolbar controls.
pub struct LogViewer {
    /// Newest first, oldest last.
    rows: VecDeque<LogRow>,
    scroll: gpui::ScrollHandle,
    /// True while the pane is pinned to the newest row. Cleared when the
    /// user scrolls up; restored once they scroll back to the bottom.
    follow_bottom: bool,

    // Toolbar controls
    group_by_domain: bool,
    /// GUI-only grouping: render rows under per-process section headers.
    /// Unlike `group_by_domain` this never collapses rows.
    group_by_process: bool,
    /// Process sections the user unfolded. Sections are folded by default,
    /// so anything absent from this set renders collapsed. Keyed by process
    /// name (`None` is the "unknown" bucket).
    expanded_processes: HashSet<Option<String>>,
    filter: LogFilter,
    filter_search_input: Entity<InputState>,
    filter_action_select: Entity<SelectState<Vec<String>>>,
    _subscriptions: Vec<gpui::Subscription>,
}

impl LogViewer {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let filter_search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("Search process, destination…"));
        let filter_action_select = cx.new(|cx| {
            SelectState::new(
                vec![
                    "Any".into(),
                    "Allow".into(),
                    "Deny".into(),
                    "Ask".into(),
                    "Route".into(),
                ],
                None,
                window,
                cx,
            )
        });

        // Live filtering on every keystroke → mirror text into filter state.
        let mut subscriptions = Vec::new();
        subscriptions.push(cx.subscribe(&filter_search_input, |this, _, event, cx| {
            if let gpui_component::input::InputEvent::Change = event {
                let text = this.filter_search_input.read(cx).value().to_string();
                this.filter.search = text;
                cx.notify();
            }
        }));

        // Action select confirmation → live filter.
        subscriptions.push(cx.subscribe(
            &filter_action_select,
            |this, _, event: &gpui_component::select::SelectEvent<Vec<String>>, cx| {
                if let gpui_component::select::SelectEvent::Confirm(Some(label)) = event {
                    let label = label.clone();
                    this.filter.action = match label.as_str() {
                        "Allow" => Some(ActionFilter::Allow),
                        "Deny" => Some(ActionFilter::Deny),
                        "Ask" => Some(ActionFilter::Ask),
                        "Route" => Some(ActionFilter::Route),
                        _ => None,
                    };
                    cx.notify();
                }
            },
        ));

        Self {
            rows: VecDeque::new(),
            scroll: gpui::ScrollHandle::new(),
            follow_bottom: true,
            group_by_domain: true,
            group_by_process: false,
            expanded_processes: HashSet::new(),
            filter: LogFilter::default(),
            filter_search_input,
            filter_action_select,
            _subscriptions: subscriptions,
        }
    }

    /// Append a notification arriving from the subscriber thread. Public so
    /// the owner of the subscription (main.rs) can pump events into the view.
    pub fn push_notification(&mut self, notif: PushNotification, cx: &mut Context<Self>) {
        self.append_notification(notif, cx);
    }

    /// Called from the async subscriber loop whenever a notification arrives.
    pub fn append_notification(&mut self, notif: PushNotification, cx: &mut Context<Self>) {
        let now = daemon::unix_now();
        // Rows always dedup on (process, IP, port) as events arrive. Domain
        // grouping is a render-time view (see `render`), which keeps the
        // toggle lossless and immediately reversible.
        let group_key = notif.group_key();

        // All notifications are retained; the toolbar filter is applied when
        // rendering so it can be changed without losing history.
        let row = match &notif {
            PushNotification::PendingCreated { decision } => LogRow::new(
                decision.flow.process_name.clone(),
                decision.flow.destination_ip.clone(),
                decision.flow.destination_port,
                decision.flow.destination_domain.clone(),
                "pending-created",
                now,
                Some(decision.id.clone()),
            ),
            PushNotification::PendingResolved {
                pending_id,
                action,
                egress_id,
                egress_name,
            } => {
                // Try to upgrade a matching pending-created row so the
                // decision appears on the request row itself.
                let pending_id = pending_id.clone();
                let action = action.clone();
                let egress_id = egress_id.clone();
                let egress_name = egress_name.clone();
                let mut r = LogRow::new(
                    None,
                    pending_id.clone(),
                    0,
                    None,
                    "pending-resolved",
                    now,
                    None,
                );
                r.egress_id = egress_id.clone();
                r.egress_name = egress_name.clone();
                if let Some(pos) = self
                    .rows
                    .iter()
                    .position(|row| row.pending_id.as_deref() == Some(&pending_id))
                {
                    let mut existing = self.rows.remove(pos).expect("position valid");
                    existing.resolve(
                        self.generate_resolved_rule_id(&pending_id),
                        action,
                        egress_id,
                        egress_name,
                    );
                    self.rows.push_front(existing);
                    if !self.follow_bottom {
                        cx.notify();
                    }
                    return;
                }
                r
            }
            PushNotification::PendingExpired { pending_id } => {
                // Also upgrade any matching pending row with an expiry note.
                let pending_id = pending_id.clone();
                if let Some(pos) = self
                    .rows
                    .iter()
                    .position(|row| row.pending_id.as_deref() == Some(&pending_id))
                {
                    let mut existing = self.rows.remove(pos).expect("position valid");
                    existing.event_type = "expired";
                    self.rows.push_front(existing);
                    if !self.follow_bottom {
                        cx.notify();
                    }
                    return;
                }
                LogRow::new(None, pending_id, 0, None, "pending-expired", now, None)
            }
            PushNotification::PolicyMatch {
                process_name,
                destination_ip,
                destination_port,
                destination_domain,
                rule_id,
                action,
                egress_id,
                egress_name,
            } => {
                let mut r = LogRow::new(
                    process_name.clone(),
                    destination_ip.clone(),
                    *destination_port,
                    destination_domain.clone(),
                    "policy-match",
                    now,
                    None,
                );
                r.rule_id = Some(rule_id.clone());
                r.action = Some(action.clone());
                r.egress_id = egress_id.clone();
                r.egress_name = egress_name.clone();
                r
            }
        };

        // Grouped rows are kept in newest-first order (FIFO = newest front),
        // so the top of the pane is always the most recent activity.
        if let Some(pos) = self
            .rows
            .iter()
            .position(|r| r.dedup_key(false) == group_key)
        {
            let mut existing = self.rows.remove(pos).expect("position valid");
            existing.merge(now);
            // Keep the egress current when a later event carries one.
            if row.egress_id.is_some() {
                existing.egress_id = row.egress_id.clone();
                existing.egress_name = row.egress_name.clone();
            }
            self.rows.push_front(existing);
            if self.follow_bottom {
                self.scroll.scroll_to_bottom();
            }
            cx.notify();
            return;
        }
        while self.rows.len() >= MAX_ROWS {
            self.rows.pop_back();
        }
        self.rows.push_front(row);
        if self.follow_bottom {
            self.scroll.scroll_to_bottom();
        }
        cx.notify();
    }

    /// Derive a stable "rule" label for resolved rows so the Rules-tab click
    /// route stays consistent: `<pending_id>:resolved`.
    fn generate_resolved_rule_id(&self, pending_id: &str) -> String {
        format!("pending-{}:resolved", pending_id)
    }

    /// Clear all rows, the filter state, and the toolbar controls. Used by the
    /// toolbar Clear button.
    pub fn clear_from_click(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.rows.clear();
        self.filter.search.clear();
        self.filter.action = None;
        self.expanded_processes.clear();
        let search_input = self.filter_search_input.clone();
        search_input.update(cx, |input, cx| input.set_value("", window, cx));
        let action_select = self.filter_action_select.clone();
        action_select.update(cx, |select, cx| select.set_selected_index(None, window, cx));
        cx.notify();
    }

    /// Called from render when the user scrolls away from / back to the
    /// newest row. Keeps `follow_bottom` in sync with the visible position.
    fn update_follow(&mut self) {
        let offset = self.scroll.offset().y;
        let max = self.scroll.max_offset().y;
        // Within a few pixels of the bottom counts as "at bottom".
        let at_bottom = max - offset <= px(4.);
        if at_bottom && !self.follow_bottom {
            self.follow_bottom = true;
        } else if !at_bottom && self.follow_bottom {
            self.follow_bottom = false;
        }
    }
}

impl EventEmitter<OpenRuleFilter> for LogViewer {}

impl Render for LogViewer {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.update_follow();
        let weak = cx.entity().downgrade();

        let filter_search_input = self.filter_search_input.clone();
        let filter_action_select = self.filter_action_select.clone();

        // --- Header toolbar ---
        let weak_clear = weak.clone();
        let clear_btn = div()
            .id("clear-log")
            .text_size(px(10.))
            .text_color(colors::muted())
            .cursor_pointer()
            .px(px(6.))
            .py(px(2.))
            .border_1()
            .border_color(colors::muted())
            .rounded(px(3.))
            .child("Clear")
            .on_click(move |_, window, cx| {
                if let Some(this) = weak_clear.upgrade() {
                    cx.update_entity(&this, |s, cx| s.clear_from_click(window, cx));
                }
            });

        let search_input = Input::new(&filter_search_input).h(px(26.)).w(px(210.));

        let action_select = div()
            .w(px(96.))
            .h(px(26.))
            .child(Select::new(&filter_action_select).placeholder("Action"));

        let group_toggle = Switch::new("group-toggle")
            .checked(self.group_by_domain)
            .label("Group By Domain")
            .on_click({
                let weak = weak.clone();
                move |checked, _, cx| {
                    if let Some(this) = weak.upgrade() {
                        let checked = *checked;
                        cx.update_entity(&this, |s, cx| {
                            s.group_by_domain = checked;
                            cx.notify();
                        });
                    }
                }
            });

        let process_toggle = Switch::new("group-process-toggle")
            .checked(self.group_by_process)
            .label("Group By Process")
            .on_click({
                let weak = weak.clone();
                move |checked, _, cx| {
                    if let Some(this) = weak.upgrade() {
                        let checked = *checked;
                        cx.update_entity(&this, |s, cx| {
                            s.group_by_process = checked;
                            // Every section starts folded each time the
                            // grouping is turned on.
                            if checked {
                                s.expanded_processes.clear();
                            }
                            cx.notify();
                        });
                    }
                }
            });

        let filtered: Vec<&LogRow> = self
            .rows
            .iter()
            .filter(|row| row.matches_filter(&self.filter))
            .collect();

        // Collapse duplicates using the active key. Rows stay stored per
        // (process, IP, port), so switching modes only changes this view —
        // no events are discarded.
        let visible: Vec<LogRow> = if self.group_by_domain {
            let mut collapsed: Vec<LogRow> = Vec::new();
            for row in filtered {
                let key = row.dedup_key(true);
                match collapsed
                    .iter_mut()
                    .find(|existing| existing.dedup_key(true) == key)
                {
                    // Keep the newest row's details (it is encountered first)
                    // and accumulate how many events the group represents.
                    Some(existing) => existing.occurrences += row.occurrences,
                    None => collapsed.push(row.clone()),
                }
            }
            collapsed
        } else {
            filtered.into_iter().cloned().collect()
        };

        let count_unit = if self.group_by_domain {
            "groups"
        } else {
            "items"
        };
        let count_label = Label::new(format!("{} {}", visible.len(), count_unit))
            .text_size(px(10.))
            .text_color(colors::muted())
            .ml(px(4.));

        let header = h_flex()
            .w_full()
            .flex_shrink_0()
            .h(px(38.))
            .px(px(12.))
            .bg(colors::surface_container_high())
            .border_b_1()
            .border_color(colors::border())
            .items_center()
            .gap(px(8.))
            .child(
                div()
                    .flex_1()
                    .text_size(px(12.))
                    .text_color(colors::text())
                    .child("Activity"),
            )
            .child(search_input)
            .child(action_select)
            .child(group_toggle)
            .child(process_toggle)
            .child(count_label)
            .child(clear_btn);

        let viewer = cx.entity();
        let rows: Vec<gpui::AnyElement> = if self.group_by_process {
            render_process_groups(
                visible,
                self.group_by_domain,
                &self.expanded_processes,
                viewer,
            )
        } else {
            visible
                .iter()
                .map(|row| render_row(row, self.group_by_domain, viewer.clone()))
                .collect()
        };

        let pane = div()
            .id("log-scroll")
            .flex_1()
            .size_full()
            .overflow_y_scroll()
            .track_scroll(&self.scroll)
            .child(v_flex().w_full().children(rows));

        let scroll_area = h_flex()
            .flex_1()
            .size_full()
            .relative()
            .child(pane)
            .child(gpui_component::scroll::Scrollbar::vertical(&self.scroll));

        v_flex()
            .size_full()
            .bg(colors::surface_container())
            .border_1()
            .border_color(colors::border())
            // Title bar with drag and window controls, matching Settings.
            .child(
                TitleBar::new()
                    .on_close_window(|_, window, _| {
                        window.remove_window();
                    })
                    .child(
                        h_flex()
                            .items_center()
                            .gap(px(8.))
                            .child(
                                div()
                                    .text_size(px(14.))
                                    .text_color(colors::primary())
                                    .child("📋"),
                            )
                            .child(
                                div()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_size(px(13.))
                                    .child("Activity Log"),
                            ),
                    ),
            )
            .child(header)
            .child(scroll_area)
            .into_any_element()
    }
}

/// Window root view for the log viewer. A thin wrapper around `LogViewer`
/// whose only purpose is to give the window a distinguishable root type, so
/// the tray handler can find (and raise) an already-open viewer instead of
/// opening a duplicate.
pub struct LogViewerRoot {
    viewer: Entity<LogViewer>,
}

impl LogViewerRoot {
    pub fn new(viewer: Entity<LogViewer>, _window: &mut Window, _cx: &mut Context<Self>) -> Self {
        Self { viewer }
    }
}

impl Render for LogViewerRoot {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        AnyView::from(self.viewer.clone()).into_any_element()
    }
}

/// Emitted when the user clicks a policy-match or resolved row.
#[derive(Clone)]
pub struct OpenRuleFilter(pub String);

/// Render `visible` as per-process sections (GUI-only grouping). Groups
/// appear in order of first activity in the newest-first list, and rows keep
/// their order inside each section. Sections start folded; `expanded` holds
/// the ones the user opened. Nothing is deduplicated here.
fn render_process_groups(
    visible: Vec<LogRow>,
    group_by_domain: bool,
    expanded: &HashSet<Option<String>>,
    viewer: Entity<LogViewer>,
) -> Vec<gpui::AnyElement> {
    let mut groups: Vec<(Option<String>, Vec<LogRow>)> = Vec::new();
    for row in visible {
        match groups
            .iter_mut()
            .find(|(process, _)| *process == row.process_name)
        {
            Some((_, rows)) => rows.push(row),
            None => groups.push((row.process_name.clone(), vec![row])),
        }
    }

    let mut out = Vec::new();
    for (process, rows) in groups {
        // Folded unless the user explicitly unfolded this process.
        let is_collapsed = !expanded.contains(&process);
        let summary = GroupSummary::from_rows(&rows);
        out.push(process_group_header(
            process,
            summary,
            is_collapsed,
            viewer.clone(),
        ));
        if !is_collapsed {
            out.extend(
                rows.iter()
                    .map(|row| render_row(row, group_by_domain, viewer.clone())),
            );
        }
    }
    out
}

/// Per-process aggregation shown in a section header.
#[derive(Default)]
struct GroupSummary {
    total: usize,
    allow: usize,
    deny: usize,
    ask: usize,
    route: usize,
    /// Egress display name → request count, sorted by count descending.
    egresses: Vec<(String, usize)>,
}

impl GroupSummary {
    fn from_rows(rows: &[LogRow]) -> Self {
        let mut summary = Self::default();
        let mut egress_counts: HashMap<String, usize> = HashMap::new();
        for row in rows {
            let n = row.occurrences;
            summary.total += n;
            match row.action {
                Some(core_types::RuleAction::Allow) => summary.allow += n,
                Some(core_types::RuleAction::Deny) => summary.deny += n,
                Some(core_types::RuleAction::Ask) => summary.ask += n,
                Some(core_types::RuleAction::Route) => summary.route += n,
                None => {}
            }
            if let Some(egress) = row.egress_name.as_deref().or(row.egress_id.as_deref()) {
                *egress_counts.entry(egress.to_string()).or_default() += n;
            }
        }
        summary.egresses = egress_counts.into_iter().collect();
        summary
            .egresses
            .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        summary
    }
}

/// Section header shown above a process's rows when "Group By Process" is on.
/// Clicking it folds or unfolds the section.
fn process_group_header(
    process: Option<String>,
    summary: GroupSummary,
    collapsed: bool,
    viewer: Entity<LogViewer>,
) -> gpui::AnyElement {
    let label = process.as_deref().unwrap_or("unknown").to_string();
    let key = process;

    let mut summary_chips = h_flex().ml_auto().gap(px(4.)).items_center();
    if summary.allow > 0 {
        summary_chips =
            summary_chips.child(badge(format!("ALLOW {}", summary.allow), colors::green()));
    }
    if summary.deny > 0 {
        summary_chips =
            summary_chips.child(badge(format!("DENY {}", summary.deny), colors::error()));
    }
    if summary.ask > 0 {
        summary_chips =
            summary_chips.child(badge(format!("ASK {}", summary.ask), colors::orange()));
    }
    if summary.route > 0 {
        summary_chips =
            summary_chips.child(badge(format!("ROUTE {}", summary.route), colors::primary()));
    }
    // Where the routed traffic went. Cap the list so busy processes don't
    // swamp the header; the folded rows hold the full detail.
    const MAX_EGRESS_CHIPS: usize = 3;
    for (egress, count) in summary.egresses.iter().take(MAX_EGRESS_CHIPS) {
        summary_chips = summary_chips.child(badge(format!("via {egress} {count}"), colors::teal()));
    }
    let hidden_egresses = summary.egresses.len().saturating_sub(MAX_EGRESS_CHIPS);
    if hidden_egresses > 0 {
        summary_chips = summary_chips.child(badge(format!("+{hidden_egresses}"), colors::muted()));
    }

    h_flex()
        .id(ElementId::Name(format!("process-group:{label}").into()))
        .w_full()
        .px(px(10.))
        .py(px(5.))
        .gap(px(6.))
        .items_center()
        .cursor_pointer()
        .bg(colors::surface_container_high())
        .hover(|this| this.bg(colors::surface_container_highest()))
        .border_b_1()
        .border_color(colors::border())
        .on_click(move |_, _, cx| {
            cx.update_entity(&viewer, |s, cx| {
                if !s.expanded_processes.remove(&key) {
                    s.expanded_processes.insert(key.clone());
                }
                cx.notify();
            });
        })
        .child(
            div()
                .w(px(10.))
                .flex_shrink_0()
                .text_size(px(10.))
                .text_color(colors::muted())
                .child(if collapsed { "▸" } else { "▾" }),
        )
        .child(
            div()
                .w(px(3.))
                .h(px(12.))
                .flex_shrink_0()
                .rounded(px(2.))
                .bg(colors::primary()),
        )
        .child(
            div()
                .text_size(px(11.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(colors::text())
                .child(label),
        )
        .child(
            div()
                .text_size(px(10.))
                .text_color(colors::muted())
                .child(format!(
                    "{} req{}",
                    summary.total,
                    if summary.total == 1 { "" } else { "s" }
                )),
        )
        .child(summary_chips)
        .into_any_element()
}

/// One compact line per group: pulse bar · event badge · process → dest ·
/// domain · action badge · egress badge · Nx counter · age. Policy-match /
/// resolved rows are clickable and emit `OpenRuleFilter(rule_id)`.
fn render_row(row: &LogRow, group_by_domain: bool, viewer: Entity<LogViewer>) -> gpui::AnyElement {
    let flash = row.flash_since.is_some();
    let clickable = row.rule_id.is_some();

    let action = row.action.as_ref().map(|a| match a {
        core_types::RuleAction::Allow => ("ALLOW", colors::green()),
        core_types::RuleAction::Deny => ("DENY", colors::error()),
        core_types::RuleAction::Ask => ("ASK", colors::orange()),
        core_types::RuleAction::Route => ("ROUTE", colors::primary()),
    });
    let event_color = match row.event_type {
        "policy-match" => colors::primary(),
        "resolved" => colors::green(),
        "expired" | "pending-expired" => colors::muted(),
        _ => colors::orange(),
    };
    // The left bar carries the outcome color: decided rows use the action
    // color, undecided ones the event color.
    let bar_color = if flash {
        colors::primary()
    } else {
        action.map(|(_, color)| color).unwrap_or(event_color)
    };

    let process = row.process_name.as_deref().unwrap_or("unknown");
    let destination = if group_by_domain {
        row.domain_group()
    } else {
        format!("{}:{}", row.destination_ip, row.destination_port)
    };

    let mut line = h_flex()
        .id(ElementId::Name(
            format!(
                "log-row:{}:{}:{}",
                row.process_name.as_deref().unwrap_or("?"),
                row.destination_ip,
                row.destination_port
            )
            .into(),
        ))
        .w_full()
        .px(px(10.))
        .py(px(3.))
        .gap(px(6.))
        .items_center()
        .border_b_1()
        .border_color(colors::border())
        .text_size(px(11.))
        .when(flash, |el| {
            el.bg(gpui::Hsla {
                a: 0.06,
                ..colors::primary()
            })
        })
        // Left pulse bar: bright while the group is flashing, otherwise the
        // row's outcome color.
        .child(
            div()
                .w(px(3.))
                .h(px(16.))
                .flex_shrink_0()
                .rounded(px(2.))
                .bg(bar_color),
        )
        .child(badge(row.event_type, event_color))
        .child(
            div()
                .flex_shrink_0()
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(colors::text())
                .child(process.to_string()),
        )
        .child(div().flex_shrink_0().text_color(colors::muted()).child("→"))
        .child(
            div()
                .flex_shrink_0()
                .text_color(colors::text())
                .child(destination),
        );

    if group_by_domain {
        // The row is deduped on the domain, but the concrete destination of
        // the most recent connection is still useful context.
        if row.destination_domain.is_some() {
            line = line.child(
                div()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_color(colors::muted())
                    .child(format!("{}:{}", row.destination_ip, row.destination_port)),
            );
        }
    } else if let Some(d) = row.destination_domain.as_deref() {
        line = line.child(
            div()
                .min_w_0()
                .overflow_hidden()
                .whitespace_nowrap()
                .text_color(colors::muted())
                .child(d.to_string()),
        );
    }
    if let Some((label, color)) = action {
        line = line.child(badge(label, color));
    }
    if let Some(egress) = row.egress_name.as_deref().or(row.egress_id.as_deref()) {
        line = line.child(badge(format!("via {egress}"), colors::teal()));
    }
    if row.occurrences > 1 {
        line = line.child(badge(format!("{}×", row.occurrences), colors::muted()));
    }
    line = line.child(
        div()
            .ml_auto()
            .flex_shrink_0()
            .text_color(colors::muted())
            .child(format!(
                "{}s",
                daemon::unix_now().saturating_sub(row.timestamp_secs)
            )),
    );

    if clickable {
        let rule_id = row.rule_id.clone().unwrap_or_default();
        line.cursor_pointer()
            .hover(|this| this.bg(colors::surface_container_highest()))
            .on_click(move |_, _, cx| {
                cx.update_entity(&viewer, |_s, cx| {
                    cx.emit(OpenRuleFilter(rule_id.clone()));
                });
            })
            .into_any_element()
    } else {
        line.into_any_element()
    }
}
