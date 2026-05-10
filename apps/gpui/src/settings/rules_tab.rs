//! Rules tab — DataTable delegate for firewall rules with toggle/delete actions.

use control_api::ControlRequest;
use core_types::{Rule, RuleAction};
use gpui::{
    App, AppContext as _, Context, InteractiveElement, IntoElement, ParentElement,
    StatefulInteractiveElement, Styled, WeakEntity, Window, div, px,
};

use gpui_component::table::{Column, TableDelegate, TableState};

use crate::colors;
use crate::daemon;

use super::SettingsState;
use super::helpers::route_summary;

// ── Delegate ───────────────────────────────────────────────────────────

/// Table delegate that displays firewall rules.
pub struct RulesDelegate {
    pub rules: Vec<Rule>,
    pub state_weak: WeakEntity<SettingsState>,
    pub socket_path: String,
    columns: Vec<Column>,
}

impl RulesDelegate {
    pub fn new(
        rules: Vec<Rule>,
        state_weak: WeakEntity<SettingsState>,
        socket_path: String,
    ) -> Self {
        Self {
            rules,
            state_weak,
            socket_path,
            columns: vec![
                Column::new("id", "ID").width(px(140.)),
                Column::new("action", "Action").width(px(80.)),
                Column::new("destination", "Destination").width(px(160.)),
                Column::new("route", "Route").width(px(100.)),
                Column::new("controls", "").width(px(150.)).resizable(false),
            ],
        }
    }
}

impl TableDelegate for RulesDelegate {
    fn columns_count(&self, _cx: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _cx: &App) -> usize {
        self.rules.len()
    }

    fn column(&self, col_ix: usize, _cx: &App) -> &Column {
        &self.columns[col_ix]
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let Some(rule) = self.rules.get(row_ix) else {
            return div().into_any_element();
        };

        match col_ix {
            // ID column with enabled indicator dot
            0 => {
                let enabled = rule.enabled;
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .child(
                        div()
                            .size(px(8.))
                            .rounded(px(4.))
                            .bg(if enabled { colors::green() } else { colors::muted() }),
                    )
                    .child(
                        div()
                            .text_color(if enabled { colors::text() } else { colors::muted() })
                            .child(rule.id.clone()),
                    )
                    .into_any_element()
            }
            // Action column
            1 => {
                let (label, color) = match &rule.action {
                    RuleAction::Allow => ("Allow", colors::green()),
                    RuleAction::Deny => ("Deny", colors::error()),
                    RuleAction::Ask => ("Ask", colors::orange()),
                    RuleAction::Route { .. } => ("Route", colors::primary()),
                };
                let color = if rule.enabled { color } else { colors::muted() };
                div().text_color(color).child(label.to_string()).into_any_element()
            }
            // Destination column
            2 => div()
                .text_color(colors::muted())
                .child(format!("{:?}", rule.destination))
                .into_any_element(),
            // Route column
            3 => {
                let route = rule
                    .route_target
                    .as_ref()
                    .map(route_summary)
                    .unwrap_or_default();
                div()
                    .text_color(if route.is_empty() { colors::muted() } else { colors::text() })
                    .child(if route.is_empty() { "—".to_string() } else { route })
                    .into_any_element()
            }
            // Controls column (toggle + delete)
            4 => {
                let id_toggle = rule.id.clone();
                let id_del = rule.id.clone();
                let rule_toggle = rule.clone();
                let enabled = rule.enabled;
                let socket_toggle = self.socket_path.clone();
                let state_toggle = self.state_weak.clone();
                let sock_del = self.socket_path.clone();
                let state_del = self.state_weak.clone();

                div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .child(
                        div()
                            .id(gpui::ElementId::Name(format!("rule-en-{id_toggle}").into()))
                            .text_size(px(11.))
                            .text_color(if enabled { colors::muted() } else { colors::green() })
                            .cursor_pointer()
                            .px(px(6.))
                            .py(px(2.))
                            .rounded(px(3.))
                            .border_1()
                            .border_color(if enabled { colors::border() } else { colors::green() })
                            .on_click(move |_, _, cx| {
                                let mut r = rule_toggle.clone();
                                let sock = socket_toggle.clone();
                                let sw = state_toggle.clone();
                                let tid = id_toggle.clone();
                                cx.spawn(async move |cx| {
                                    r.enabled = !r.enabled;
                                    let _ = cx
                                        .background_executor()
                                        .spawn(async move {
                                            daemon::send_request(&sock, &ControlRequest::AddRule(r))
                                        })
                                        .await;
                                    if let Some(st) = sw.upgrade() {
                                        let _ = cx.update_entity(&st, |s, cx| {
                                            if let Some(x) = s.rules.iter_mut().find(|x| x.id == tid)
                                            {
                                                x.enabled = !x.enabled;
                                            }
                                            cx.notify();
                                        });
                                    }
                                })
                                .detach();
                            })
                            .child(if enabled { "Disable" } else { "Enable" }),
                    )
                    .child(
                        div()
                            .id(gpui::ElementId::Name(format!("rule-del-{id_del}").into()))
                            .text_size(px(11.))
                            .text_color(colors::error())
                            .cursor_pointer()
                            .px(px(6.))
                            .py(px(2.))
                            .rounded(px(3.))
                            .border_1()
                            .border_color(colors::error())
                            .on_click(move |_, _, cx| {
                                let rid = id_del.clone();
                                let sock = sock_del.clone();
                                let sw = state_del.clone();
                                cx.spawn(async move |cx| {
                                    let rid_cmp = rid.clone();
                                    let _ = cx
                                        .background_executor()
                                        .spawn(async move {
                                            daemon::send_request(
                                                &sock,
                                                &ControlRequest::DeleteRule { id: rid },
                                            )
                                        })
                                        .await;
                                    if let Some(st) = sw.upgrade() {
                                        let _ = cx.update_entity(&st, |s, cx| {
                                            s.rules.retain(|r| r.id != rid_cmp);
                                            cx.notify();
                                        });
                                    }
                                })
                                .detach();
                            })
                            .child("Delete"),
                    )
                    .into_any_element()
            }
            _ => div().into_any_element(),
        }
    }
}
