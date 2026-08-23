//! Rules tab — DataTable delegate for firewall rules with toggle/delete actions.

use control_api::ControlRequest;
use core_types::{Egress, Rule, RuleAction, RuleDuration};
use gpui::{
    px, App, AppContext as _, Context, IntoElement, ParentElement, StatefulInteractiveElement,
    Styled, WeakEntity, Window,
};
use gpui_component::h_flex;
use gpui_component::label::Label;
use gpui_component::table::{Column, TableDelegate, TableState};

use crate::colors;
use crate::components::{action_btn, badge, dest_text};
use crate::daemon;

use super::{fetch_and_apply, SettingsState};

// ── Delegate ───────────────────────────────────────────────────────────

pub struct RulesDelegate {
    pub rules: Vec<Rule>,
    pub egresses: Vec<Egress>,
    pub state_weak: WeakEntity<SettingsState>,
    pub socket_path: String,
    columns: Vec<Column>,
}

impl RulesDelegate {
    pub fn new(
        rules: Vec<Rule>,
        egresses: Vec<Egress>,
        state_weak: WeakEntity<SettingsState>,
        socket_path: String,
    ) -> Self {
        Self {
            rules,
            egresses,
            state_weak,
            socket_path,
            columns: vec![
                Column::new("id", "ID").width(px(90.)),
                Column::new("process", "Process").width(px(110.)),
                Column::new("destination", "Destination").width(px(180.)),
                Column::new("action", "Action").width(px(80.)),
                Column::new("duration", "Duration").width(px(80.)),
                Column::new("route", "Route").width(px(90.)),
                Column::new("priority", "Priority").width(px(56.)).resizable(false),
                Column::new("controls", "").width(px(190.)).resizable(false),
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

    fn column(&self, col_ix: usize, _cx: &App) -> Column {
        self.columns[col_ix].clone()
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let Some(rule) = self.rules.get(row_ix) else {
            return h_flex().into_any_element();
        };

        let dimmed = !rule.enabled;

        match col_ix {
            // ID column — enabled indicator dot + short rule id
            0 => {
                let enabled = rule.enabled;
                let id_short = rule
                    .id
                    .chars()
                    .rev()
                    .take(8)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>();
                h_flex()
                    .gap(px(6.))
                    .items_center()
                    .child(
                        h_flex()
                            .size(px(7.))
                            .flex_shrink_0()
                            .rounded(px(4.))
                            .bg(if enabled {
                                colors::green()
                            } else {
                                colors::muted()
                            }),
                    )
                    .child(
                        Label::new(id_short)
                            .text_size(px(10.))
                            .text_color(colors::muted()),
                    )
                    .into_any_element()
            }
            // Process column — process name or "—" when unconstrained
            1 => {
                let proc_label: gpui::SharedString = match &rule.process_name {
                    Some(p) if !p.is_empty() => p.clone().into(),
                    _ => "—".into(),
                };
                let has_proc = rule
                    .process_name
                    .as_deref()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                Label::new(proc_label)
                    .text_size(px(12.))
                    .text_color(if has_proc && !dimmed {
                        colors::text()
                    } else {
                        colors::muted()
                    })
                    .into_any_element()
            }

            // Destination column
            2 => Label::new(dest_text(&rule.destination))
                .text_size(px(12.))
                .text_color(if dimmed {
                    colors::muted()
                } else {
                    colors::text()
                })
                .into_any_element(),

            // Duration column
            4 => {
                let (label, color) = match rule.duration {
                    RuleDuration::Permanent => ("PERM", colors::primary()),
                    RuleDuration::UntilRestart => ("SESSION", colors::muted()),
                };
                badge(label, if dimmed { colors::muted() } else { color })
            }
            // Action column — colored badge
            3 => {
                let (label, color) = match &rule.action {
                    RuleAction::Allow => ("ALLOW", colors::green()),
                    RuleAction::Deny => ("DENY", colors::error()),
                    RuleAction::Ask => ("ASK", colors::orange()),
                    RuleAction::Route { .. } => ("ROUTE", colors::primary()),
                };
                badge(label, if dimmed { colors::muted() } else { color })
            }
            // Route column
            5 => {
                let route = rule.egress_id.as_deref().unwrap_or("");
                let display_name = if route.is_empty() {
                    "—".to_string()
                } else {
                    self.egresses
                        .iter()
                        .find(|e| e.id == route)
                        .map(|e| e.name.clone())
                        .unwrap_or_else(|| route.to_string())
                };
                Label::new(display_name)
                    .text_size(px(12.))
                    .text_color(if route_is_empty(&rule) || dimmed {
                        colors::muted()
                    } else {
                        colors::text()
                    })
                    .into_any_element()
            }
            // Priority column — restriction-level color strip.
            // The strip answers "how restrictive is this rule," independent of
            // where the user dragged it. No number is shown by design.
            6 => h_flex()
                .h_full()
                .items_center()
                .child(
                    h_flex()
                        .w(px(4.))
                        .h(px(16.))
                        .rounded(px(2.))
                        .bg(if dimmed {
                            colors::muted()
                        } else {
                            colors::priority_color(rule.priority)
                        }),
                )
                .into_any_element(),

            // Controls column — toggle + delete + reorder
            7 => {
                let id_toggle = rule.id.clone();
                let id_del = rule.id.clone();
                let rule_toggle = rule.clone();
                let enabled = rule.enabled;
                let socket_toggle = self.socket_path.clone();
                let state_toggle = self.state_weak.clone();
                let sock_del = self.socket_path.clone();
                let state_del = self.state_weak.clone();

                // Reorder neighbors come from the delegate's current (filtered,
                // priority-descending) view. Moving within a filtered view is
                // still well-defined: the rule is placed between its visible
                // neighbors.
                //
                // Daemon semantics (control-service `move_rule`): `before_id`
                // is the upper neighbor (rule lands below it), `after_id` the
                // lower neighbor (rule lands above it). So:
                //   move up   → land between above_above and above
                //   move down → land between below and below_below
                let above = row_ix
                    .checked_sub(1)
                    .and_then(|i| self.rules.get(i))
                    .map(|r| r.id.clone());
                let above_above = row_ix
                    .checked_sub(2)
                    .and_then(|i| self.rules.get(i))
                    .map(|r| r.id.clone());
                let below = self.rules.get(row_ix + 1).map(|r| r.id.clone());
                let below_below = self.rules.get(row_ix + 2).map(|r| r.id.clone());

                let sock_up = self.socket_path.clone();
                let state_up = self.state_weak.clone();
                let id_up = rule.id.clone();
                let sock_down = self.socket_path.clone();
                let state_down = self.state_weak.clone();
                let id_down = rule.id.clone();

                h_flex()
                    .gap(px(6.))
                    .child(
                        action_btn(
                            format!("rule-en-{id_toggle}"),
                            if enabled { "Disable" } else { "Enable" },
                            if enabled {
                                colors::muted()
                            } else {
                                colors::green()
                            },
                        )
                        .border_color(if enabled {
                            colors::border()
                        } else {
                            colors::green()
                        })
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
                                        if let Some(x) = s.rules.iter_mut().find(|x| x.id == tid) {
                                            x.enabled = !x.enabled;
                                        }
                                        cx.notify();
                                    });
                                }
                            })
                            .detach();
                        }),
                    )
                    .child(
                        action_btn(format!("rule-del-{id_del}"), "Delete", colors::error())
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
                            }),
                    )
                    .child(
                        action_btn(format!("rule-up-{id_up}"), "↑", colors::muted())
                            .on_click(move |_, _, cx| {
                                // Already at the top — nothing to do.
                                let Some(above_id) = above.clone() else {
                                    return;
                                };
                                let rid = id_up.clone();
                                let sock = sock_up.clone();
                                let sw = state_up.clone();
                                // Land between above_above and above. When
                                // above_above is None this becomes (None, Some)
                                // → daemon places the rule at the top.
                                let before = above_above.clone();
                                let after = Some(above_id);
                                let sock_send = sock.clone();
                                cx.spawn(async move |cx| {
                                    let _ = cx
                                        .background_executor()
                                        .spawn(async move {
                                            daemon::send_request(
                                                &sock_send,
                                                &ControlRequest::MoveRule {
                                                    id: rid,
                                                    before_id: before,
                                                    after_id: after,
                                                },
                                            )
                                        })
                                        .await;
                                    // The new priority is computed daemon-side;
                                    // re-fetch so the table re-sorts correctly.
                                    fetch_and_apply(sw, &sock, cx).await;
                                })
                                .detach();
                            }),
                    )
                    .child(
                        action_btn(format!("rule-down-{id_down}"), "↓", colors::muted())
                            .on_click(move |_, _, cx| {
                                // Already at the bottom — nothing to do.
                                let Some(below_id) = below.clone() else {
                                    return;
                                };
                                let rid = id_down.clone();
                                let sock = sock_down.clone();
                                let sw = state_down.clone();
                                // Land between below and below_below. When
                                // below_below is None this becomes (Some, None)
                                // → daemon places the rule at the bottom.
                                let before = Some(below_id);
                                let after = below_below.clone();
                                let sock_send = sock.clone();
                                cx.spawn(async move |cx| {
                                    let _ = cx
                                        .background_executor()
                                        .spawn(async move {
                                            daemon::send_request(
                                                &sock_send,
                                                &ControlRequest::MoveRule {
                                                    id: rid,
                                                    before_id: before,
                                                    after_id: after,
                                                },
                                            )
                                        })
                                        .await;
                                    // The new priority is computed daemon-side;
                                    // re-fetch so the table re-sorts correctly.
                                    fetch_and_apply(sw, &sock, cx).await;
                                })
                                .detach();
                            }),
                    )
                    .into_any_element()
            }
            _ => h_flex().into_any_element(),
        }
    }
}

fn route_is_empty(rule: &Rule) -> bool {
    rule.egress_id.is_none()
}
