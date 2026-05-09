//! Rules tab — displays firewall rules with toggle/delete actions.

use control_api::ControlRequest;
use core_types::Rule;
use gpui::{
    AppContext as _, ElementId, InteractiveElement, IntoElement,
    ParentElement, StatefulInteractiveElement, Styled, WeakEntity, div, px,
};

use gpui_component::scroll::ScrollableElement;
use gpui_component::{h_flex, v_flex};

use crate::colors;
use crate::daemon;

use super::SettingsState;
use super::helpers::route_summary;

/// Render the full Rules tab content (scrollable list of rule rows).
pub fn render_rules_tab(
    rules: Vec<Rule>,
    state_weak: WeakEntity<SettingsState>,
    socket_path: String,
) -> gpui::AnyElement {
    v_flex()
        .id(ElementId::Name("rules-tab-content".into()))
        .flex_1()
        .overflow_y_scrollbar()
        .px(px(16.))
        .py(px(12.))
        .gap(px(20.))
        // Section header
        .child(
            div()
                .text_size(px(11.))
                .text_color(colors::muted())
                .font_weight(gpui::FontWeight::BOLD)
                .child("FIREWALL RULES"),
        )
        // Rules list
        .children(
            rules
                .iter()
                .map(|rule| rule_row(rule, state_weak.clone(), socket_path.clone())),
        )
        .into_any_element()
}

/// Render a single rule row with toggle and delete buttons.
fn rule_row(
    rule: &Rule,
    state_weak: WeakEntity<SettingsState>,
    socket_path: String,
) -> gpui::AnyElement {
    let id = rule.id.clone();
    let id_toggle = id.clone();
    let id_del = id.clone();
    let rule_toggle = rule.clone();
    let enabled = rule.enabled;
    let dest = format!("{:?}", rule.destination);
    let action = format!("{:?}", rule.action);
    let route = rule
        .route_target
        .as_ref()
        .map(route_summary)
        .unwrap_or_default();

    let action_color = if enabled {
        colors::green()
    } else {
        colors::muted()
    };

    h_flex()
        .w_full()
        .items_start()
        .justify_between()
        .gap(px(8.))
        .py(px(6.))
        .px(px(8.))
        .rounded(px(4.))
        .bg(colors::surface_container())
        .border_1()
        .border_color(colors::border())
        .child(
            v_flex()
                .flex_1()
                .gap(px(2.))
                .child(
                    div()
                        .text_size(px(12.))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child(rule.id.clone()),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(colors::muted())
                        .child(format!(
                            "{action} · {dest}{}",
                            if route.is_empty() {
                                String::new()
                            } else {
                                format!(" · route {route}")
                            }
                        )),
                ),
        )
        .child(
            h_flex()
                .gap(px(6.))
                .items_center()
                // Toggle enabled/disabled
                .child(
                    div()
                        .id(ElementId::Name(format!("rule-en-{id_toggle}").into()))
                        .text_size(px(11.))
                        .text_color(action_color)
                        .cursor_pointer()
                        .px(px(8.))
                        .py(px(4.))
                        .rounded(px(4.))
                        .border_1()
                        .border_color(colors::border())
                        .on_click({
                            let socket_toggle = socket_path.clone();
                            let state_toggle = state_weak.clone();
                            move |_, _, cx| {
                                let mut r = rule_toggle.clone();
                                let sock = socket_toggle.clone();
                                let sw = state_toggle.clone();
                                let tid = id_toggle.clone();
                                cx.spawn(async move |cx| {
                                    r.enabled = !r.enabled;
                                    let _ = cx
                                        .background_executor()
                                        .spawn(async move {
                                            daemon::send_request(
                                                &sock,
                                                &ControlRequest::AddRule(r),
                                            )
                                        })
                                        .await;
                                    if let Some(st) = sw.upgrade() {
                                        let _ = cx.update_entity(&st, |s, cx| {
                                            if let Some(x) =
                                                s.rules.iter_mut().find(|x| x.id == tid)
                                            {
                                                x.enabled = !x.enabled;
                                            }
                                            cx.notify();
                                        });
                                    }
                                })
                                .detach();
                            }
                        })
                        .child(if enabled { "Enabled" } else { "Disabled" }),
                )
                // Delete button
                .child(
                    div()
                        .id(ElementId::Name(format!("rule-del-{id_del}").into()))
                        .text_size(px(11.))
                        .text_color(colors::error())
                        .cursor_pointer()
                        .px(px(8.))
                        .py(px(4.))
                        .rounded(px(4.))
                        .border_1()
                        .border_color(colors::error())
                        .on_click({
                            let sock_del = socket_path.clone();
                            let state_del = state_weak.clone();
                            move |_, _, cx| {
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
                            }
                        })
                        .child("Delete"),
                ),
        )
        .into_any_element()
}
