use gpui::{
    InteractiveElement, IntoElement, ParentElement, StatefulInteractiveElement, Styled,
    WeakEntity, div, px, prelude::FluentBuilder as _,
};
use gpui_component::h_flex;

use core_types::{DestinationMatcher, Egress, FlowContext, Rule, RuleAction, RuleDuration};
use control_api::ControlRequest;

use crate::colors;
use crate::daemon::{self, SOCKET_PATH};
use crate::state::AppState;

pub struct ActionFooterProps {
    pub pending_id: String,
    pub flow: FlowContext,
    pub make_permanent: bool,
    pub egresses: Vec<Egress>,
    pub selected_egress_index: usize,
    pub state: WeakEntity<AppState>,
}

pub fn action_footer(props: ActionFooterProps) -> gpui::AnyElement {
    let ActionFooterProps {
        pending_id,
        flow,
        make_permanent,
        egresses,
        selected_egress_index,
        state: state_weak,
    } = props;

    let pid_deny = pending_id.clone();
    let pid_allow = pending_id.clone();

    let session_selected = !make_permanent;
    let permanent_selected = make_permanent;
    let state_weak_pill = state_weak.clone();

    let selected_egress = egresses.get(selected_egress_index).cloned().unwrap_or_else(|| Egress {
        id: "eg-default".to_string(),
        name: "Default Route".to_string(),
        color: "#6b7280".to_string(),
        targets: vec![],
        dns_servers: vec![],
        is_system_default: true,
        is_available: true,
    });

    h_flex()
        .w_full()
        .flex_col()
        .px(px(16.))
        .pt_0()
        .pb(px(16.))
        .gap(px(16.))
        // Scope toggle row
        .child(
            scope_toggle(state_weak_pill, session_selected, permanent_selected),
        )
        // Egress selector row
        .child(
            egress_selector(state_weak.clone(), &egresses, selected_egress_index),
        )
        // Main buttons row: ALLOW + DENY
        .child(
            h_flex()
                .w_full()
                .gap(px(12.))
                .child(
                    allow_button(pid_allow, make_permanent, flow.clone(), selected_egress),
                )
                .child(
                    deny_button(pid_deny, make_permanent, flow.clone()),
                ),
        )
        // Centered link
        .child(
            h_flex()
                .w_full()
                .justify_center()
                .child(
                    div()
                        .text_color(colors::muted())
                        .text_size(px(12.))
                        .cursor_pointer()
                        .child("Always ask for this process \u{2192}"),
                ),
        )
        .into_any_element()
}

fn scope_toggle(
    state_weak: WeakEntity<AppState>,
    session_selected: bool,
    permanent_selected: bool,
) -> gpui::AnyElement {
    let state_weak_session = state_weak.clone();
    let state_weak_permanent = state_weak.clone();

    h_flex()
        .w_full()
        .items_center()
        .justify_between()
        .bg(colors::surface())
        .px(px(8.))
        .py(px(8.))
        .rounded(px(4.))
        .border_1()
        .border_color(colors::border())
        // Left label
        .child(
            div()
                .text_color(colors::muted())
                .font_weight(gpui::FontWeight::BOLD)
                .text_size(px(11.))
                .child("APPLY RULE FOR:"),
        )
        // Right: segmented pill
        .child(
            h_flex()
                .bg(colors::surface_container_high())
                .rounded(px(4.))
                .px(px(4.))
                .py(px(4.))
                .border_1()
                .border_color(colors::border())
                .child(
                    pill_segment(
                        "pill-session",
                        "THIS SESSION",
                        session_selected,
                        false,
                        state_weak_session,
                    ),
                )
                .child(
                    pill_segment(
                        "pill-permanent",
                        "PERMANENTLY",
                        permanent_selected,
                        true,
                        state_weak_permanent,
                    ),
                ),
        )
        .into_any_element()
}

fn pill_segment(
    id: &'static str,
    label: &str,
    selected: bool,
    is_permanent: bool,
    state_weak: WeakEntity<AppState>,
) -> gpui::AnyElement {
    let label_text = gpui::SharedString::from(label.to_string());
    div()
        .id(id)
        .px(px(12.))
        .py(px(4.))
        .rounded(px(4.))
        .cursor_pointer()
        .when(selected, |el| el.bg(colors::primary()))
        .when(!selected, |el| el.bg(gpui::hsla(0., 0., 0., 0.)))
        .on_click(move |_, _, cx| {
            if let Some(state) = state_weak.upgrade() {
                state.update(cx, |s, cx| {
                    s.make_permanent = is_permanent;
                    cx.notify();
                });
            }
        })
        .child(
            div()
                .text_color(if selected {
                    colors::on_primary()
                } else {
                    colors::muted()
                })
                .font_weight(gpui::FontWeight::BOLD)
                .text_size(px(10.))
                .child(label_text),
        )
        .into_any_element()
}

fn egress_selector(
    state_weak: WeakEntity<AppState>,
    egresses: &[Egress],
    selected_index: usize,
) -> gpui::AnyElement {
    let max_visible = 10;
    let total = egresses.len();
    let visible_count = total.min(max_visible);
    let overflow = total.saturating_sub(max_visible);

    h_flex()
        .w_full()
        .flex_wrap()
        .gap(px(6.))
        .max_h(px(56.))
        .overflow_hidden()
        .children(egresses.iter().enumerate().take(visible_count).map(|(i, eg)| {
            let is_selected = i == selected_index;
            let is_available = eg.is_available;
            let state_w = state_weak.clone();
            let label = if is_available {
                gpui::SharedString::from(eg.name.clone())
            } else {
                gpui::SharedString::from(format!("{} (offline)", eg.name))
            };
            let color_str = eg.color.clone();

            div()
                .id(gpui::ElementId::Name(format!("egress-{i}").into()))
                .px(px(10.))
                .py(px(4.))
                .rounded(px(4.))
                .cursor_pointer()
                .border_1()
                .border_color(if !is_available {
                    colors::border()
                } else if is_selected {
                    colors::hex_to_hsla(&color_str)
                } else {
                    colors::border()
                })
                .when(is_selected && is_available, |el| el.bg(colors::hex_to_hsla(&color_str)))
                .when(!is_selected || !is_available, |el| el.bg(colors::surface()))
                .on_click(move |_, _, cx| {
                    if !is_available {
                        return;
                    }
                    if let Some(state) = state_w.upgrade() {
                        state.update(cx, |s, cx| {
                            s.selected_egress_index = i;
                            cx.notify();
                        });
                    }
                })
                .child(
                    div()
                        .text_color(if !is_available {
                            gpui::hsla(0., 0., 0.40, 1.) // dim grey for offline
                        } else if is_selected {
                            colors::on_primary()
                        } else {
                            colors::muted()
                        })
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_size(px(10.))
                        .child(label),
                )
        }))
        .when(overflow > 0, |el| {
            el.child(
                div()
                    .px(px(10.))
                    .py(px(4.))
                    .rounded(px(4.))
                    .border_1()
                    .border_color(colors::border())
                    .bg(colors::surface())
                    .child(
                        div()
                            .text_color(colors::muted())
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_size(px(10.))
                            .child(format!("+{overflow} more")),
                    ),
            )
        })
        .into_any_element()
}

fn allow_button(
    pid: String,
    make_permanent: bool,
    flow: FlowContext,
    selected_egress: Egress,
) -> gpui::AnyElement {
    let is_default = selected_egress.is_system_default;
    let route_target = selected_egress.targets.first().cloned();

    div()
        .id("allow-btn")
        .flex_1()
        .flex()
        .items_center()
        .justify_center()
        .gap(px(8.))
        .py(px(8.))
        .px(px(16.))
        .rounded(px(4.))
        .bg(colors::surface_container_highest())
        .border_1()
        .border_color(colors::green_dim())
        .cursor_pointer()
        .on_click({
            move |_, _, cx| {
                let pid = pid.clone();
                let flow = flow.clone();
                let mk_perm = make_permanent;
                let rt = route_target.clone();
                cx.spawn(async move |cx| {
                    let (resolve_action, rule_action, rule_target) = if rt.is_some() {
                        let target = rt.clone().unwrap();
                        (
                            RuleAction::Route { target: target.clone() },
                            RuleAction::Route { target: target.clone() },
                            Some(target),
                        )
                    } else {
                        (RuleAction::Allow, RuleAction::Allow, None)
                    };
                    let pid2 = pid.clone();
                    let socket = std::env::var("LOGIGUARD_SOCKET_PATH")
                        .unwrap_or_else(|_| SOCKET_PATH.to_string());
                    let _ = cx
                        .background_executor()
                        .spawn(async move {
                            daemon::send_request(
                                &socket,
                                &ControlRequest::ResolvePending {
                                    pending_id: pid2,
                                    action: resolve_action,
                                },
                            )
                        })
                        .await;
                    let dest = if let Some(d) = &flow.destination_domain {
                        DestinationMatcher::DomainExact(d.clone())
                    } else {
                        DestinationMatcher::IpExact(
                            flow.destination_ip.clone(),
                        )
                    };
                    let rule = Rule {
                        id: format!("ui-{}", daemon::unix_now()),
                        enabled: true,
                        action: rule_action,
                        duration: if mk_perm {
                            RuleDuration::Permanent
                        } else {
                            RuleDuration::UntilRestart
                        },
                        process_name: flow.process_name.clone(),
                        destination: dest,
                        route_target: rule_target,
                    };
                    let socket2 = std::env::var("LOGIGUARD_SOCKET_PATH")
                        .unwrap_or_else(|_| SOCKET_PATH.to_string());
                    let _ = cx
                        .background_executor()
                        .spawn(async move {
                            daemon::send_request(
                                &socket2,
                                &ControlRequest::AddRule(rule),
                            )
                        })
                        .await;
                    std::process::exit(0);
                })
                .detach();
            }
        })
        .child(
            div()
                .text_color(colors::green())
                .text_size(px(18.))
                .child(if is_default { "\u{1F6E1}" } else { "\u{1F5A7}" }), // shield or network icon
        )
        .child(
            div()
                .text_color(colors::green())
                .font_weight(gpui::FontWeight::BOLD)
                .text_size(px(11.))
                .child(if is_default { "ALLOW" } else { "ALLOW + ROUTE" }),
        )
        .into_any_element()
}

fn deny_button(
    pid: String,
    make_permanent: bool,
    flow: FlowContext,
) -> gpui::AnyElement {
    div()
        .id("deny-btn")
        .flex_1()
        .flex()
        .items_center()
        .justify_center()
        .gap(px(8.))
        .py(px(8.))
        .px(px(16.))
        .rounded(px(4.))
        .bg(colors::surface_container_highest())
        .border_1()
        .border_color(gpui::hsla(0., 0.80, 0.65, 0.50)) // error with 50% alpha
        .cursor_pointer()
        .on_click({
            move |_, _, cx| {
                let pid = pid.clone();
                let flow = flow.clone();
                let mk_perm = make_permanent;
                cx.spawn(async move |cx| {
                    let pid2 = pid.clone();
                    let socket = std::env::var("LOGIGUARD_SOCKET_PATH")
                        .unwrap_or_else(|_| SOCKET_PATH.to_string());
                    let _ = cx
                        .background_executor()
                        .spawn(async move {
                            daemon::send_request(
                                &socket,
                                &ControlRequest::ResolvePending {
                                    pending_id: pid2,
                                    action: RuleAction::Deny,
                                },
                            )
                        })
                        .await;
                    let dest = if let Some(d) = &flow.destination_domain {
                        DestinationMatcher::DomainExact(d.clone())
                    } else {
                        DestinationMatcher::IpExact(
                            flow.destination_ip.clone(),
                        )
                    };
                    let rule = Rule {
                        id: format!("ui-{}", daemon::unix_now()),
                        enabled: true,
                        action: RuleAction::Deny,
                        duration: if mk_perm {
                            RuleDuration::Permanent
                        } else {
                            RuleDuration::UntilRestart
                        },
                        process_name: flow.process_name.clone(),
                        destination: dest,
                        route_target: None,
                    };
                    let socket2 = std::env::var("LOGIGUARD_SOCKET_PATH")
                        .unwrap_or_else(|_| SOCKET_PATH.to_string());
                    let _ = cx
                        .background_executor()
                        .spawn(async move {
                            daemon::send_request(
                                &socket2,
                                &ControlRequest::AddRule(rule),
                            )
                        })
                        .await;
                    std::process::exit(0);
                })
                .detach();
            }
        })
        .child(
            div()
                .text_color(colors::error())
                .text_size(px(18.))
                .child("\u{1F6AB}"), // 🚫 prohibited
        )
        .child(
            div()
                .text_color(colors::error())
                .font_weight(gpui::FontWeight::BOLD)
                .text_size(px(11.))
                .child("DENY"),
        )
        .into_any_element()
}
