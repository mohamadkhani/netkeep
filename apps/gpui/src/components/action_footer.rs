use gpui::{
    AppContext as _, InteractiveElement, IntoElement, ParentElement, StatefulInteractiveElement,
    Styled, WeakEntity, div, px, prelude::FluentBuilder as _,
};
use gpui_component::h_flex;

use core_types::{DestinationMatcher, FlowContext, Rule, RuleAction, RuleDuration};
use control_api::ControlRequest;

use crate::colors;
use crate::daemon::{self, SOCKET_PATH};
use crate::state::AppState;

pub struct ActionFooterProps {
    pub pending_id: String,
    pub flow: FlowContext,
    pub make_permanent: bool,
    pub state: WeakEntity<AppState>,
}

pub fn action_footer(props: ActionFooterProps) -> gpui::AnyElement {
    let ActionFooterProps {
        pending_id,
        flow,
        make_permanent,
        state: state_weak,
    } = props;

    let state_weak_deny = state_weak.clone();
    let state_weak_allow = state_weak.clone();

    let pid_deny = pending_id.clone();
    let pid_allow = pending_id.clone();

    let session_selected = !make_permanent;
    let permanent_selected = make_permanent;
    let state_weak_pill = state_weak.clone();

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
        // Main buttons row
        .child(
            h_flex()
                .w_full()
                .gap(px(12.))
                .child(
                    allow_button(pid_allow, state_weak_allow, make_permanent, flow.clone()),
                )
                .child(
                    deny_button(pid_deny, state_weak_deny, make_permanent, flow.clone()),
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

fn allow_button(
    pid: String,
    state_weak: WeakEntity<AppState>,
    make_permanent: bool,
    flow: FlowContext,
) -> gpui::AnyElement {
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
                let state_weak = state_weak.clone();
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
                                    action: RuleAction::Allow,
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
                        action: RuleAction::Allow,
                        duration: if mk_perm {
                            RuleDuration::Permanent
                        } else {
                            RuleDuration::UntilRestart
                        },
                        process_name: flow.process_name.clone(),
                        destination: dest,
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
                    if let Some(state) = state_weak.upgrade() {
                        cx.update_entity(&state, |s, cx| {
                            s.resolved = true;
                            cx.notify();
                        })
                        .ok();
                    }
                    cx.background_executor()
                        .timer(std::time::Duration::from_millis(500))
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
                .child("\u{1F6E1}"), // 🛡️ shield
        )
        .child(
            div()
                .text_color(colors::green())
                .font_weight(gpui::FontWeight::BOLD)
                .text_size(px(11.))
                .child("ALLOW"),
        )
        .into_any_element()
}

fn deny_button(
    pid: String,
    state_weak: WeakEntity<AppState>,
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
                let state_weak = state_weak.clone();
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
                    if let Some(state) = state_weak.upgrade() {
                        cx.update_entity(&state, |s, cx| {
                            s.resolved = true;
                            cx.notify();
                        })
                        .ok();
                    }
                    cx.background_executor()
                        .timer(std::time::Duration::from_millis(500))
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
