use gpui::{
    AppContext as _, IntoElement, ParentElement, Styled, WeakEntity,
};
use gpui_component::{button::{Button, ButtonVariants as _}, checkbox::Checkbox, h_flex, v_flex};

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

    let state_weak_checkbox = state_weak.clone();
    let state_weak_deny = state_weak.clone();
    let state_weak_allow = state_weak.clone();

    let pid_deny = pending_id.clone();
    let pid_allow = pending_id.clone();

    h_flex()
        .w_full()
        .flex_col()
        .child(
            v_flex()
                .px_5()
                .py_4()
                .child(
                    Checkbox::new("make-permanent")
                        .label("Remember this decision (permanent rule)")
                        .checked(make_permanent)
                        .on_click({
                            move |checked, _, cx| {
                                if let Some(state) = state_weak_checkbox.upgrade() {
                                    state.update(cx, |s, cx| {
                                        s.make_permanent = *checked;
                                        cx.notify();
                                    });
                                }
                            }
                        }),
                ),
        )
        .child(
            h_flex()
                .w_full()
                .gap_3()
                .px_5()
                .py_4()
                .border_t_1()
                .border_color(colors::border())
                .child(
                    Button::new("deny-btn")
                        .label("Deny")
                        .danger()
                        .w_full()
                        .on_click({
                            move |_, _, cx| {
                                let pid = pid_deny.clone();
                                let state_weak = state_weak_deny.clone();
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
                        }),
                )
                .child(
                    Button::new("allow-btn")
                        .label("Allow")
                        .success()
                        .w_full()
                        .on_click({
                            move |_, _, cx| {
                                let pid = pid_allow.clone();
                                let state_weak = state_weak_allow.clone();
                                let mk_perm = make_permanent;
                                let flow = flow.clone();
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
                                    if mk_perm {
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
                                            duration: RuleDuration::Permanent,
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
                                    }
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
                        }),
                ),
        )
        .into_any_element()
}
