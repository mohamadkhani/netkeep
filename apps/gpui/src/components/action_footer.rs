use gpui::{
    InteractiveElement, IntoElement, ParentElement, StatefulInteractiveElement, Styled,
    WeakEntity, div, px, prelude::FluentBuilder as _,
};
use gpui_component::h_flex;

use core_types::{DestinationMatcher, Egress, FlowContext, Rule, RuleAction, RuleDuration};
use control_api::ControlRequest;

use crate::colors;
use crate::components::ds;
use crate::daemon::{self, SOCKET_PATH};
use crate::state::{AppState, DestScope, ProcessScope};

pub struct ActionFooterProps {
    pub pending_id: String,
    pub flow: FlowContext,
    pub make_permanent: bool,
    pub egresses: Vec<Egress>,
    pub selected_egress_index: usize,
    pub process_scope: ProcessScope,
    pub dest_scope: DestScope,
    pub state: WeakEntity<AppState>,
}

pub fn action_footer(props: ActionFooterProps) -> gpui::AnyElement {
    let ActionFooterProps {
        pending_id,
        flow,
        make_permanent,
        egresses,
        selected_egress_index,
        process_scope,
        dest_scope,
        state: state_weak,
    } = props;

    let selected_egress = egresses.get(selected_egress_index).cloned().unwrap_or_else(|| Egress {
        id: "eg-default".to_string(),
        name: "Default Route".to_string(),
        color: "#6b7280".to_string(),
        targets: vec![],
        dns_servers: vec![],
        is_system_default: true,
        is_available: true,
    });

    // Compute rule validity: all processes + any destination is too broad
    let is_too_broad = process_scope == ProcessScope::All
        && dest_scope == DestScope::Any;

    // Compute the DestinationMatcher for the current scope selection
    let dest_matcher = build_dest_matcher(&flow, &dest_scope);

    // Process_name for the rule
    let rule_process_name = match &process_scope {
        ProcessScope::Specific => flow.process_name.clone(),
        ProcessScope::All => None,
    };

    let pid_deny = pending_id.clone();
    let pid_allow = pending_id.clone();
    let flow_allow = flow.clone();
    let flow_deny = flow.clone();
    let dest_allow = dest_matcher.clone();
    let dest_deny = dest_matcher.clone();
    let proc_allow = rule_process_name.clone();
    let proc_deny = rule_process_name.clone();

    let state_weak_pill = state_weak.clone();
    let session_selected = !make_permanent;
    let permanent_selected = make_permanent;

    h_flex()
        .w_full()
        .flex_col()
        .px(px(16.))
        .pt(px(12.))
        .pb(px(16.))
        .gap(px(8.))
        // Rule Scope section
        .child(rule_scope_section(
            &flow,
            &process_scope,
            &dest_scope,
            state_weak.clone(),
        ))
        // Divider
        .child(
            div()
                .w_full()
                .h(px(1.))
                .bg(colors::border()),
        )
        // Duration row
        .child(
            h_flex()
                .w_full()
                .items_center()
                .gap(px(6.))
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(colors::muted())
                        .w(px(72.))
                        .child("Duration"),
                )
                .child(scope_toggle(state_weak_pill, session_selected, permanent_selected)),
        )
        // Egress row
        .child(
            h_flex()
                .w_full()
                .items_center()
                .gap(px(6.))
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(colors::muted())
                        .w(px(72.))
                        .child("Route via"),
                )
                .child(egress_selector(state_weak.clone(), &egresses, selected_egress_index)),
        )
        // Allow + Deny buttons
        .child(
            h_flex()
                .w_full()
                .gap(px(10.))
                .child(allow_button(
                    pid_allow,
                    make_permanent,
                    flow_allow,
                    selected_egress,
                    dest_allow,
                    proc_allow,
                    is_too_broad,
                ))
                .child(deny_button(
                    pid_deny,
                    make_permanent,
                    flow_deny,
                    dest_deny,
                    proc_deny,
                    is_too_broad,
                )),
        )
        .into_any_element()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the apex domain to use for wildcard scope.
///
/// `google.com`          → `google.com`   (1 dot — already the apex)
/// `accounts.google.com` → `google.com`   (2+ dots — strip the leftmost label)
fn domain_apex(domain: &str) -> String {
    let dot_count = domain.chars().filter(|&c| c == '.').count();
    if dot_count >= 2 {
        domain.splitn(2, '.').nth(1).unwrap_or(domain).to_string()
    } else {
        domain.to_string()
    }
}

// ---------------------------------------------------------------------------
// Rule scope section
// ---------------------------------------------------------------------------

fn rule_scope_section(
    flow: &FlowContext,
    process_scope: &ProcessScope,
    dest_scope: &DestScope,
    state_weak: WeakEntity<AppState>,
) -> gpui::AnyElement {
    let process_name = flow.process_name.clone();
    let has_domain = flow.destination_domain.is_some();
    let process_known = process_name.is_some();
    // Warning banner: both process and dest unknown — process is locked, any option hidden
    let show_warning = !process_known && flow.destination_domain.is_none();

    let mut col = h_flex().w_full().flex_col().gap(px(8.));

    if show_warning {
        col = col.child(
            div()
                .w_full()
                .px(px(10.))
                .py(px(6.))
                .rounded(px(4.))
                .bg(gpui::hsla(0.07, 0.80, 0.20, 0.40))
                .border_1()
                .border_color(gpui::hsla(0.07, 0.80, 0.50, 0.50))
                .child(
                    div()
                        .text_size(px(10.))
                        .text_color(gpui::hsla(0.07, 0.70, 0.80, 1.))
                        .child("Unable to identify this connection. Specify a destination to create a rule."),
                ),
        );
    }

    // Process toggle row
    col = col.child(process_scope_row(
        process_name.clone(),
        process_scope,
        process_known,
        state_weak.clone(),
    ));

    // Destination scope row
    col = col.child(dest_scope_row(
        flow,
        dest_scope,
        has_domain,
        show_warning,
        state_weak.clone(),
    ));

    // Rule summary line
    col = col.child(rule_summary_line(
        process_name.as_deref(),
        process_scope,
        dest_scope,
        flow,
    ));

    col.into_any_element()
}

fn process_scope_row(
    process_name: Option<String>,
    scope: &ProcessScope,
    process_known: bool,
    state_weak: WeakEntity<AppState>,
) -> gpui::AnyElement {
    let display_name = process_name.clone().unwrap_or_else(|| "unknown".to_string());
    let is_specific = *scope == ProcessScope::Specific;
    let sw1 = state_weak.clone();
    let sw2 = state_weak.clone();

    let chips = h_flex()
        .gap(px(4.))
        .child(ds::chip("proc-specific", display_name, is_specific, move |_, _, cx| {
            if let Some(s) = sw1.upgrade() {
                s.update(cx, |st, cx| { st.process_scope = ProcessScope::Specific; cx.notify(); });
            }
        }))
        .when(process_known, |el| {
            el.child(ds::chip("proc-all", "all processes", !is_specific, move |_, _, cx| {
                if let Some(s) = sw2.upgrade() {
                    s.update(cx, |st, cx| { st.process_scope = ProcessScope::All; cx.notify(); });
                }
            }))
        });

    ds::label_row("Process", chips.into_any_element())
}

fn dest_scope_row(
    flow: &FlowContext,
    dest_scope: &DestScope,
    has_domain: bool,
    hide_any: bool,
    state_weak: WeakEntity<AppState>,
) -> gpui::AnyElement {
    let sw_exact = state_weak.clone();
    let sw_wild = state_weak.clone();
    let sw_any = state_weak.clone();

    let content: gpui::AnyElement = if has_domain {
        let domain = flow.destination_domain.clone().unwrap_or_default();
        let apex = domain_apex(&domain);
        let wildcard_label = format!("*.{apex}");
        let is_exact = *dest_scope == DestScope::DomainExact;
        let is_wild = *dest_scope == DestScope::DomainWildcard;
        let is_any = *dest_scope == DestScope::Any;

        h_flex()
            .gap(px(4.))
            .child(ds::chip("dest-exact", domain.clone(), is_exact, move |_, _, cx| {
                if let Some(s) = sw_exact.upgrade() {
                    s.update(cx, |st, cx| { st.dest_scope = DestScope::DomainExact; cx.notify(); });
                }
            }))
            .child(ds::chip("dest-wild", wildcard_label, is_wild, move |_, _, cx| {
                if let Some(s) = sw_wild.upgrade() {
                    s.update(cx, |st, cx| { st.dest_scope = DestScope::DomainWildcard; cx.notify(); });
                }
            }))
            .when(!hide_any, |el| {
                el.child(ds::chip("dest-any", "any", is_any, move |_, _, cx| {
                    if let Some(s) = sw_any.upgrade() {
                        s.update(cx, |st, cx| { st.dest_scope = DestScope::Any; cx.notify(); });
                    }
                }))
            })
            .into_any_element()
    } else {
        let active_octets = if let DestScope::IpCidr(n) = dest_scope { *n } else { 4 };
        h_flex()
            .gap(px(6.))
            .child(ds::cidr_picker(&flow.destination_ip, active_octets, state_weak.clone()))
            .when(!hide_any, |el| {
                el.child(ds::chip("dest-ip-any", "any", false, move |_, _, cx| {
                    if let Some(s) = sw_any.upgrade() {
                        s.update(cx, |st, cx| { st.dest_scope = DestScope::Any; cx.notify(); });
                    }
                }))
            })
            .into_any_element()
    };

    ds::label_row("Destination", content)
}

fn rule_summary_line(
    process_name: Option<&str>,
    process_scope: &ProcessScope,
    dest_scope: &DestScope,
    flow: &FlowContext,
) -> gpui::AnyElement {
    let proc_label = match process_scope {
        ProcessScope::Specific => process_name.unwrap_or("unknown").to_string(),
        ProcessScope::All => "any process".to_string(),
    };

    let dest_label = match dest_scope {
        DestScope::DomainExact => flow
            .destination_domain
            .clone()
            .unwrap_or_else(|| flow.destination_ip.clone()),
        DestScope::DomainWildcard => {
            let domain = flow.destination_domain.clone().unwrap_or_default();
            format!("*.{}", domain_apex(&domain))
        }
        DestScope::Any => "any destination".to_string(),
        DestScope::IpCidr(n) => {
            let parts: Vec<&str> = flow.destination_ip.splitn(4, '.').collect();
            let mut octets: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
            while octets.len() < 4 { octets.push("0".to_string()); }
            for i in (*n as usize)..4 { octets[i] = "0".to_string(); }
            let prefix = n * 8;
            if *n == 4 { octets.join(".") } else { format!("{}/{prefix}", octets.join(".")) }
        }
    };

    div()
        .w_full()
        .py(px(4.))
        .px(px(8.))
        .rounded(px(4.))
        .bg(colors::surface())
        .border_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(11.))
                .text_color(colors::muted())
                .child(format!("Rule: {proc_label} → {dest_label}")),
        )
        .into_any_element()
}

// ---------------------------------------------------------------------------
// Duration scope toggle (session / permanent)
// ---------------------------------------------------------------------------

fn scope_toggle(
    state_weak: WeakEntity<AppState>,
    session_selected: bool,
    permanent_selected: bool,
) -> gpui::AnyElement {
    let state_weak_session = state_weak.clone();
    let state_weak_permanent = state_weak.clone();

    h_flex()
        .items_center()
        .bg(colors::surface())
        .px(px(6.))
        .py(px(4.))
        .rounded(px(4.))
        .border_1()
        .border_color(colors::border())
        .gap(px(2.))
        .child(pill_segment(
            "pill-session",
            "SESSION",
            session_selected,
            false,
            state_weak_session,
        ))
        .child(pill_segment(
            "pill-permanent",
            "PERMANENT",
            permanent_selected,
            true,
            state_weak_permanent,
        ))
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
        .px(px(8.))
        .py(px(2.))
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
                .text_color(if selected { colors::on_primary() } else { colors::muted() })
                .font_weight(gpui::FontWeight::BOLD)
                .text_size(px(10.))
                .child(label_text),
        )
        .into_any_element()
}

// ---------------------------------------------------------------------------
// Egress selector
// ---------------------------------------------------------------------------

fn egress_selector(
    state_weak: WeakEntity<AppState>,
    egresses: &[Egress],
    selected_index: usize,
) -> gpui::AnyElement {
    let max_visible = 6;
    let total = egresses.len();
    let visible_count = total.min(max_visible);
    let overflow = total.saturating_sub(max_visible);

    h_flex()
        .flex_1()
        .flex_wrap()
        .gap(px(4.))
        .max_h(px(48.))
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
                .px(px(8.))
                .py(px(2.))
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
                            gpui::hsla(0., 0., 0.40, 1.)
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
                    .px(px(8.))
                    .py(px(2.))
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

// ---------------------------------------------------------------------------
// Allow / Deny buttons
// ---------------------------------------------------------------------------

fn build_dest_matcher(flow: &FlowContext, dest_scope: &DestScope) -> DestinationMatcher {
    match dest_scope {
        DestScope::DomainExact => {
            if let Some(d) = &flow.destination_domain {
                DestinationMatcher::DomainExact(d.clone())
            } else {
                DestinationMatcher::IpExact(flow.destination_ip.clone())
            }
        }
        DestScope::DomainWildcard => {
            let domain = flow.destination_domain.clone().unwrap_or_default();
            DestinationMatcher::DomainWildcard(domain_apex(&domain))
        }
        DestScope::Any => DestinationMatcher::Any,
        DestScope::IpCidr(n) => {
            let parts: Vec<&str> = flow.destination_ip.splitn(4, '.').collect();
            let mut octets: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
            while octets.len() < 4 {
                octets.push("0".to_string());
            }
            for i in (*n as usize)..4 {
                octets[i] = "0".to_string();
            }
            let prefix = n * 8;
            if *n == 4 {
                DestinationMatcher::IpExact(flow.destination_ip.clone())
            } else {
                DestinationMatcher::Cidr(format!("{}/{prefix}", octets.join(".")))
            }
        }
    }
}

fn allow_button(
    pid: String,
    make_permanent: bool,
    _flow: FlowContext,
    selected_egress: Egress,
    dest_matcher: DestinationMatcher,
    rule_process_name: Option<String>,
    disabled: bool,
) -> gpui::AnyElement {
    let is_default = selected_egress.is_system_default;
    let egress_id = if is_default { None } else { Some(selected_egress.id.clone()) };

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
        .border_color(if disabled {
            colors::border()
        } else {
            colors::green_dim()
        })
        .when(!disabled, |el| el.cursor_pointer())
        .when(disabled, |el| el.opacity(0.35))
        .when(!disabled, |el| {
            el.on_click({
                move |_, _, cx| {
                    let pid = pid.clone();
                    let mk_perm = make_permanent;
                    let eid = egress_id.clone();
                    let dest = dest_matcher.clone();
                    let proc = rule_process_name.clone();
                    cx.spawn(async move |cx| {
                        let action = if eid.is_some() { RuleAction::Route } else { RuleAction::Allow };
                        let rule = Rule {
                            id: format!("ui-{}", daemon::unix_now()),
                            enabled: true,
                            action: action.clone(),
                            duration: if mk_perm {
                                RuleDuration::Permanent
                            } else {
                                RuleDuration::UntilRestart
                            },
                            process_name: proc,
                            destination: dest,
                            egress_id: eid,
                        };
                        let socket = std::env::var("LOGIGUARD_SOCKET_PATH")
                            .unwrap_or_else(|_| SOCKET_PATH.to_string());
                        let _ = cx
                            .background_executor()
                            .spawn(async move {
                                daemon::send_request(
                                    &socket,
                                    &ControlRequest::ResolvePendingWithRule {
                                        pending_id: pid,
                                        action,
                                        rule,
                                    },
                                )
                            })
                            .await;
                        std::process::exit(0);
                    })
                    .detach();
                }
            })
        })
        .child(
            div()
                .text_color(if disabled { colors::muted() } else { colors::green() })
                .text_size(px(18.))
                .child(if is_default { "\u{1F6E1}" } else { "\u{1F5A7}" }),
        )
        .child(
            div()
                .text_color(if disabled { colors::muted() } else { colors::green() })
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
    dest_matcher: DestinationMatcher,
    rule_process_name: Option<String>,
    disabled: bool,
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
        .border_color(if disabled {
            colors::border()
        } else {
            gpui::hsla(0., 0.80, 0.65, 0.50)
        })
        .when(!disabled, |el| el.cursor_pointer())
        .when(disabled, |el| el.opacity(0.35))
        .when(!disabled, |el| {
            el.on_click({
                move |_, _, cx| {
                    let pid = pid.clone();
                    let mk_perm = make_permanent;
                    let dest = dest_matcher.clone();
                    let proc = rule_process_name.clone();
                    cx.spawn(async move |cx| {
                        let rule = Rule {
                            id: format!("ui-{}", daemon::unix_now()),
                            enabled: true,
                            action: RuleAction::Deny,
                            duration: if mk_perm {
                                RuleDuration::Permanent
                            } else {
                                RuleDuration::UntilRestart
                            },
                            process_name: proc,
                            destination: dest,
                            egress_id: None,
                        };
                        let socket = std::env::var("LOGIGUARD_SOCKET_PATH")
                            .unwrap_or_else(|_| SOCKET_PATH.to_string());
                        let _ = cx
                            .background_executor()
                            .spawn(async move {
                                daemon::send_request(
                                    &socket,
                                    &ControlRequest::ResolvePendingWithRule {
                                        pending_id: pid,
                                        action: RuleAction::Deny,
                                        rule,
                                    },
                                )
                            })
                            .await;
                        std::process::exit(0);
                    })
                    .detach();
                }
            })
        })
        .child(
            div()
                .text_color(if disabled { colors::muted() } else { colors::error() })
                .text_size(px(18.))
                .child("\u{1F6AB}"),
        )
        .child(
            div()
                .text_color(if disabled { colors::muted() } else { colors::error() })
                .font_weight(gpui::FontWeight::BOLD)
                .text_size(px(11.))
                .child("DENY"),
        )
        .into_any_element()
}
