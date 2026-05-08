//! Rules and egress management window (opened from the tray menu).

use control_api::{ControlRequest, ControlResponse};
use core_types::{Egress, RouteTarget, Rule};
use gpui::{
    App, AppContext as _, Context, ElementId, Entity, InteractiveElement, IntoElement,
    ParentElement, Render, StatefulInteractiveElement, Styled, WeakEntity, Window, div, px,
    prelude::FluentBuilder as _,
};
use gpui_component::input::{Input, InputState};
use gpui_component::scroll::ScrollableElement;
use gpui_component::{h_flex, v_flex};

use crate::colors;
use crate::daemon::{self};

pub struct ManagementState {
    pub rules: Vec<Rule>,
    pub egresses: Vec<Egress>,
    pub status: Option<String>,
    /// Incremented after each successful load so DNS input widgets rebuild.
    pub load_generation: u64,
    pub socket_path: String,
}

impl ManagementState {
    pub fn new(socket_path: String) -> Self {
        Self {
            rules: Vec::new(),
            egresses: Vec::new(),
            status: None,
            load_generation: 0,
            socket_path,
        }
    }
}

pub struct ManagementApp {
    state: Entity<ManagementState>,
    dns_inputs: Vec<Entity<InputState>>,
    dns_built_generation: u64,
}

impl ManagementApp {
    pub fn new(state: Entity<ManagementState>, cx: &mut Context<Self>) -> Self {
        cx.observe(&state, |_, _, cx| cx.notify()).detach();

        let weak = state.downgrade();
        let socket_path = state.read(cx).socket_path.clone();
        cx.spawn(async move |_this, cx| {
            fetch_and_apply(weak, &socket_path, cx).await;
        })
        .detach();

        Self {
            state,
            dns_inputs: Vec::new(),
            dns_built_generation: 0,
        }
    }

    fn sync_dns_inputs(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let gen = self.state.read(cx).load_generation;
        if gen == self.dns_built_generation {
            return;
        }
        let egresses = self.state.read(cx).egresses.clone();
        self.dns_inputs.clear();
        for eg in &egresses {
            let v = eg.dns_servers.join(", ");
            let inp = cx.new(|cx| InputState::new(window, cx).default_value(v));
            self.dns_inputs.push(inp);
        }
        self.dns_built_generation = gen;
    }

}

async fn fetch_and_apply(
    state: WeakEntity<ManagementState>,
    socket_path: &str,
    cx: &mut gpui::AsyncApp,
) {
    let rules_task = cx.background_executor().spawn({
        let p = socket_path.to_string();
        async move { daemon::send_request(&p, &ControlRequest::ListRules) }
    });
    let egress_task = cx.background_executor().spawn({
        let p = socket_path.to_string();
        async move { daemon::send_request(&p, &ControlRequest::ListEgresses) }
    });
    let (rules_r, egress_r) = (rules_task.await, egress_task.await);

    let Some(entity) = state.upgrade() else {
        return;
    };

    match (rules_r, egress_r) {
        (Ok(ControlResponse::RuleList(rules)), Ok(ControlResponse::EgressList(egresses))) => {
            let merged = daemon::merge_egress_availability(egresses);
            let _ = cx.update_entity(&entity, |s, cx| {
                s.rules = rules;
                s.egresses = merged;
                s.load_generation = s.load_generation.saturating_add(1);
                s.status = None;
                cx.notify();
            });
        }
        (Err(e), _) | (_, Err(e)) => {
            let _ = cx.update_entity(&entity, |s, cx| {
                s.status = Some(format!("load failed: {e}"));
                cx.notify();
            });
        }
        _ => {
            let _ = cx.update_entity(&entity, |s, cx| {
                s.status = Some("unexpected response from daemon".into());
                cx.notify();
            });
        }
    }
}

fn parse_dns_csv(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

fn route_summary(t: &RouteTarget) -> String {
    match t {
        RouteTarget::Tun(n) => format!("tun:{n}"),
        RouteTarget::Device(n) => format!("dev:{n}"),
    }
}

impl Render for ManagementApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.sync_dns_inputs(window, cx);

        let state = self.state.read(cx);
        let status = state.status.clone();
        let socket_path = state.socket_path.clone();
        let rules = state.rules.clone();
        let egresses = state.egresses.clone();

        let weak = self.state.downgrade();
        let weak_refresh = weak.clone();
        let socket_for_refresh = socket_path.clone();

        v_flex()
            .size_full()
            .bg(colors::bg())
            .text_color(colors::text())
            .child(
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .px(px(16.))
                    .py(px(12.))
                    .bg(colors::surface_container_high())
                    .border_b_1()
                    .border_color(colors::border())
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .text_size(px(14.))
                            .child("Rules & egresses"),
                    )
                    .child(
                        div()
                            .id(ElementId::Name("mgmt-refresh".into()))
                            .text_size(px(12.))
                            .text_color(colors::primary())
                            .cursor_pointer()
                            .on_click({
                                let weak_refresh = weak_refresh.clone();
                                let socket_for_refresh = socket_for_refresh.clone();
                                move |_, _, cx| {
                                    let wr = weak_refresh.clone();
                                    let sp = socket_for_refresh.clone();
                                    cx.spawn(async move |cx| {
                                        fetch_and_apply(wr, &sp, cx).await;
                                    })
                                    .detach();
                                }
                            })
                            .child("Refresh"),
                    ),
            )
            .when_some(status, |el, msg| {
                el.child(
                    div()
                        .w_full()
                        .px(px(16.))
                        .py(px(8.))
                        .bg(colors::surface_container())
                        .text_color(colors::error())
                        .text_size(px(12.))
                        .child(msg),
                )
            })
            .child(
                v_flex()
                    .id(ElementId::Name("mgmt-body".into()))
                    .flex_1()
                    .overflow_y_scrollbar()
                    .px(px(16.))
                    .py(px(12.))
                    .gap(px(20.))
                    .child(
                        v_flex()
                            .w_full()
                            .gap(px(8.))
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(colors::muted())
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .child("RULES"),
                            )
                            .children(
                                rules
                                    .iter()
                                    .map(|rule| rule_row(rule, weak.clone(), socket_path.clone())),
                            ),
                    )
                    .child(
                        v_flex()
                            .w_full()
                            .gap(px(8.))
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(colors::muted())
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .child("EGRESSES"),
                            )
                            .children(egresses.iter().enumerate().map(|(i, eg)| {
                                egress_row(
                                    i,
                                    eg,
                                    self.dns_inputs.get(i),
                                    weak.clone(),
                                    socket_path.clone(),
                                )
                            })),
                    ),
            )
            .into_any_element()
    }
}

fn rule_row(
    rule: &Rule,
    state_weak: WeakEntity<ManagementState>,
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
                .child(
                    div()
                        .id(ElementId::Name(format!("mgmt-rule-en-{id_toggle}").into()))
                        .text_size(px(11.))
                        .text_color(if enabled { colors::green() } else { colors::muted() })
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
                                            if let Some(x) = s.rules.iter_mut().find(|x| x.id == tid) {
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
                .child(
                    div()
                        .id(ElementId::Name(format!("mgmt-rule-del-{id_del}").into()))
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

fn egress_row(
    index: usize,
    egress: &Egress,
    dns_input: Option<&Entity<InputState>>,
    state_weak: WeakEntity<ManagementState>,
    socket_path: String,
) -> gpui::AnyElement {
    let targets = if egress.targets.is_empty() {
        "default routing".to_string()
    } else {
        egress.targets.iter().map(route_summary).collect::<Vec<_>>().join(", ")
    };
    let avail = if egress.is_available {
        "up"
    } else {
        "down"
    };
    let eg_save = egress.clone();

    let dns_el = if let Some(inp) = dns_input {
        let inp = inp.clone();
        let weak_dns = state_weak.clone();
        let socket_dns = socket_path.clone();
        let idx = index;
        h_flex()
            .w_full()
            .gap(px(8.))
            .items_center()
            .child(
                Input::new(&inp).w_full().appearance(true),
            )
            .child(
                div()
                    .id(ElementId::Name(format!("mgmt-eg-dns-{idx}").into()))
                    .text_size(px(11.))
                    .text_color(colors::primary())
                    .cursor_pointer()
                    .px(px(8.))
                    .py(px(4.))
                    .rounded(px(4.))
                    .border_1()
                    .border_color(colors::primary())
                    .on_click(move |_, _, cx| {
                        let inp = inp.clone();
                        let weak_dns = weak_dns.clone();
                        let mut eg_save = eg_save.clone();
                        let socket_dns = socket_dns.clone();
                        cx.spawn(async move |cx| {
                            let text = cx
                                .read_entity(&inp, |i: &InputState, _: &App| i.value().to_string())
                                .unwrap_or_default();
                            eg_save.dns_servers = parse_dns_csv(&text);
                            let dns_after = eg_save.dns_servers.clone();
                            let to_send = eg_save.clone();
                            let res = cx
                                .background_executor()
                                .spawn(async move {
                                    daemon::send_request(
                                        &socket_dns,
                                        &ControlRequest::UpsertEgress(to_send),
                                    )
                                })
                                .await;
                            if let Some(st) = weak_dns.upgrade() {
                                let _ = cx.update_entity(&st, |s, cx| {
                                    match res {
                                        Ok(ControlResponse::Ok) => {
                                            s.status = Some("DNS saved.".into());
                                            if let Some(e) = s.egresses.get_mut(idx) {
                                                e.dns_servers = dns_after.clone();
                                            }
                                        }
                                        Ok(ControlResponse::Error(msg)) => {
                                            s.status = Some(format!("save failed: {msg}"));
                                        }
                                        Err(e) => {
                                            s.status = Some(format!("save failed: {e}"));
                                        }
                                        _ => {
                                            s.status = Some("unexpected save response".into());
                                        }
                                    }
                                    cx.notify();
                                });
                            }
                        })
                        .detach();
                    })
                    .child("Save DNS"),
            )
            .into_any_element()
    } else {
        div()
            .text_size(px(11.))
            .text_color(colors::muted())
            .child("…")
            .into_any_element()
    };

    h_flex()
        .w_full()
        .items_start()
        .justify_between()
        .gap(px(8.))
        .py(px(8.))
        .px(px(8.))
        .rounded(px(4.))
        .bg(colors::surface_container())
        .border_1()
        .border_color(colors::border())
        .child(
            v_flex()
                .flex_1()
                .gap(px(4.))
                .child(
                    h_flex()
                        .gap(px(8.))
                        .items_center()
                        .child(
                            div()
                                .text_size(px(12.))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(egress.name.clone()),
                        )
                        .child(
                            div()
                                .text_size(px(10.))
                                .text_color(colors::muted())
                                .child(format!("({})", egress.id)),
                        )
                        .when(!egress.is_system_default, |el| {
                            el.child(
                                div()
                                    .text_size(px(10.))
                                    .text_color(colors::teal())
                                    .child(avail),
                            )
                        }),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(colors::muted())
                        .child(targets),
                )
                .child(dns_el),
        )
        .when(!egress.is_system_default, |el| {
            el.child(
                div()
                    .id(ElementId::Name(format!("mgmt-eg-del-{}", egress.id).into()))
                    .text_size(px(11.))
                    .text_color(colors::error())
                    .cursor_pointer()
                    .px(px(8.))
                    .py(px(4.))
                    .rounded(px(4.))
                    .border_1()
                    .border_color(colors::error())
                    .on_click({
                        let eid = egress.id.clone();
                        let socket_path = socket_path.clone();
                        let weak = state_weak.clone();
                        move |_, _, cx| {
                            let weak = weak.clone();
                            let eid_req = eid.clone();
                            let eid_cmp = eid.clone();
                            let socket_path = socket_path.clone();
                            cx.spawn(async move |cx| {
                                let res = cx
                                    .background_executor()
                                    .spawn(async move {
                                        daemon::send_request(
                                            &socket_path,
                                            &ControlRequest::DeleteEgress { id: eid_req },
                                        )
                                    })
                                    .await;
                                if let Some(st) = weak.upgrade() {
                                    let _ = cx.update_entity(&st, |s, cx| {
                                        match res {
                                            Ok(ControlResponse::Ok) => {
                                                s.egresses.retain(|e| e.id != eid_cmp);
                                                s.load_generation =
                                                    s.load_generation.saturating_add(1);
                                                s.status = Some("Egress removed.".into());
                                            }
                                            Ok(ControlResponse::Error(msg)) => {
                                                s.status = Some(format!("delete failed: {msg}"));
                                            }
                                            Err(e) => {
                                                s.status = Some(format!("delete failed: {e}"));
                                            }
                                            _ => {
                                                s.status = Some("unexpected delete response".into());
                                            }
                                        }
                                        cx.notify();
                                    });
                                }
                            })
                            .detach();
                        }
                    })
                    .child("Delete"),
            )
        })
        .into_any_element()
}
