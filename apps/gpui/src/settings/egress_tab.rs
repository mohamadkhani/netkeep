//! Egress tab — displays egress routes with DNS editing and delete actions.

use control_api::{ControlRequest, ControlResponse};
use core_types::Egress;
use gpui::{
    App, AppContext as _, ElementId, Entity, InteractiveElement, IntoElement,
    ParentElement, StatefulInteractiveElement, Styled, WeakEntity, div, px,
    prelude::FluentBuilder as _,
};
use gpui_component::input::{Input, InputState};
use gpui_component::scroll::ScrollableElement;
use gpui_component::{h_flex, v_flex};

use crate::colors;
use crate::daemon;

use super::SettingsState;
use super::helpers::{parse_dns_csv, route_summary};

/// Render the full Egress tab content (scrollable list of egress rows).
pub fn render_egress_tab(
    egresses: Vec<Egress>,
    dns_inputs: &[Entity<InputState>],
    state_weak: WeakEntity<SettingsState>,
    socket_path: String,
) -> gpui::AnyElement {
    v_flex()
        .id(ElementId::Name("egress-tab-content".into()))
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
                .child("EGRESS ROUTES"),
        )
        // Egress list
        .children(egresses.iter().enumerate().map(|(i, eg)| {
            egress_row(
                i,
                eg,
                dns_inputs.get(i),
                state_weak.clone(),
                socket_path.clone(),
            )
        }))
        .into_any_element()
}

/// Render a single egress row with DNS input and delete button.
fn egress_row(
    index: usize,
    egress: &Egress,
    dns_input: Option<&Entity<InputState>>,
    state_weak: WeakEntity<SettingsState>,
    socket_path: String,
) -> gpui::AnyElement {
    let targets = if egress.targets.is_empty() {
        "default routing".to_string()
    } else {
        egress
            .targets
            .iter()
            .map(route_summary)
            .collect::<Vec<_>>()
            .join(", ")
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
            .child(Input::new(&inp).w_full().appearance(true))
            .child(
                div()
                    .id(ElementId::Name(format!("eg-dns-{idx}").into()))
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
                                .read_entity(&inp, |i: &InputState, _: &App| {
                                    i.value().to_string()
                                })
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
                    .id(ElementId::Name(format!("eg-del-{}", egress.id).into()))
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
                                                s.status =
                                                    Some(format!("delete failed: {msg}"));
                                            }
                                            Err(e) => {
                                                s.status =
                                                    Some(format!("delete failed: {e}"));
                                            }
                                            _ => {
                                                s.status =
                                                    Some("unexpected delete response".into());
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
