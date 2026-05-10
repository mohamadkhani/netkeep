//! Egress tab — DataTable delegate for egress route management.

use control_api::{ControlRequest, ControlResponse};
use core_types::{Egress, RouteTarget};
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

/// Table delegate that displays egress routes.
pub struct EgressDelegate {
    pub egresses: Vec<Egress>,
    pub state_weak: WeakEntity<SettingsState>,
    pub socket_path: String,
    columns: Vec<Column>,
}

impl EgressDelegate {
    pub fn new(
        egresses: Vec<Egress>,
        state_weak: WeakEntity<SettingsState>,
        socket_path: String,
    ) -> Self {
        Self {
            egresses,
            state_weak,
            socket_path,
            columns: vec![
                Column::new("name", "Name").width(px(140.)),
                Column::new("type", "Type").width(px(80.)),
                Column::new("targets", "Targets").width(px(200.)),
                Column::new("dns", "DNS").width(px(140.)),
                Column::new("status", "Status").width(px(80.)),
                Column::new("controls", "").width(px(80.)).resizable(false),
            ],
        }
    }
}

impl EgressDelegate {
    fn egress_type_label(egress: &Egress) -> (&'static str, gpui::Hsla) {
        if egress.is_system_default {
            return ("SYSTEM", colors::muted());
        }
        if egress.targets.iter().any(|t| matches!(t, RouteTarget::Proxy(_))) {
            return ("PROXY", colors::teal());
        }
        if egress.targets.iter().any(|t| matches!(t, RouteTarget::Tun(_))) {
            return ("VPN", colors::green());
        }
        ("DIRECT", colors::muted())
    }
}

impl TableDelegate for EgressDelegate {
    fn columns_count(&self, _cx: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _cx: &App) -> usize {
        self.egresses.len()
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
        let Some(egress) = self.egresses.get(row_ix) else {
            return div().into_any_element();
        };

        match col_ix {
            // Name
            0 => {
                let mut el = div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .child(
                        div()
                            .text_color(colors::text())
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(egress.name.clone()),
                    );
                if !egress.is_system_default {
                    el = el.child(
                        div()
                            .text_size(px(10.))
                            .text_color(colors::muted())
                            .child(format!("({})", egress.id)),
                    );
                }
                el.into_any_element()
            }
            // Type badge
            1 => {
                let (label, color) = Self::egress_type_label(egress);
                div()
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .text_size(px(10.))
                            .text_color(color)
                            .px(px(6.))
                            .py(px(2.))
                            .rounded(px(3.))
                            .border_1()
                            .border_color(color)
                            .bg(colors::bg())
                            .child(label.to_string()),
                    )
                    .into_any_element()
            }
            // Targets
            2 => {
                if egress.targets.is_empty() {
                    div()
                        .text_color(colors::muted())
                        .child("default routing")
                        .into_any_element()
                } else {
                    let targets: Vec<String> =
                        egress.targets.iter().map(|t| route_summary(t)).collect();
                    div()
                        .text_color(colors::text())
                        .child(targets.join(", "))
                        .into_any_element()
                }
            }
            // DNS
            3 => {
                if egress.dns_servers.is_empty() {
                    div()
                        .text_color(colors::muted())
                        .child("—")
                        .into_any_element()
                } else {
                    div()
                        .text_color(colors::text())
                        .child(egress.dns_servers.join(", "))
                        .into_any_element()
                }
            }
            // Status badge
            4 => {
                let (label, color) =
                    if egress.is_available || egress.is_system_default {
                        ("ACTIVE", colors::green())
                    } else {
                        ("INACTIVE", colors::muted())
                    };
                div()
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .text_size(px(10.))
                            .text_color(color)
                            .px(px(6.))
                            .py(px(2.))
                            .rounded(px(3.))
                            .border_1()
                            .border_color(color)
                            .bg(colors::bg())
                            .child(label.to_string()),
                    )
                    .into_any_element()
            }
            // Controls (delete for non-system)
            5 => {
                if egress.is_system_default {
                    return div().into_any_element();
                }
                let eid = egress.id.clone();
                let socket_path = self.socket_path.clone();
                let weak = self.state_weak.clone();

                div()
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .id(gpui::ElementId::Name(format!("eg-del-{eid}").into()))
                            .text_size(px(11.))
                            .text_color(colors::error())
                            .cursor_pointer()
                            .px(px(6.))
                            .py(px(2.))
                            .rounded(px(3.))
                            .border_1()
                            .border_color(colors::error())
                            .on_click(move |_, _, cx| {
                                let eid_req = eid.clone();
                                let eid_cmp = eid.clone();
                                let socket_path = socket_path.clone();
                                let weak = weak.clone();
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
                                        let _ = cx.update_entity(&st, |s: &mut SettingsState, cx| {
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
                            })
                            .child("Delete"),
                    )
                    .into_any_element()
            }
            _ => div().into_any_element(),
        }
    }
}
