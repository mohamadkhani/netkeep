//! Proxies tab — DataTable delegate for managing proxy configurations.

use control_api::{ControlRequest, ControlResponse};
use core_types::{ProxyAuth, ProxyConfig, ProxyProtocol};
use gpui::{
    App, AppContext as _, Context, InteractiveElement, IntoElement, ParentElement,
    StatefulInteractiveElement, Styled, WeakEntity, Window, div, px,
};

use gpui_component::table::{Column, TableDelegate, TableState};

use crate::colors;
use crate::daemon;

use super::SettingsState;

// ── Delegate ───────────────────────────────────────────────────────────

/// Table delegate that displays proxy configurations.
pub struct ProxiesDelegate {
    pub proxies: Vec<ProxyConfig>,
    pub state_weak: WeakEntity<SettingsState>,
    pub socket_path: String,
    columns: Vec<Column>,
}

impl ProxiesDelegate {
    pub fn new(
        proxies: Vec<ProxyConfig>,
        state_weak: WeakEntity<SettingsState>,
        socket_path: String,
    ) -> Self {
        Self {
            proxies,
            state_weak,
            socket_path,
            columns: vec![
                Column::new("name", "Name").width(px(140.)),
                Column::new("protocol", "Protocol").width(px(80.)),
                Column::new("address", "Address").width(px(160.)),
                Column::new("auth", "Auth").width(px(120.)),
                Column::new("status", "Status").width(px(80.)),
                Column::new("controls", "").width(px(140.)).resizable(false),
            ],
        }
    }
}

impl TableDelegate for ProxiesDelegate {
    fn columns_count(&self, _cx: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _cx: &App) -> usize {
        self.proxies.len()
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
        let Some(proxy) = self.proxies.get(row_ix) else {
            return div().into_any_element();
        };

        match col_ix {
            // Name
            0 => div()
                .text_color(if proxy.enabled { colors::text() } else { colors::muted() })
                .child(proxy.name.clone())
                .into_any_element(),
            // Protocol badge
            1 => {
                let (label, color) = match proxy.protocol {
                    ProxyProtocol::Socks5 => ("SOCKS5", colors::green()),
                    ProxyProtocol::Http => ("HTTP", colors::primary()),
                    ProxyProtocol::Shadowsocks => ("SS", colors::teal()),
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
            // Address
            2 => div()
                .text_color(if proxy.enabled { colors::text() } else { colors::muted() })
                .child(format!("{}:{}", proxy.host, proxy.port))
                .into_any_element(),
            // Auth
            3 => {
                let auth_summary = match &proxy.auth {
                    ProxyAuth::None => "none".to_string(),
                    ProxyAuth::Basic { username, .. } => format!("{username}:***"),
                    ProxyAuth::Shadowsocks { method, .. } => method.clone(),
                };
                div()
                    .text_color(colors::muted())
                    .child(auth_summary)
                    .into_any_element()
            }
            // Status badge
            4 => {
                let (label, color) = if proxy.enabled {
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
            // Controls (toggle + delete)
            5 => {
                let pid_toggle = proxy.id.clone();
                let pid_del = proxy.id.clone();
                let proxy_toggle = proxy.clone();
                let socket_toggle = self.socket_path.clone();
                let state_toggle = self.state_weak.clone();
                let sock_del = self.socket_path.clone();
                let state_del = self.state_weak.clone();

                div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    // Toggle
                    .child(
                        div()
                            .id(gpui::ElementId::Name(format!("px-tog-{pid_toggle}").into()))
                            .text_size(px(10.))
                            .text_color(if proxy.enabled { colors::muted() } else { colors::green() })
                            .cursor_pointer()
                            .px(px(4.))
                            .py(px(1.))
                            .rounded(px(3.))
                            .border_1()
                            .border_color(if proxy.enabled { colors::border() } else { colors::green() })
                            .on_click(move |_, _, cx| {
                                let mut toggled = proxy_toggle.clone();
                                toggled.enabled = !toggled.enabled;
                                let to_send = toggled.clone();
                                let weak = state_toggle.clone();
                                let sock = socket_toggle.clone();
                                cx.spawn(async move |cx| {
                                    let res = cx
                                        .background_executor()
                                        .spawn(async move {
                                            daemon::send_request(
                                                &sock,
                                                &ControlRequest::UpsertProxy(to_send),
                                            )
                                        })
                                        .await;
                                    if let Some(st) = weak.upgrade() {
                                        let _ = cx.update_entity(&st, |s: &mut SettingsState, cx| {
                                            match res {
                                                Ok(ControlResponse::Ok) => {
                                                    s.status = Some("Proxy updated.".into());
                                                }
                                                Ok(ControlResponse::Error(msg)) => {
                                                    s.status = Some(format!("failed: {msg}"));
                                                }
                                                Err(e) => {
                                                    s.status = Some(format!("failed: {e}"));
                                                }
                                                _ => {
                                                    s.status = Some("unexpected response".into());
                                                }
                                            }
                                            cx.notify();
                                        });
                                    }
                                })
                                .detach();
                            })
                            .child(if proxy.enabled { "Disable" } else { "Enable" }),
                    )
                    // Delete
                    .child(
                        div()
                            .id(gpui::ElementId::Name(format!("px-del-{pid_del}").into()))
                            .text_size(px(11.))
                            .text_color(colors::error())
                            .cursor_pointer()
                            .px(px(6.))
                            .py(px(2.))
                            .rounded(px(3.))
                            .border_1()
                            .border_color(colors::error())
                            .on_click(move |_, _, cx| {
                                let pid_req = pid_del.clone();
                                let pid_cmp = pid_del.clone();
                                let socket_path = sock_del.clone();
                                let weak = state_del.clone();
                                cx.spawn(async move |cx| {
                                    let res = cx
                                        .background_executor()
                                        .spawn(async move {
                                            daemon::send_request(
                                                &socket_path,
                                                &ControlRequest::DeleteProxy { id: pid_req },
                                            )
                                        })
                                        .await;
                                    if let Some(st) = weak.upgrade() {
                                        let _ = cx.update_entity(&st, |s: &mut SettingsState, cx| {
                                            match res {
                                                Ok(ControlResponse::Ok) => {
                                                    s.proxies.retain(|p| p.id != pid_cmp);
                                                    s.status = Some("Proxy removed.".into());
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
                            })
                            .child("Delete"),
                    )
                    .into_any_element()
            }
            _ => div().into_any_element(),
        }
    }
}
