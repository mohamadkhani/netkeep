//! Settings window (opened from the tray menu).
//!
//! Uses gpui-component `Table` (DataTable) for each tab and `Dialog` for
//! editing/viewing details of egress and proxy items.

mod egress_tab;
mod helpers;
mod proxies_tab;
mod rules_tab;

use std::sync::{Arc, Mutex};

use control_api::{ControlRequest, ControlResponse};
use core_types::{Egress, ProxyAuth, ProxyConfig, ProxyProtocol};
use gpui::{
    div, px, AppContext as _, Context, Entity, InteractiveElement, IntoElement, ParentElement,
    Render, StatefulInteractiveElement, Styled, Subscription, Window,
};
use gpui_component::input::{Input, InputState};
use gpui_component::tab::{Tab, TabBar};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::TitleBar;
use gpui_component::WindowExt as _;
use gpui_component::{h_flex, v_flex};

use crate::colors;
use crate::components::{field_label, modal_footer, modal_header, proto_btn};

use egress_tab::EgressDelegate;
use proxies_tab::ProxiesDelegate;
use rules_tab::RulesDelegate;

// Re-export helpers needed by main.rs (refresh action).
pub use helpers::fetch_and_apply;

// ── Tab enum ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
pub enum SettingsTab {
    Rules,
    Egress,
    Proxies,
}

// ── State ──────────────────────────────────────────────────────────────

pub struct SettingsState {
    pub rules: Vec<core_types::Rule>,
    pub egresses: Vec<Egress>,
    pub proxies: Vec<ProxyConfig>,
    pub status: Option<String>,
    /// Incremented after each successful load so DNS input widgets rebuild.
    pub load_generation: u64,
    pub socket_path: String,
    pub active_tab: SettingsTab,
    /// Set by the Edit button in the egress table; drained by SettingsApp observer.
    pub egress_edit_request: Option<Egress>,
    /// Set by the Edit button in the proxy table; drained by SettingsApp observer.
    pub proxy_edit_request: Option<ProxyConfig>,
}

impl SettingsState {
    pub fn new(socket_path: String) -> Self {
        Self {
            rules: Vec::new(),
            egresses: Vec::new(),
            proxies: Vec::new(),
            status: None,
            load_generation: 0,
            socket_path,
            active_tab: SettingsTab::Rules,
            egress_edit_request: None,
            proxy_edit_request: None,
        }
    }
}

// ── App (Render) ───────────────────────────────────────────────────────

pub struct SettingsApp {
    state: Entity<SettingsState>,
    rules_table: Entity<TableState<RulesDelegate>>,
    egress_table: Entity<TableState<EgressDelegate>>,
    proxy_table: Entity<TableState<ProxiesDelegate>>,
    _subscriptions: Vec<Subscription>,
}

impl SettingsApp {
    pub fn new(state: Entity<SettingsState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let socket_path = state.read(cx).socket_path.clone();
        let weak = state.downgrade();

        // Create table delegates
        let rules_table = cx.new(|cx| {
            TableState::new(
                RulesDelegate::new(vec![], weak.clone(), socket_path.clone()),
                window,
                cx,
            )
        });

        let egress_table = cx.new(|cx| {
            TableState::new(
                EgressDelegate::new(vec![], weak.clone(), socket_path.clone()),
                window,
                cx,
            )
        });

        let proxy_table = cx.new(|cx| {
            TableState::new(
                ProxiesDelegate::new(vec![], weak.clone(), socket_path.clone()),
                window,
                cx,
            )
        });

        // Subscribe to table events (double-click opens dialog)
        let mut subscriptions = Vec::new();
        subscriptions.push(cx.subscribe_in(&egress_table, window, Self::on_egress_table_event));
        subscriptions.push(cx.subscribe_in(&proxy_table, window, Self::on_proxy_table_event));

        // Observe state changes: refresh tables, handle edit requests, re-render.
        // Note: do NOT call cx.notify() when clearing request fields — that would re-trigger this observer.
        cx.observe_in(&state, window, |this, _, window, cx| {
            this.sync_tables(cx);

            // Drain egress edit request → open pre-filled egress form.
            let egress_edit = this.state.read(cx).egress_edit_request.clone();
            if let Some(egress) = egress_edit {
                let _ = cx.update_entity(&this.state, |s, _cx| {
                    s.egress_edit_request = None;
                    // intentionally no cx.notify() — would re-enter this observer
                });
                this.open_egress_form_dialog(Some(egress), window, cx);
                return;
            }

            // Drain proxy edit request → open pre-filled proxy form.
            let proxy_edit = this.state.read(cx).proxy_edit_request.clone();
            if let Some(proxy) = proxy_edit {
                let _ = cx.update_entity(&this.state, |s, _cx| {
                    s.proxy_edit_request = None;
                    // intentionally no cx.notify() here to avoid re-entering this observer
                });
                this.open_proxy_form_dialog(Some(proxy), window, cx);
                return;
            }

            cx.notify();
        })
        .detach();

        // Initial fetch
        let weak_refresh = weak.clone();
        let socket_for_refresh = socket_path.clone();
        cx.spawn(async move |_this, cx| {
            fetch_and_apply(weak_refresh, &socket_for_refresh, cx).await;
        })
        .detach();

        Self {
            state,
            rules_table,
            egress_table,
            proxy_table,
            _subscriptions: subscriptions,
        }
    }

    /// Sync table delegate data from the shared state entity.
    fn sync_tables(&mut self, cx: &mut Context<Self>) {
        let state = self.state.read(cx);
        let rules = state.rules.clone();
        let egresses = state.egresses.clone();
        let proxies = state.proxies.clone();
        let weak = self.state.downgrade();
        let socket = state.socket_path.clone();

        self.rules_table.update(cx, |table, _| {
            table.delegate_mut().rules = rules;
            table.delegate_mut().state_weak = weak.clone();
            table.delegate_mut().socket_path = socket.clone();
        });
        self.egress_table.update(cx, |table, _| {
            table.delegate_mut().egresses = egresses;
            table.delegate_mut().state_weak = weak.clone();
            table.delegate_mut().socket_path = socket.clone();
        });
        self.proxy_table.update(cx, |table, _| {
            table.delegate_mut().proxies = proxies;
            table.delegate_mut().state_weak = weak.clone();
            table.delegate_mut().socket_path = socket.clone();
        });
    }

    /// Handle egress table events — double-click opens edit form.
    fn on_egress_table_event(
        &mut self,
        _table: &Entity<TableState<EgressDelegate>>,
        event: &TableEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let TableEvent::DoubleClickedRow(row_ix) = event {
            let egresses = &self.state.read(cx).egresses;
            if let Some(egress) = egresses.get(*row_ix) {
                if !egress.is_system_default {
                    let egress = egress.clone();
                    self.open_egress_form_dialog(Some(egress), window, cx);
                }
            }
        }
    }

    /// Handle proxy table events — double-click opens edit form.
    fn on_proxy_table_event(
        &mut self,
        _table: &Entity<TableState<ProxiesDelegate>>,
        event: &TableEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let TableEvent::DoubleClickedRow(row_ix) = event {
            let proxies = &self.state.read(cx).proxies;
            if let Some(proxy) = proxies.get(*row_ix) {
                let proxy = proxy.clone();
                self.open_proxy_form_dialog(Some(proxy), window, cx);
            }
        }
    }

    /// Open the egress form dialog for adding (existing = None) or editing (existing = Some).
    fn open_egress_form_dialog(
        &mut self,
        existing: Option<Egress>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let state_weak = self.state.downgrade();
        let socket_path = self.state.read(cx).socket_path.clone();

        let is_edit = existing.is_some();
        let existing_id = existing.as_ref().map(|e| e.id.clone());
        let init_name = existing.as_ref().map(|e| e.name.as_str()).unwrap_or("New Egress").to_string();
        let init_color = existing.as_ref().map(|e| e.color.as_str()).unwrap_or("#3b82f6").to_string();
        let init_targets = existing
            .as_ref()
            .map(|e| e.targets.iter().map(|t| helpers::route_summary(t)).collect::<Vec<_>>().join(", "))
            .unwrap_or_else(|| "dev:eth0".to_string());
        let init_dns = existing.as_ref().map(|e| e.dns_servers.join(", ")).unwrap_or_default();

        let name_input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s.set_value(init_name.clone(), window, cx);
            s
        });
        let color_input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s.set_value(init_color.clone(), window, cx);
            s
        });
        let targets_input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s.set_value(init_targets.clone(), window, cx);
            s
        });
        let dns_input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s.set_value(init_dns.clone(), window, cx);
            s
        });

        let name_c    = name_input.clone();
        let color_c   = color_input.clone();
        let targets_c = targets_input.clone();
        let dns_c     = dns_input.clone();

        let hdr_icon  = if is_edit { "✏" } else { "⊕" };
        let hdr_title = if is_edit { "EDIT EGRESS" } else { "ADD EGRESS" };
        let ok_label  = if is_edit { "Save" } else { "Add Egress" };

        window.open_dialog(cx, move |dialog, _, _cx| {
            let name_i    = name_c.clone();
            let color_i   = color_c.clone();
            let targets_i = targets_c.clone();
            let dns_i     = dns_c.clone();
            let state_w   = state_weak.clone();
            let sock      = socket_path.clone();
            let eid       = existing_id.clone();

            dialog
                .p(px(0.))
                .close_button(false)
                .title(modal_header(hdr_icon, hdr_title))
                .w(px(480.))
                .button_props(
                    gpui_component::dialog::DialogButtonProps::default()
                        .ok_text(ok_label)
                        .cancel_text("Cancel"),
                )
                .footer(|ok, cancel, w, cx| {
                    vec![modal_footer(cancel(w, cx), ok(w, cx))]
                })
                .child(
                    v_flex()
                        .px(px(16.))
                        .py(px(16.))
                        .gap(px(16.))
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(field_label("NAME"))
                                .child(Input::new(&name_c)),
                        )
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(field_label("COLOR (hex)"))
                                .child(Input::new(&color_c)),
                        )
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(field_label("TARGETS  (dev:eth0, tun:wg0, proxy:id)"))
                                .child(Input::new(&targets_c)),
                        )
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(field_label("DNS SERVERS  (comma-separated, empty = system)"))
                                .child(Input::new(&dns_c)),
                        ),
                )
                .on_ok(move |_, _, cx| {
                    let name      = name_i.read(cx).value().to_string();
                    let color     = color_i.read(cx).value().to_string();
                    let targets_s = targets_i.read(cx).value().to_string();
                    let dns_s     = dns_i.read(cx).value().to_string();
                    let targets   = helpers::parse_targets_csv(&targets_s);
                    let dns       = helpers::parse_dns_csv(&dns_s);
                    let id        = eid.clone().unwrap_or_else(|| format!("eg-{}", crate::daemon::unix_now()));
                    let egress = Egress {
                        id,
                        name:    if name.trim().is_empty()  { "New Egress".into() } else { name },
                        color:   if color.trim().is_empty() { "#3b82f6".into()    } else { color },
                        targets,
                        dns_servers: dns,
                        is_system_default: false,
                        is_available: false,
                    };
                    let to_send  = egress.clone();
                    let sock_c   = sock.clone();
                    let state_wc = state_w.clone();
                    let editing  = eid.is_some();
                    cx.spawn(async move |cx| {
                        let res = cx
                            .background_executor()
                            .spawn(async move {
                                crate::daemon::send_request(
                                    &sock_c,
                                    &ControlRequest::UpsertEgress(to_send),
                                )
                            })
                            .await;
                        if let Some(st) = state_wc.upgrade() {
                            let _ = cx.update_entity(&st, |s: &mut SettingsState, cx| {
                                match res {
                                    Ok(ControlResponse::Ok) => {
                                        if editing {
                                            if let Some(e) = s.egresses.iter_mut().find(|e| e.id == egress.id) {
                                                *e = egress;
                                            }
                                            s.status = Some("Egress updated.".into());
                                        } else {
                                            s.egresses.push(egress);
                                            s.status = Some("Egress added.".into());
                                        }
                                        s.load_generation = s.load_generation.saturating_add(1);
                                    }
                                    Ok(ControlResponse::Error(msg)) => {
                                        s.status = Some(format!("save failed: {msg}"));
                                    }
                                    Err(e) => {
                                        s.status = Some(format!("save failed: {e}"));
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
                    true
                })
        });
    }

    /// Open the proxy form dialog for adding (existing = None) or editing (existing = Some).
    fn open_proxy_form_dialog(
        &mut self,
        existing: Option<ProxyConfig>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let state_weak = self.state.downgrade();
        let socket_path = self.state.read(cx).socket_path.clone();

        let is_edit = existing.is_some();
        let existing_id = existing.as_ref().map(|p| p.id.clone());
        let init_name = existing.as_ref().map(|p| p.name.as_str()).unwrap_or("New Proxy").to_string();
        let init_host = existing.as_ref().map(|p| p.host.as_str()).unwrap_or("127.0.0.1").to_string();
        let init_port = existing.as_ref().map(|p| p.port).unwrap_or(1080).to_string();
        let init_proto = existing.as_ref().map(|p| p.protocol.clone()).unwrap_or(ProxyProtocol::Socks5);
        let init_auth = existing.map(|p| p.auth.clone()).unwrap_or(ProxyAuth::None);

        // Create input entities before the Fn dialog closure.
        let name_input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s.set_value(init_name.clone(), window, cx);
            s
        });
        let host_input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s.set_value(init_host.clone(), window, cx);
            s
        });
        let port_input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s.set_value(init_port.clone(), window, cx);
            s
        });

        // Shared protocol — interior mutability because dialog closure is Fn.
        let selected_proto: Arc<Mutex<ProxyProtocol>> = Arc::new(Mutex::new(init_proto));

        let name_input_c = name_input.clone();
        let host_input_c = host_input.clone();
        let port_input_c = port_input.clone();
        let proto_c = selected_proto.clone();

        let hdr_icon  = if is_edit { "✏" } else { "⊕" };
        let hdr_title = if is_edit { "EDIT PROXY" } else { "ADD PROXY" };
        let ok_label  = if is_edit { "Save" } else { "Add Proxy" };

        window.open_dialog(cx, move |dialog, _, _cx| {
            let cur_proto = proto_c.lock().unwrap().clone();

            let proto_socks5 = selected_proto.clone();
            let proto_http   = selected_proto.clone();
            let proto_ss     = selected_proto.clone();
            let proto_for_ok = proto_c.clone();

            let (sc, hc, sc2) = match cur_proto {
                ProxyProtocol::Socks5      => (colors::green(),   colors::muted(),   colors::muted()),
                ProxyProtocol::Http        => (colors::muted(),   colors::primary(), colors::muted()),
                ProxyProtocol::Shadowsocks => (colors::muted(),   colors::muted(),   colors::teal()),
            };

            let name_i   = name_input_c.clone();
            let host_i   = host_input_c.clone();
            let port_i   = port_input_c.clone();
            let state_w  = state_weak.clone();
            let sock     = socket_path.clone();
            let eid      = existing_id.clone();
            let auth_val = init_auth.clone();

            dialog
                .p(px(0.))
                .close_button(false)
                .title(modal_header(hdr_icon, hdr_title))
                .w(px(480.))
                .button_props(
                    gpui_component::dialog::DialogButtonProps::default()
                        .ok_text(ok_label)
                        .cancel_text("Cancel"),
                )
                .footer(|ok, cancel, w, cx| {
                    vec![modal_footer(cancel(w, cx), ok(w, cx))]
                })
                .child(
                    v_flex()
                        .px(px(16.))
                        .py(px(16.))
                        .gap(px(16.))
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(field_label("NAME"))
                                .child(Input::new(&name_input_c)),
                        )
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(field_label("PROTOCOL"))
                                .child(
                                    h_flex()
                                        .gap(px(8.))
                                        .child(proto_btn("SOCKS5", sc, sc, move |_, _, _| {
                                            *proto_socks5.lock().unwrap() = ProxyProtocol::Socks5;
                                        }))
                                        .child(proto_btn("HTTP", hc, hc, move |_, _, _| {
                                            *proto_http.lock().unwrap() = ProxyProtocol::Http;
                                        }))
                                        .child(proto_btn("SS", sc2, sc2, move |_, _, _| {
                                            *proto_ss.lock().unwrap() = ProxyProtocol::Shadowsocks;
                                        })),
                                ),
                        )
                        .child(
                            h_flex()
                                .gap(px(12.))
                                .child(
                                    v_flex()
                                        .flex_1()
                                        .gap(px(4.))
                                        .child(field_label("HOST"))
                                        .child(Input::new(&host_input_c)),
                                )
                                .child(
                                    v_flex()
                                        .w(px(96.))
                                        .gap(px(4.))
                                        .child(field_label("PORT"))
                                        .child(Input::new(&port_input_c)),
                                ),
                        ),
                )
                .on_ok(move |_, _, cx| {
                    let name     = name_i.read(cx).value().to_string();
                    let host     = host_i.read(cx).value().to_string();
                    let port_str = port_i.read(cx).value().to_string();
                    let port: u16 = port_str.trim().parse().unwrap_or(1080);
                    let proto    = proto_for_ok.lock().unwrap().clone();
                    let id       = eid.clone().unwrap_or_else(|| format!("px-{}", crate::daemon::unix_now()));
                    let proxy = ProxyConfig {
                        id,
                        name: if name.trim().is_empty() { "New Proxy".into() } else { name },
                        protocol: proto,
                        host: if host.trim().is_empty() { "127.0.0.1".into() } else { host },
                        port,
                        auth: auth_val.clone(),
                        enabled: true,
                    };
                    let to_send  = proxy.clone();
                    let sock_c   = sock.clone();
                    let state_wc = state_w.clone();
                    let editing  = eid.is_some();
                    cx.spawn(async move |cx| {
                        let res = cx
                            .background_executor()
                            .spawn(async move {
                                crate::daemon::send_request(
                                    &sock_c,
                                    &ControlRequest::UpsertProxy(to_send),
                                )
                            })
                            .await;
                        if let Some(st) = state_wc.upgrade() {
                            let _ = cx.update_entity(&st, |s: &mut SettingsState, cx| {
                                match res {
                                    Ok(ControlResponse::Ok) => {
                                        if editing {
                                            if let Some(p) = s.proxies.iter_mut().find(|p| p.id == proxy.id) {
                                                *p = proxy;
                                            }
                                            s.status = Some("Proxy updated.".into());
                                        } else {
                                            s.proxies.push(proxy);
                                            s.status = Some("Proxy added.".into());
                                        }
                                        s.load_generation = s.load_generation.saturating_add(1);
                                    }
                                    Ok(ControlResponse::Error(msg)) => {
                                        s.status = Some(format!("save failed: {msg}"));
                                    }
                                    Err(e) => {
                                        s.status = Some(format!("save failed: {e}"));
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
                    true
                })
        });
    }
}

// ── Render ─────────────────────────────────────────────────────────────

impl Render for SettingsApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.sync_tables(cx);

        let state = self.state.read(cx);
        let status = state.status.clone();
        let socket_path = state.socket_path.clone();
        let active_tab = state.active_tab;

        let weak = self.state.downgrade();
        let weak_refresh = weak.clone();
        let socket_for_refresh = socket_path.clone();

        let selected_index = match active_tab {
            SettingsTab::Rules => 0,
            SettingsTab::Egress => 1,
            SettingsTab::Proxies => 2,
        };

        let tab_bar = TabBar::new("settings-tabs")
            .selected_index(selected_index)
            .on_click(cx.listener(|this, index: &usize, _, cx| {
                let tab = match index {
                    0 => SettingsTab::Rules,
                    1 => SettingsTab::Egress,
                    _ => SettingsTab::Proxies,
                };
                let _ = cx.update_entity(&this.state, |s, cx| {
                    s.active_tab = tab;
                    cx.notify();
                });
            }))
            .child(Tab::new().label("Rules"))
            .child(Tab::new().label("Egress"))
            .child(Tab::new().label("Proxies"));

        // Table content for the active tab
        let table_content = match active_tab {
            SettingsTab::Rules => gpui_component::table::Table::new(&self.rules_table)
                .stripe(true)
                .bordered(true)
                .into_any_element(),
            SettingsTab::Egress => gpui_component::table::Table::new(&self.egress_table)
                .stripe(true)
                .bordered(true)
                .into_any_element(),
            SettingsTab::Proxies => gpui_component::table::Table::new(&self.proxy_table)
                .stripe(true)
                .bordered(true)
                .into_any_element(),
        };

        // Add button for egress/proxies tabs
        let add_button: Option<gpui::AnyElement> = match active_tab {
            SettingsTab::Egress => Some(
                div()
                    .id(gpui::ElementId::Name("add-egress-btn".into()))
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .bg(colors::primary())
                    .text_color(colors::bg())
                    .px(px(12.))
                    .py(px(6.))
                    .rounded(px(4.))
                    .cursor_pointer()
                    .text_size(px(10.))
                    .font_weight(gpui::FontWeight::BOLD)
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.open_egress_form_dialog(None, window, cx);
                    }))
                    .child("+ ADD EGRESS")
                    .into_any_element(),
            ),
            SettingsTab::Proxies => Some(
                div()
                    .id(gpui::ElementId::Name("add-proxy-btn".into()))
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .bg(colors::primary())
                    .text_color(colors::bg())
                    .px(px(12.))
                    .py(px(6.))
                    .rounded(px(4.))
                    .cursor_pointer()
                    .text_size(px(10.))
                    .font_weight(gpui::FontWeight::BOLD)
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.open_proxy_form_dialog(None, window, cx);
                    }))
                    .child("+ ADD PROXY")
                    .into_any_element(),
            ),
            SettingsTab::Rules => None,
        };

        let status_el: Option<gpui::AnyElement> = status.map(|msg| {
            div()
                .w_full()
                .px(px(16.))
                .py(px(8.))
                .bg(colors::surface_container())
                .text_color(colors::error())
                .text_size(px(12.))
                .child(msg)
                .into_any_element()
        });

        let footer_el: Option<gpui::AnyElement> = add_button.map(|btn| {
            div()
                .px(px(12.))
                .py(px(8.))
                .border_t_1()
                .border_color(colors::border())
                .bg(colors::surface_container_high())
                .child(btn)
                .into_any_element()
        });

        v_flex()
            .size_full()
            .bg(colors::bg())
            .text_color(colors::text())
            // Title bar with drag, close button, icon, title, and refresh
            .child(
                TitleBar::new()
                    .on_close_window(|_, window, _| {
                        window.remove_window();
                    })
                    .child(
                        h_flex()
                            .items_center()
                            .gap(px(8.))
                            .child(
                                div()
                                    .text_size(px(14.))
                                    .text_color(colors::primary())
                                    .child("⚙"),
                            )
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_size(px(13.))
                                    .child("Settings"),
                            )
                            .child(
                                div()
                                    .id(gpui::ElementId::Name("settings-refresh".into()))
                                    .text_size(px(11.))
                                    .text_color(colors::primary())
                                    .cursor_pointer()
                                    .px(px(6.))
                                    .py(px(2.))
                                    .rounded(px(3.))
                                    .border_1()
                                    .border_color(colors::border())
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
                    ),
            )
            // Tab bar
            .child(tab_bar)
            // Status message
            .children(status_el)
            // Table content (flex-1 to fill remaining space)
            .child(
                v_flex()
                    .flex_1()
                    .px(px(12.))
                    .py(px(8.))
                    .child(table_content),
            )
            // Footer with add button
            .children(footer_el)
            // Dialog layer — must be rendered here or dialogs never appear
            .children(gpui_component::Root::render_dialog_layer(window, &mut **cx))
            .into_any_element()
    }
}


