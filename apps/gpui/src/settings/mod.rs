//! Settings window (opened from the tray menu).
//!
//! Uses gpui-component `Table` (DataTable) for each tab and `Dialog` for
//! editing/viewing details of egress and proxy items.

mod egress_tab;
mod helpers;
mod proxies_tab;
mod rules_tab;

use control_api::{ControlRequest, ControlResponse};
use core_types::{Egress, ProxyAuth, ProxyConfig, ProxyProtocol, RouteTarget};
use gpui::{
    div, px, AppContext as _, Context, Entity, InteractiveElement, IntoElement, ParentElement,
    Render, StatefulInteractiveElement, Styled, Subscription, WeakEntity, Window,
};
use gpui_component::tab::{Tab, TabBar};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::TitleBar;
use gpui_component::WindowExt as _;
use gpui_component::{h_flex, v_flex};

use crate::colors;
use crate::daemon;

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

        // Observe state changes to refresh tables
        cx.observe(&state, |this, _, cx| {
            this.sync_tables(cx);
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

    /// Handle egress table events — double-click opens detail dialog.
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
                let egress = egress.clone();
                self.open_egress_detail_dialog(egress, window, cx);
            }
        }
    }

    /// Handle proxy table events — double-click opens edit dialog.
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
                self.open_proxy_edit_dialog(proxy, window, cx);
            }
        }
    }

    /// Open a dialog showing egress details.
    fn open_egress_detail_dialog(
        &mut self,
        egress: Egress,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let name = egress.name.clone();
        let id = egress.id.clone();
        let is_system = egress.is_system_default;
        let is_available = egress.is_available;
        let targets: Vec<String> = egress
            .targets
            .iter()
            .map(|t| helpers::route_summary(t))
            .collect();
        let dns = egress.dns_servers.join(", ");
        let color = egress.color.clone();

        window.open_dialog(cx, move |dialog, _, _| {
            let mut d = dialog
                .title(format!("Egress: {name}"))
                .w(px(500.))
                .close_button(true)
                .child(
                    v_flex()
                        .gap(px(12.))
                        .child(
                            h_flex()
                                .gap(px(12.))
                                .items_center()
                                .child(info_field("ID", &id))
                                .child(info_field("Color", &color))
                                .child(if is_system {
                                    badge_el("SYSTEM", colors::muted())
                                } else {
                                    badge_el("CUSTOM", colors::primary())
                                })
                                .child(if is_available || is_system {
                                    badge_el("ACTIVE", colors::green())
                                } else {
                                    badge_el("INACTIVE", colors::muted())
                                }),
                        )
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(colors::muted())
                                        .font_weight(gpui::FontWeight::BOLD)
                                        .child("TARGETS"),
                                )
                                .child(div().text_color(colors::text()).child(
                                    if targets.is_empty() {
                                        "default routing".to_string()
                                    } else {
                                        targets.join(", ")
                                    },
                                )),
                        )
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(colors::muted())
                                        .font_weight(gpui::FontWeight::BOLD)
                                        .child("DNS SERVERS"),
                                )
                                .child(div().text_color(colors::text()).child(if dns.is_empty() {
                                    "—".to_string()
                                } else {
                                    dns.clone()
                                })),
                        ),
                );

            if !is_system {
                d = d.on_ok(|_, _, _| true);
            }
            d
        });
    }

    /// Open a dialog for editing proxy details.
    fn open_proxy_edit_dialog(
        &mut self,
        proxy: ProxyConfig,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let name = proxy.name.clone();
        let id = proxy.id.clone();
        let protocol = match proxy.protocol {
            ProxyProtocol::Socks5 => "SOCKS5",
            ProxyProtocol::Http => "HTTP",
            ProxyProtocol::Shadowsocks => "Shadowsocks",
        };
        let address = format!("{}:{}", proxy.host, proxy.port);
        let auth_summary = match &proxy.auth {
            ProxyAuth::None => "None".to_string(),
            ProxyAuth::Basic { username, .. } => format!("{username}:***"),
            ProxyAuth::Shadowsocks { method, .. } => method.clone(),
        };
        let enabled = proxy.enabled;
        let proto_color = match proxy.protocol {
            ProxyProtocol::Socks5 => colors::green(),
            ProxyProtocol::Http => colors::primary(),
            ProxyProtocol::Shadowsocks => colors::teal(),
        };

        window.open_dialog(cx, move |dialog, _, _| {
            dialog
                .title(format!("Proxy: {name}"))
                .w(px(480.))
                .close_button(true)
                .child(
                    v_flex()
                        .gap(px(12.))
                        .child(
                            h_flex()
                                .gap(px(12.))
                                .items_center()
                                .child(info_field("ID", &id))
                                .child(badge_el(protocol, proto_color))
                                .child(if enabled {
                                    badge_el("ACTIVE", colors::green())
                                } else {
                                    badge_el("INACTIVE", colors::muted())
                                }),
                        )
                        .child(
                            h_flex()
                                .gap(px(16.))
                                .child(info_field("Address", &address))
                                .child(info_field("Auth", &auth_summary)),
                        ),
                )
                .on_ok(|_, _, _| true)
        });
    }
}

// ── Helper elements ────────────────────────────────────────────────────

fn info_field(label: &str, value: &str) -> gpui::AnyElement {
    v_flex()
        .gap(px(2.))
        .child(
            div()
                .text_size(px(10.))
                .text_color(colors::muted())
                .child(label.to_string()),
        )
        .child(div().text_color(colors::text()).child(value.to_string()))
        .into_any_element()
}

fn badge_el(label: &str, color: gpui::Hsla) -> gpui::AnyElement {
    div()
        .text_size(px(10.))
        .text_color(color)
        .px(px(6.))
        .py(px(2.))
        .rounded(px(3.))
        .border_1()
        .border_color(color)
        .bg(colors::bg())
        .child(label.to_string())
        .into_any_element()
}

// ── Render ─────────────────────────────────────────────────────────────

impl Render for SettingsApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
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
            SettingsTab::Egress => {
                Some(render_add_egress_button(weak.clone(), socket_path.clone()))
            }
            SettingsTab::Proxies => {
                Some(render_add_proxy_button(weak.clone(), socket_path.clone()))
            }
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
            .into_any_element()
    }
}

// ── Add Egress button ──────────────────────────────────────────────────

fn render_add_egress_button(
    state_weak: WeakEntity<SettingsState>,
    socket_path: String,
) -> gpui::AnyElement {
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
        .on_click({
            let weak = state_weak.clone();
            let sock = socket_path.clone();
            move |_, _, cx| {
                let weak_c = weak.clone();
                let sock_c = sock.clone();
                cx.spawn(async move |cx| {
                    let new_eg = Egress {
                        id: format!("eg-{}", daemon::unix_now()),
                        name: "New Egress".into(),
                        color: "#3b82f6".into(),
                        targets: vec![RouteTarget::Device("eth0".into())],
                        dns_servers: vec![],
                        is_system_default: false,
                        is_available: false,
                    };
                    let to_send = new_eg.clone();
                    let res = cx
                        .background_executor()
                        .spawn(async move {
                            daemon::send_request(&sock_c, &ControlRequest::UpsertEgress(to_send))
                        })
                        .await;
                    if let Some(st) = weak_c.upgrade() {
                        let _ = cx.update_entity(&st, |s: &mut SettingsState, cx| {
                            match res {
                                Ok(ControlResponse::Ok) => {
                                    s.egresses.push(new_eg);
                                    s.load_generation = s.load_generation.saturating_add(1);
                                    s.status = Some("Egress added.".into());
                                }
                                Ok(ControlResponse::Error(msg)) => {
                                    s.status = Some(format!("add failed: {msg}"));
                                }
                                Err(e) => {
                                    s.status = Some(format!("add failed: {e}"));
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
            }
        })
        .child("+ ADD EGRESS")
        .into_any_element()
}

// ── Add Proxy button ───────────────────────────────────────────────────

fn render_add_proxy_button(
    state_weak: WeakEntity<SettingsState>,
    socket_path: String,
) -> gpui::AnyElement {
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
        .on_click({
            let weak = state_weak.clone();
            let sock = socket_path.clone();
            move |_, _, cx| {
                let weak_c = weak.clone();
                let sock_c = sock.clone();
                cx.spawn(async move |cx| {
                    let new_proxy = ProxyConfig {
                        id: format!("px-{}", daemon::unix_now()),
                        name: "New Proxy".into(),
                        protocol: ProxyProtocol::Socks5,
                        host: "127.0.0.1".into(),
                        port: 1080,
                        auth: ProxyAuth::None,
                        enabled: true,
                    };
                    let to_send = new_proxy.clone();
                    let res = cx
                        .background_executor()
                        .spawn(async move {
                            daemon::send_request(&sock_c, &ControlRequest::UpsertProxy(to_send))
                        })
                        .await;
                    if let Some(st) = weak_c.upgrade() {
                        let _ = cx.update_entity(&st, |s: &mut SettingsState, cx| {
                            match res {
                                Ok(ControlResponse::Ok) => {
                                    s.proxies.push(new_proxy);
                                    s.status = Some("Proxy added.".into());
                                }
                                Ok(ControlResponse::Error(msg)) => {
                                    s.status = Some(format!("add failed: {msg}"));
                                }
                                Err(e) => {
                                    s.status = Some(format!("add failed: {e}"));
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
            }
        })
        .child("+ ADD PROXY")
        .into_any_element()
}
