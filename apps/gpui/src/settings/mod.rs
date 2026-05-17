//! Settings window (opened from the tray menu).
//!
//! Uses gpui-component `Table` (DataTable) for each tab and `Dialog` for
//! editing/viewing details of egress and proxy items.

mod egress_tab;
mod helpers;
mod proxies_tab;
mod rules_tab;

use std::rc::Rc;
use std::sync::{Arc, Mutex};

use control_api::{ControlRequest, ControlResponse};
use core_types::{
    DestinationMatcher, Egress, ProxyAuth, ProxyConfig, ProxyProtocol, Rule, RuleAction,
    RuleDuration,
};
use gpui::{
    div, prelude::FluentBuilder as _, px, AppContext as _, Context, Entity, InteractiveElement,
    IntoElement, ParentElement, Render, StatefulInteractiveElement, Styled, Subscription, Window,
};
use gpui_component::input::{Input, InputState};
use gpui_component::tab::{Tab, TabBar};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::TitleBar;
use gpui_component::WindowExt as _;
use gpui_component::{h_flex, v_flex};

use crate::colors;
use crate::components::{action_btn, field_label, modal_header, proto_btn};

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
    /// Set by double-clicking a rule row; drained by SettingsApp observer.
    pub rule_edit_request: Option<Rule>,
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
            rule_edit_request: None,
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
                RulesDelegate::new(vec![], vec![], weak.clone(), socket_path.clone()),
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
        subscriptions.push(cx.subscribe_in(&rules_table, window, Self::on_rules_table_event));
        subscriptions.push(cx.subscribe_in(&egress_table, window, Self::on_egress_table_event));
        subscriptions.push(cx.subscribe_in(&proxy_table, window, Self::on_proxy_table_event));

        // Observe state changes: refresh tables, handle edit requests, re-render.
        // Note: do NOT call cx.notify() when clearing request fields — that would re-trigger this observer.
        cx.observe_in(&state, window, |this, _, window, cx| {
            this.sync_tables(cx);

            // Drain rule edit request → open pre-filled rule form.
            let rule_edit = this.state.read(cx).rule_edit_request.clone();
            if let Some(rule) = rule_edit {
                let _ = cx.update_entity(&this.state, |s, _cx| {
                    s.rule_edit_request = None;
                });
                this.open_rule_form_dialog(Some(rule), window, cx);
                return;
            }

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
            table.delegate_mut().egresses = egresses.clone();
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

    /// Handle rules table events — double-click opens edit form.
    fn on_rules_table_event(
        &mut self,
        _table: &Entity<TableState<RulesDelegate>>,
        event: &TableEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let TableEvent::DoubleClickedRow(row_ix) = event {
            let rules = &self.state.read(cx).rules;
            if let Some(rule) = rules.get(*row_ix) {
                let rule = rule.clone();
                self.open_rule_form_dialog(Some(rule), window, cx);
            }
        }
    }

    /// Open the rule form dialog for adding (existing = None) or editing (existing = Some).
    fn open_rule_form_dialog(
        &mut self,
        existing: Option<Rule>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let state_weak = self.state.downgrade();
        let socket_path = self.state.read(cx).socket_path.clone();

        let is_edit = existing.is_some();
        let existing_id = existing.as_ref().map(|r| r.id.clone());

        let init_process = existing
            .as_ref()
            .and_then(|r| r.process_name.clone())
            .unwrap_or_default();
        let init_action = existing
            .as_ref()
            .map(|r| r.action.clone())
            .unwrap_or(RuleAction::Allow);
        let init_duration = existing
            .as_ref()
            .map(|r| r.duration)
            .unwrap_or(RuleDuration::Permanent);
        let (init_dest_type, init_dest_value) = match existing.as_ref().map(|r| &r.destination) {
            Some(DestinationMatcher::IpExact(v)) => ("ip", v.clone()),
            Some(DestinationMatcher::Cidr(v)) => ("cidr", v.clone()),
            Some(DestinationMatcher::DomainExact(v)) => ("domain", v.clone()),
            Some(DestinationMatcher::DomainWildcard(v)) => ("wildcard", v.clone()),
            Some(DestinationMatcher::Any) | None => ("any", String::new()),
        };
        let init_route = existing
            .as_ref()
            .and_then(|r| r.egress_id.clone())
            .unwrap_or_default();

        let process_input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s.set_value(init_process.clone(), window, cx);
            s
        });
        let dest_input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s.set_value(init_dest_value.clone(), window, cx);
            s
        });
        // Available egresses for the route-target selector (id, display name).
        let available_egresses: Vec<(String, String)> = self
            .state
            .read(cx)
            .egresses
            .iter()
            .map(|e| (e.id.clone(), e.name.clone()))
            .collect();

        // Interior-mutable route selection — replaces the old free-text InputState.
        let selected_route: Arc<Mutex<String>> = Arc::new(Mutex::new(init_route.clone()));

        // Interior-mutable shared state for radio-group selections inside Fn closure.
        let selected_action: Arc<Mutex<RuleAction>> = Arc::new(Mutex::new(init_action));
        let selected_duration: Arc<Mutex<RuleDuration>> = Arc::new(Mutex::new(init_duration));
        let selected_dest_type: Arc<Mutex<String>> =
            Arc::new(Mutex::new(init_dest_type.to_string()));

        let proc_c = process_input.clone();
        let dest_c = dest_input.clone();
        let action_c = selected_action.clone();
        let dur_c = selected_duration.clone();
        let dtype_c = selected_dest_type.clone();

        let hdr_icon = if is_edit { "✏" } else { "⊕" };
        let hdr_title = if is_edit { "EDIT RULE" } else { "ADD RULE" };
        let ok_label = if is_edit { "Save" } else { "Add Rule" };

        window.open_dialog(cx, move |dialog, _, _cx| {
            let cur_action = action_c.lock().unwrap().clone();
            let cur_duration = dur_c.lock().unwrap().clone();
            let cur_dtype = dtype_c.lock().unwrap().clone();

            // Action button colors
            let (ac_allow, ac_deny, ac_ask, ac_route) = match cur_action {
                RuleAction::Allow => (
                    colors::green(),
                    colors::muted(),
                    colors::muted(),
                    colors::muted(),
                ),
                RuleAction::Deny => (
                    colors::muted(),
                    colors::error(),
                    colors::muted(),
                    colors::muted(),
                ),
                RuleAction::Ask => (
                    colors::muted(),
                    colors::muted(),
                    colors::orange(),
                    colors::muted(),
                ),
                RuleAction::Route { .. } => (
                    colors::muted(),
                    colors::muted(),
                    colors::muted(),
                    colors::primary(),
                ),
            };
            let is_route_action = matches!(cur_action, RuleAction::Route { .. });
            // Duration button colors
            let (dc_perm, dc_sess) = match cur_duration {
                RuleDuration::Permanent => (colors::primary(), colors::muted()),
                RuleDuration::UntilRestart => (colors::muted(), colors::orange()),
            };
            // Dest type button colors
            let dtype_color = |t: &str| {
                if cur_dtype == t {
                    colors::primary()
                } else {
                    colors::muted()
                }
            };
            let (dtc_ip, dtc_cidr, dtc_dom, dtc_wild, dtc_any) = (
                dtype_color("ip"),
                dtype_color("cidr"),
                dtype_color("domain"),
                dtype_color("wildcard"),
                dtype_color("any"),
            );

            let show_dest_input = cur_dtype != "any";

            // Clones for on_ok
            let proc_i = proc_c.clone();
            let dest_i = dest_c.clone();
            let route_ok = selected_route.clone();
            let action_ok = action_c.clone();
            let dur_ok = dur_c.clone();
            let dtype_ok = dtype_c.clone();
            let state_w = state_weak.clone();
            let sock = socket_path.clone();
            let eid = existing_id.clone();

            let do_save: Rc<dyn Fn(&mut gpui::App) -> bool> = {
                let proc_i = proc_i;
                let dest_i = dest_i;
                let route_ok = route_ok;
                let action_ok = action_ok;
                let dur_ok = dur_ok;
                let dtype_ok = dtype_ok;
                let state_w = state_w;
                let sock = sock;
                let eid = eid;
                Rc::new(move |cx: &mut gpui::App| -> bool {
                    let process_raw = proc_i.read(cx).value().to_string();
                    let process_name = if process_raw.trim().is_empty() {
                        None
                    } else {
                        Some(process_raw.trim().to_string())
                    };
                    let dest_val = dest_i.read(cx).value().trim().to_string();
                    let action = action_ok.lock().unwrap().clone();
                    let duration = dur_ok.lock().unwrap().clone();
                    let dest_type = dtype_ok.lock().unwrap().clone();
                    let destination = match dest_type.as_str() {
                        "cidr" => DestinationMatcher::Cidr(dest_val),
                        "domain" => DestinationMatcher::DomainExact(dest_val),
                        "wildcard" => DestinationMatcher::DomainWildcard(
                            dest_val.strip_prefix("*.").unwrap_or(&dest_val).to_string(),
                        ),
                        "any" => DestinationMatcher::Any,
                        _ => DestinationMatcher::IpExact(dest_val),
                    };
                    let route_raw = route_ok.lock().unwrap().clone();
                    let (action, egress_id) = if action == RuleAction::Route {
                        if route_raw.is_empty() {
                            (RuleAction::Allow, None)
                        } else {
                            (RuleAction::Route, Some(route_raw))
                        }
                    } else {
                        (action, None)
                    };
                    let id = eid
                        .clone()
                        .unwrap_or_else(|| format!("ui-{}", crate::daemon::unix_now()));
                    let rule = Rule {
                        id,
                        enabled: true,
                        action,
                        duration,
                        process_name,
                        process_exe: None,
                        destination,
                        egress_id,
                    };
                    let to_send = rule.clone();
                    let sock_c = sock.clone();
                    let state_wc = state_w.clone();
                    let editing = eid.is_some();
                    cx.spawn(async move |cx| {
                        let res = cx
                            .background_executor()
                            .spawn(async move {
                                crate::daemon::send_request(
                                    &sock_c,
                                    &ControlRequest::AddRule(to_send),
                                )
                            })
                            .await;
                        if let Some(st) = state_wc.upgrade() {
                            let _ = cx.update_entity(&st, |s: &mut SettingsState, cx| {
                                match res {
                                    Ok(ControlResponse::Ok) => {
                                        if editing {
                                            if let Some(r) =
                                                s.rules.iter_mut().find(|r| r.id == rule.id)
                                            {
                                                *r = rule;
                                            }
                                            s.status = Some("Rule updated.".into());
                                        } else {
                                            s.rules.push(rule);
                                            s.status = Some("Rule added.".into());
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
            };
            let do_save_btn = do_save.clone();

            // Clones for buttons
            let act_allow = selected_action.clone();
            let act_deny = selected_action.clone();
            let act_ask = selected_action.clone();
            let act_route = selected_action.clone();
            let dur_perm = selected_duration.clone();
            let dur_sess = selected_duration.clone();
            let dt_ip = selected_dest_type.clone();
            let dt_cidr = selected_dest_type.clone();
            let dt_dom = selected_dest_type.clone();
            let dt_wild = selected_dest_type.clone();
            let dt_any = selected_dest_type.clone();

            dialog
                .p(px(0.))
                .title(modal_header(hdr_icon, hdr_title))
                .w(px(480.))
                .button_props(
                    gpui_component::dialog::DialogButtonProps::default()
                        .ok_text(ok_label)
                        .cancel_text("Cancel"),
                )
                .footer(
                    h_flex()
                        .px(px(16.))
                        .py(px(8.))
                        .gap(px(8.))
                        .justify_end()
                        .child(
                            action_btn("dialog-cancel", "Cancel", crate::colors::muted()).on_click(
                                |_, win, cx| {
                                    win.close_dialog(cx);
                                },
                            ),
                        )
                        .child(
                            action_btn("dialog-ok", ok_label, crate::colors::primary()).on_click(
                                move |_, win, cx| {
                                    do_save_btn(cx);
                                    win.close_dialog(cx);
                                },
                            ),
                        ),
                )
                .child(
                    v_flex()
                        .px(px(16.))
                        .py(px(16.))
                        .gap(px(16.))
                        // Process
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(field_label("PROCESS  (leave empty to match all)"))
                                .child(Input::new(&proc_c)),
                        )
                        // Action
                        .child(
                            v_flex().gap(px(4.)).child(field_label("ACTION")).child(
                                h_flex()
                                    .gap(px(8.))
                                    .child(proto_btn(
                                        "ALLOW",
                                        ac_allow,
                                        ac_allow,
                                        move |_, _, _| {
                                            *act_allow.lock().unwrap() = RuleAction::Allow;
                                        },
                                    ))
                                    .child(proto_btn("DENY", ac_deny, ac_deny, move |_, _, _| {
                                        *act_deny.lock().unwrap() = RuleAction::Deny;
                                    }))
                                    .child(proto_btn("ASK", ac_ask, ac_ask, move |_, _, _| {
                                        *act_ask.lock().unwrap() = RuleAction::Ask;
                                    }))
                                    .child(proto_btn(
                                        "ROUTE",
                                        ac_route,
                                        ac_route,
                                        move |_, _, _| {
                                            *act_route.lock().unwrap() = RuleAction::Route;
                                        },
                                    )),
                            ),
                        )
                        // Route target egress selector — shown only when action is ROUTE
                        .when(is_route_action, |el| {
                            let cur_route = selected_route.lock().unwrap().clone();
                            let route_arc = selected_route.clone();
                            let egress_btns: Vec<gpui::AnyElement> = available_egresses
                                .iter()
                                .map(|(eid, ename)| {
                                    let is_sel = cur_route == *eid;
                                    let color = if is_sel {
                                        colors::primary()
                                    } else {
                                        colors::muted()
                                    };
                                    let eid_c = eid.clone();
                                    let rt = route_arc.clone();
                                    div()
                                        .id(gpui::ElementId::Name(format!("eg-sel-{eid_c}").into()))
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .px(px(10.))
                                        .py(px(5.))
                                        .rounded(px(4.))
                                        .border_1()
                                        .border_color(color)
                                        .text_color(color)
                                        .text_size(px(10.))
                                        .font_weight(gpui::FontWeight::BOLD)
                                        .cursor_pointer()
                                        .on_click(move |_, _, _| {
                                            *rt.lock().unwrap() = eid_c.clone();
                                        })
                                        .child(ename.clone())
                                        .into_any_element()
                                })
                                .collect();
                            if egress_btns.is_empty() {
                                el.child(
                                    div().text_color(colors::muted()).text_size(px(11.)).child(
                                        "No egresses configured — add one in the Egress tab.",
                                    ),
                                )
                            } else {
                                el.child(
                                    v_flex().gap(px(4.)).child(field_label("ROUTE VIA")).child(
                                        div().flex().flex_wrap().gap(px(6.)).children(egress_btns),
                                    ),
                                )
                            }
                        })
                        // Destination type
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(field_label("DESTINATION TYPE"))
                                .child(
                                    h_flex()
                                        .gap(px(6.))
                                        .child(proto_btn("IP", dtc_ip, dtc_ip, move |_, _, _| {
                                            *dt_ip.lock().unwrap() = "ip".into();
                                        }))
                                        .child(proto_btn(
                                            "CIDR",
                                            dtc_cidr,
                                            dtc_cidr,
                                            move |_, _, _| {
                                                *dt_cidr.lock().unwrap() = "cidr".into();
                                            },
                                        ))
                                        .child(proto_btn(
                                            "DOMAIN",
                                            dtc_dom,
                                            dtc_dom,
                                            move |_, _, _| {
                                                *dt_dom.lock().unwrap() = "domain".into();
                                            },
                                        ))
                                        .child(proto_btn(
                                            "WILDCARD",
                                            dtc_wild,
                                            dtc_wild,
                                            move |_, _, _| {
                                                *dt_wild.lock().unwrap() = "wildcard".into();
                                            },
                                        ))
                                        .child(proto_btn(
                                            "ANY",
                                            dtc_any,
                                            dtc_any,
                                            move |_, _, _| {
                                                *dt_any.lock().unwrap() = "any".into();
                                            },
                                        )),
                                ),
                        )
                        // Destination value (hidden for Any)
                        .when(show_dest_input, |el| {
                            el.child(
                                v_flex()
                                    .gap(px(4.))
                                    .child(field_label("DESTINATION VALUE"))
                                    .child(Input::new(&dest_c)),
                            )
                        })
                        // Duration
                        .child(
                            v_flex().gap(px(4.)).child(field_label("DURATION")).child(
                                h_flex()
                                    .gap(px(8.))
                                    .child(proto_btn(
                                        "PERMANENT",
                                        dc_perm,
                                        dc_perm,
                                        move |_, _, _| {
                                            *dur_perm.lock().unwrap() = RuleDuration::Permanent;
                                        },
                                    ))
                                    .child(proto_btn(
                                        "SESSION",
                                        dc_sess,
                                        dc_sess,
                                        move |_, _, _| {
                                            *dur_sess.lock().unwrap() = RuleDuration::UntilRestart;
                                        },
                                    )),
                            ),
                        ),
                )
                .on_ok(move |_, _, cx| do_save(cx))
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
        let init_name = existing
            .as_ref()
            .map(|e| e.name.as_str())
            .unwrap_or("New Egress")
            .to_string();
        let init_color = existing
            .as_ref()
            .map(|e| e.color.as_str())
            .unwrap_or("#3b82f6")
            .to_string();
        let init_targets_vec: Vec<String> = existing
            .as_ref()
            .map(|e| {
                e.targets
                    .iter()
                    .map(|t| helpers::route_summary(t))
                    .collect()
            })
            .unwrap_or_default();
        let init_dns = existing
            .as_ref()
            .map(|e| e.dns_servers.join(", "))
            .unwrap_or_default();

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
        let dns_input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s.set_value(init_dns.clone(), window, cx);
            s
        });
        // Collect available interfaces and proxy options for the add-target selector.
        let (tun_ifaces, dev_ifaces) = crate::daemon::list_net_interfaces();
        let proxy_options: Vec<(String, String)> = self
            .state
            .read(cx)
            .proxies
            .iter()
            .map(|p| (p.id.clone(), p.name.clone()))
            .collect();
        let tun_ifaces = Arc::new(tun_ifaces);
        let dev_ifaces = Arc::new(dev_ifaces);
        let proxy_options = Arc::new(proxy_options);

        // Reactive list of "type:name" target strings; shared with add/remove buttons.
        let targets_list = Arc::new(Mutex::new(init_targets_vec));
        // Currently-selected type for the add-target inline form.
        let new_tgt_type = Arc::new(Mutex::new("tun".to_string()));
        // Currently-selected interface value for the add-target form.
        let selected_iface: Arc<Mutex<String>> =
            Arc::new(Mutex::new(tun_ifaces.first().cloned().unwrap_or_default()));

        let name_c = name_input.clone();
        let color_c = color_input.clone();
        let dns_c = dns_input.clone();

        let hdr_icon = if is_edit { "✏" } else { "⊕" };
        let hdr_title = if is_edit { "EDIT EGRESS" } else { "ADD EGRESS" };
        let ok_label = if is_edit { "Save" } else { "Add Egress" };

        window.open_dialog(cx, move |dialog, _, _cx| {
            // ── Snapshot shared state for this render ───────────────────
            let cur_targets = targets_list.lock().unwrap().clone();
            let cur_tgt_type = new_tgt_type.lock().unwrap().clone();
            let current_color = color_c.read(_cx).value().to_string();
            let color_swatch = colors::hex_to_hsla(&current_color);

            // ── Preset color swatches ────────────────────────────────────
            const PRESET_COLORS: &[(&str, u32)] = &[
                ("#22c55e", 0x22c55e),
                ("#3b82f6", 0x3b82f6),
                ("#f59e0b", 0xf59e0b),
                ("#ef4444", 0xef4444),
                ("#8b5cf6", 0x8b5cf6),
                ("#06b6d4", 0x06b6d4),
            ];
            let preset_swatches: Vec<gpui::AnyElement> = PRESET_COLORS
                .iter()
                .map(|(hex_str, hex_u32)| {
                    let is_selected = current_color.trim_start_matches('#').eq_ignore_ascii_case(
                        &format!("{:06x}", hex_u32),
                    );
                    let color_ent = color_c.clone();
                    let hex = hex_str.to_string();
                    div()
                        .id(gpui::ElementId::Name(format!("swatch-{hex_str}").into()))
                        .w(px(22.))
                        .h(px(22.))
                        .rounded_full()
                        .bg(gpui::rgb(*hex_u32))
                        .cursor_pointer()
                        .when(is_selected, |el| {
                            el.border_2().border_color(colors::text())
                        })
                        .when(!is_selected, |el| {
                            el.border_1().border_color(colors::border())
                        })
                        .on_click(move |_, win, cx| {
                            color_ent.update(cx, |state, ictx| {
                                state.set_value(hex.clone(), win, ictx);
                            });
                        })
                        .into_any_element()
                })
                .collect();

            // ── Per-target rows (each has a remove button) ──────────────
            let target_rows: Vec<gpui::AnyElement> = cur_targets
                .iter()
                .enumerate()
                .map(|(i, tgt)| {
                    let tl = targets_list.clone();
                    let (badge, badge_color): (&str, gpui::Hsla) =
                        if tgt.starts_with("tun:") {
                            ("TUN", colors::green())
                        } else if tgt.starts_with("proxy:") {
                            ("PROXY", colors::primary())
                        } else {
                            ("DEV", colors::muted())
                        };
                    let tgt_name = tgt
                        .split_once(':')
                        .map(|(_, n)| n)
                        .unwrap_or(tgt.as_str())
                        .to_string();
                    div()
                        .id(gpui::ElementId::Name(format!("tgt-row-{i}").into()))
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .px(px(10.))
                        .py(px(5.))
                        .border_b_1()
                        .border_color(colors::border())
                        .child(
                            div()
                                .text_size(px(9.))
                                .text_color(badge_color)
                                .border_1()
                                .border_color(badge_color)
                                .px(px(4.))
                                .py(px(1.))
                                .rounded(px(2.))
                                .font_weight(gpui::FontWeight::BOLD)
                                .child(badge),
                        )
                        .child(
                            div()
                                .flex_1()
                                .text_size(px(12.))
                                .text_color(colors::text())
                                .child(tgt_name),
                        )
                        .child(
                            div()
                                .id(gpui::ElementId::Name(format!("tgt-rm-{i}").into()))
                                .text_size(px(11.))
                                .text_color(colors::muted())
                                .cursor_pointer()
                                .px(px(4.))
                                .on_click(move |_, _, _| {
                                    tl.lock().unwrap().remove(i);
                                })
                                .child("✕"),
                        )
                        .into_any_element()
                })
                .collect();

            // ── Type-button active colors for add-target form ───────────
            let (tc_tun, tc_dev, tc_prx) = match cur_tgt_type.as_str() {
                "tun" => (colors::green(), colors::muted(), colors::muted()),
                "dev" => (colors::muted(), colors::primary(), colors::muted()),
                _ => (colors::muted(), colors::muted(), colors::teal()),
            };
            // ── Snapshot selected_iface for this render ──────────────────
            let cur_sel_iface = selected_iface.lock().unwrap().clone();

            // ── Interface options based on current type ──────────────────
            let (iface_vals, iface_labels): (Vec<String>, Vec<String>) =
                match cur_tgt_type.as_str() {
                    "tun" => (tun_ifaces.as_ref().clone(), tun_ifaces.as_ref().clone()),
                    "dev" => (dev_ifaces.as_ref().clone(), dev_ifaces.as_ref().clone()),
                    _ => proxy_options
                        .iter()
                        .map(|(id, name)| (id.clone(), name.clone()))
                        .unzip(),
                };

            let iface_sel_btns: Vec<gpui::AnyElement> = iface_vals
                .iter()
                .zip(iface_labels.iter())
                .map(|(val, label)| {
                    let is_sel = *val == cur_sel_iface;
                    let color = if is_sel { colors::primary() } else { colors::muted() };
                    let si = selected_iface.clone();
                    let v = val.clone();
                    div()
                        .id(gpui::ElementId::Name(format!("iface-sel-{val}").into()))
                        .px(px(8.))
                        .py(px(4.))
                        .rounded(px(3.))
                        .border_1()
                        .border_color(color)
                        .text_color(color)
                        .text_size(px(11.))
                        .cursor_pointer()
                        .on_click(move |_, _, _| {
                            *si.lock().unwrap() = v.clone();
                        })
                        .child(label.clone())
                        .into_any_element()
                })
                .collect();

            let tt_tun = new_tgt_type.clone();
            let si_tun = selected_iface.clone();
            let tun_first = tun_ifaces.first().cloned().unwrap_or_default();
            let tt_dev = new_tgt_type.clone();
            let si_dev = selected_iface.clone();
            let dev_first = dev_ifaces.first().cloned().unwrap_or_default();
            let tt_prx = new_tgt_type.clone();
            let si_prx = selected_iface.clone();
            let prx_first = proxy_options.first().map(|(id, _)| id.clone()).unwrap_or_default();
            let tl_add = targets_list.clone();
            let tt_add = new_tgt_type.clone();
            let si_add = selected_iface.clone();

            // ── Clones consumed by on_ok ────────────────────────────────
            let name_i = name_c.clone();
            let color_i = color_c.clone();
            let dns_i = dns_c.clone();
            let tl_ok = targets_list.clone();
            let state_w = state_weak.clone();
            let sock = socket_path.clone();
            let eid = existing_id.clone();

            let do_save: Rc<dyn Fn(&mut gpui::App) -> bool> = {
                let name_i = name_i;
                let color_i = color_i;
                let dns_i = dns_i;
                let tl_ok = tl_ok;
                let state_w = state_w;
                let sock = sock;
                let eid = eid;
                Rc::new(move |cx: &mut gpui::App| -> bool {
                    let name = name_i.read(cx).value().to_string();
                    let color = color_i.read(cx).value().to_string();
                    let dns_s = dns_i.read(cx).value().to_string();
                    let targets_vec = tl_ok.lock().unwrap().clone();
                    let targets = helpers::parse_targets_csv(&targets_vec.join(","));
                    let dns = helpers::parse_dns_csv(&dns_s);
                    let id = eid
                        .clone()
                        .unwrap_or_else(|| format!("eg-{}", crate::daemon::unix_now()));
                    let egress = Egress {
                        id,
                        name: if name.trim().is_empty() {
                            "New Egress".into()
                        } else {
                            name
                        },
                        color: if color.trim().is_empty() {
                            "#3b82f6".into()
                        } else {
                            color
                        },
                        targets,
                        dns_servers: dns,
                        is_system_default: false,
                        is_available: false,
                    };
                    let to_send = egress.clone();
                    let sock_c = sock.clone();
                    let state_wc = state_w.clone();
                    let editing = eid.is_some();
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
                                            if let Some(e) =
                                                s.egresses.iter_mut().find(|e| e.id == egress.id)
                                            {
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
            };
            let do_save_btn = do_save.clone();

            dialog
                .p(px(0.))
                .title(modal_header(hdr_icon, hdr_title))
                .w(px(520.))
                .button_props(
                    gpui_component::dialog::DialogButtonProps::default()
                        .ok_text(ok_label)
                        .cancel_text("Cancel"),
                )
                .footer(
                    h_flex()
                        .px(px(16.)).py(px(8.))
                        .gap(px(8.)).justify_end()
                        .child(
                            action_btn("dialog-cancel", "Cancel", crate::colors::muted())
                                .on_click(|_, win, cx| { win.close_dialog(cx); })
                        )
                        .child(
                            action_btn("dialog-ok", ok_label, crate::colors::primary())
                                .on_click(move |_, win, cx| {
                                    do_save_btn(cx);
                                    win.close_dialog(cx);
                                })
                        )
                )
                .child(
                    v_flex()
                        .px(px(16.))
                        .py(px(16.))
                        .gap(px(16.))
                        // Name
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(field_label("NAME"))
                                .child(Input::new(&name_c)),
                        )
                        // Color with preset swatches and live preview
                        .child(
                            v_flex()
                                .gap(px(6.))
                                .child(field_label("COLOR"))
                                .child(
                                    h_flex()
                                        .gap(px(6.))
                                        .items_center()
                                        .children(preset_swatches),
                                )
                                .child(
                                    h_flex()
                                        .gap(px(8.))
                                        .items_center()
                                        .child(Input::new(&color_c))
                                        .child(
                                            div()
                                                .w(px(28.))
                                                .h(px(28.))
                                                .rounded(px(4.))
                                                .border_1()
                                                .border_color(colors::border())
                                                .bg(color_swatch)
                                                .flex_shrink_0(),
                                        ),
                                ),
                        )
                        // Routing Targets
                        .child(
                            v_flex()
                                .gap(px(6.))
                                .child(field_label("ROUTING TARGETS"))
                                // Current target list
                                .child(
                                    div()
                                        .border_1()
                                        .border_color(colors::border())
                                        .rounded(px(4.))
                                        .overflow_hidden()
                                        .when(cur_targets.is_empty(), |el| {
                                            el.child(
                                                div()
                                                    .px(px(10.))
                                                    .py(px(8.))
                                                    .text_size(px(11.))
                                                    .text_color(colors::muted())
                                                    .child(
                                                        "No targets — system routing table used.",
                                                    ),
                                            )
                                        })
                                        .children(target_rows),
                                )
                                // Add-target inline form
                                .child(
                                    v_flex()
                                        .gap(px(6.))
                                        .border_1()
                                        .border_color(colors::border())
                                        .rounded(px(4.))
                                        .px(px(10.))
                                        .py(px(8.))
                                        .child(field_label("ADD TARGET"))
                                        .child(
                                            h_flex()
                                                .gap(px(6.))
                                                .items_center()
                                                // TUN / DEV / PROXY type buttons
                                                .child(
                                                    h_flex()
                                                        .gap(px(4.))
                                                        .child(
                                                            div()
                                                                .id(gpui::ElementId::Name(
                                                                    "tgt-type-tun".into(),
                                                                ))
                                                                .px(px(8.))
                                                                .py(px(4.))
                                                                .rounded(px(3.))
                                                                .border_1()
                                                                .border_color(tc_tun)
                                                                .text_color(tc_tun)
                                                                .text_size(px(9.))
                                                                .font_weight(
                                                                    gpui::FontWeight::BOLD,
                                                                )
                                                                .cursor_pointer()
                                                                .on_click(move |_, _, _| {
                                                                    *tt_tun.lock().unwrap() = "tun".into();
                                                                    *si_tun.lock().unwrap() = tun_first.clone();
                                                                })
                                                                .child("TUN"),
                                                        )
                                                        .child(
                                                            div()
                                                                .id(gpui::ElementId::Name(
                                                                    "tgt-type-dev".into(),
                                                                ))
                                                                .px(px(8.))
                                                                .py(px(4.))
                                                                .rounded(px(3.))
                                                                .border_1()
                                                                .border_color(tc_dev)
                                                                .text_color(tc_dev)
                                                                .text_size(px(9.))
                                                                .font_weight(
                                                                    gpui::FontWeight::BOLD,
                                                                )
                                                                .cursor_pointer()
                                                                .on_click(move |_, _, _| {
                                                                    *tt_dev.lock().unwrap() = "dev".into();
                                                                    *si_dev.lock().unwrap() = dev_first.clone();
                                                                })
                                                                .child("DEV"),
                                                        )
                                                        .child(
                                                            div()
                                                                .id(gpui::ElementId::Name(
                                                                    "tgt-type-proxy".into(),
                                                                ))
                                                                .px(px(8.))
                                                                .py(px(4.))
                                                                .rounded(px(3.))
                                                                .border_1()
                                                                .border_color(tc_prx)
                                                                .text_color(tc_prx)
                                                                .text_size(px(9.))
                                                                .font_weight(
                                                                    gpui::FontWeight::BOLD,
                                                                )
                                                                .cursor_pointer()
                                                                .on_click(move |_, _, _| {
                                                                    *tt_prx.lock().unwrap() = "proxy".into();
                                                                    *si_prx.lock().unwrap() = prx_first.clone();
                                                                })
                                                                .child("PROXY"),
                                                        ),
                                                ),
                                        )
                                        // Interface / proxy selector
                                        .child(
                                            div()
                                                .when(iface_sel_btns.is_empty(), |el| {
                                                    el.child(
                                                        div()
                                                            .text_size(px(11.))
                                                            .text_color(colors::muted())
                                                            .child("No options — add via the Proxies tab."),
                                                    )
                                                })
                                                .when(!iface_sel_btns.is_empty(), |el| {
                                                    el.child(
                                                        div()
                                                            .flex()
                                                            .flex_wrap()
                                                            .gap(px(6.))
                                                            .children(iface_sel_btns),
                                                    )
                                                }),
                                        )
                                        // ADD button
                                        .child(
                                            h_flex()
                                                .justify_end()
                                                .child(
                                                    div()
                                                        .id(gpui::ElementId::Name(
                                                            "tgt-add-btn".into(),
                                                        ))
                                                        .px(px(10.))
                                                        .py(px(5.))
                                                        .rounded(px(3.))
                                                        .border_1()
                                                        .border_color(colors::primary())
                                                        .text_color(colors::primary())
                                                        .text_size(px(10.))
                                                        .font_weight(gpui::FontWeight::BOLD)
                                                        .cursor_pointer()
                                                        .on_click(move |_, _, _| {
                                                            let type_s = tt_add.lock().unwrap().clone();
                                                            let iface = si_add.lock().unwrap().clone();
                                                            if !iface.is_empty() {
                                                                tl_add.lock().unwrap().push(
                                                                    format!("{type_s}:{iface}"),
                                                                );
                                                            }
                                                        })
                                                        .child("ADD"),
                                                ),
                                        ),
                                ),
                        )
                        // DNS
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .child(field_label(
                                    "DNS SERVERS  (comma-separated, empty = system)",
                                ))
                                .child(Input::new(&dns_c)),
                        ),
                )
                .on_ok(move |_, _, cx| do_save(cx))
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
        let init_name = existing
            .as_ref()
            .map(|p| p.name.as_str())
            .unwrap_or("New Proxy")
            .to_string();
        let init_host = existing
            .as_ref()
            .map(|p| p.host.as_str())
            .unwrap_or("127.0.0.1")
            .to_string();
        let init_port = existing
            .as_ref()
            .map(|p| p.port)
            .unwrap_or(1080)
            .to_string();
        let init_proto = existing
            .as_ref()
            .map(|p| p.protocol.clone())
            .unwrap_or(ProxyProtocol::Socks5);
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

        let hdr_icon = if is_edit { "✏" } else { "⊕" };
        let hdr_title = if is_edit { "EDIT PROXY" } else { "ADD PROXY" };
        let ok_label = if is_edit { "Save" } else { "Add Proxy" };

        window.open_dialog(cx, move |dialog, _, _cx| {
            let cur_proto = proto_c.lock().unwrap().clone();

            let proto_socks5 = selected_proto.clone();
            let proto_http = selected_proto.clone();
            let proto_ss = selected_proto.clone();
            let proto_for_ok = proto_c.clone();

            let (sc, hc, sc2) = match cur_proto {
                ProxyProtocol::Socks5 => (colors::green(), colors::muted(), colors::muted()),
                ProxyProtocol::Http => (colors::muted(), colors::primary(), colors::muted()),
                ProxyProtocol::Shadowsocks => (colors::muted(), colors::muted(), colors::teal()),
            };

            let name_i = name_input_c.clone();
            let host_i = host_input_c.clone();
            let port_i = port_input_c.clone();
            let state_w = state_weak.clone();
            let sock = socket_path.clone();
            let eid = existing_id.clone();
            let auth_val = init_auth.clone();

            let do_save: Rc<dyn Fn(&mut gpui::App) -> bool> = {
                let name_i = name_i;
                let host_i = host_i;
                let port_i = port_i;
                let proto_for_ok = proto_for_ok;
                let state_w = state_w;
                let sock = sock;
                let eid = eid;
                let auth_val = auth_val;
                Rc::new(move |cx: &mut gpui::App| -> bool {
                    let name = name_i.read(cx).value().to_string();
                    let host = host_i.read(cx).value().to_string();
                    let port_str = port_i.read(cx).value().to_string();
                    let port: u16 = port_str.trim().parse().unwrap_or(1080);
                    let proto = proto_for_ok.lock().unwrap().clone();
                    let id = eid
                        .clone()
                        .unwrap_or_else(|| format!("px-{}", crate::daemon::unix_now()));
                    let proxy = ProxyConfig {
                        id,
                        name: if name.trim().is_empty() {
                            "New Proxy".into()
                        } else {
                            name
                        },
                        protocol: proto,
                        host: if host.trim().is_empty() {
                            "127.0.0.1".into()
                        } else {
                            host
                        },
                        port,
                        auth: auth_val.clone(),
                        enabled: true,
                    };
                    let to_send = proxy.clone();
                    let sock_c = sock.clone();
                    let state_wc = state_w.clone();
                    let editing = eid.is_some();
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
                                            if let Some(p) =
                                                s.proxies.iter_mut().find(|p| p.id == proxy.id)
                                            {
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
            };
            let do_save_btn = do_save.clone();

            dialog
                .p(px(0.))
                .title(modal_header(hdr_icon, hdr_title))
                .w(px(480.))
                .button_props(
                    gpui_component::dialog::DialogButtonProps::default()
                        .ok_text(ok_label)
                        .cancel_text("Cancel"),
                )
                .footer(
                    h_flex()
                        .px(px(16.))
                        .py(px(8.))
                        .gap(px(8.))
                        .justify_end()
                        .child(
                            action_btn("dialog-cancel", "Cancel", crate::colors::muted()).on_click(
                                |_, win, cx| {
                                    win.close_dialog(cx);
                                },
                            ),
                        )
                        .child(
                            action_btn("dialog-ok", ok_label, crate::colors::primary()).on_click(
                                move |_, win, cx| {
                                    do_save_btn(cx);
                                    win.close_dialog(cx);
                                },
                            ),
                        ),
                )
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
                            v_flex().gap(px(4.)).child(field_label("PROTOCOL")).child(
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
                .on_ok(move |_, _, cx| do_save(cx))
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
            SettingsTab::Rules => gpui_component::table::DataTable::new(&self.rules_table)
                .stripe(true)
                .bordered(true)
                .into_any_element(),
            SettingsTab::Egress => gpui_component::table::DataTable::new(&self.egress_table)
                .stripe(true)
                .bordered(true)
                .into_any_element(),
            SettingsTab::Proxies => gpui_component::table::DataTable::new(&self.proxy_table)
                .stripe(true)
                .bordered(true)
                .into_any_element(),
        };

        // Add button for all tabs
        let add_button: Option<gpui::AnyElement> = match active_tab {
            SettingsTab::Rules => Some(
                div()
                    .id(gpui::ElementId::Name("add-rule-btn".into()))
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
                        this.open_rule_form_dialog(None, window, cx);
                    }))
                    .child("+ ADD RULE")
                    .into_any_element(),
            ),
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
