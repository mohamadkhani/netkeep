//! Settings window (opened from the tray menu).

mod egress_tab;
mod helpers;
mod rules_tab;

use core_types::{Egress, Rule};
use gpui::{
    AppContext as _, Context, ElementId, Entity, InteractiveElement, IntoElement, ParentElement,
    Render, StatefulInteractiveElement, Styled, Window, div, px,
    prelude::FluentBuilder as _,
};
use gpui_component::input::InputState;
use gpui_component::tab::{Tab, TabBar};
use gpui_component::TitleBar;
use gpui_component::{h_flex, v_flex};

use crate::colors;

// Re-export helpers needed by main.rs (refresh action).
pub use helpers::fetch_and_apply;

// ── Tab enum ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
pub enum SettingsTab {
    Rules,
    Egress,
}

// ── State ──────────────────────────────────────────────────────────────

pub struct SettingsState {
    pub rules: Vec<Rule>,
    pub egresses: Vec<Egress>,
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
    dns_inputs: Vec<Entity<InputState>>,
    dns_built_generation: u64,
}

impl SettingsApp {
    pub fn new(state: Entity<SettingsState>, cx: &mut Context<Self>) -> Self {
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

    /// Rebuild DNS input entities when the data generation changes.
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

impl Render for SettingsApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.sync_dns_inputs(window, cx);

        let state = self.state.read(cx);
        let status = state.status.clone();
        let socket_path = state.socket_path.clone();
        let rules = state.rules.clone();
        let egresses = state.egresses.clone();
        let active_tab = state.active_tab;

        let weak = self.state.downgrade();
        let weak_refresh = weak.clone();
        let socket_for_refresh = socket_path.clone();

        let selected_index = match active_tab {
            SettingsTab::Rules => 0,
            SettingsTab::Egress => 1,
        };

        let tab_bar = TabBar::new("settings-tabs")
            .selected_index(selected_index)
            .on_click(cx.listener(|this, index: &usize, _, cx| {
                let tab = match index {
                    0 => SettingsTab::Rules,
                    _ => SettingsTab::Egress,
                };
                let _ = cx.update_entity(&this.state, |s, cx| {
                    s.active_tab = tab;
                    cx.notify();
                });
            }))
            .child(Tab::new().label("Rules"))
            .child(Tab::new().label("Egress"));

        let content = match active_tab {
            SettingsTab::Rules => {
                rules_tab::render_rules_tab(rules, weak.clone(), socket_path.clone())
            }
            SettingsTab::Egress => egress_tab::render_egress_tab(
                egresses,
                &self.dns_inputs,
                weak.clone(),
                socket_path.clone(),
            ),
        };

        v_flex()
            .size_full()
            .bg(colors::bg())
            .text_color(colors::text())
            // Title bar with drag, close button, icon, title, and refresh
            .child(
                TitleBar::new()
                    .on_close_window(|_, window, _| {
                        // Safe to remove: settings runs as its own process.
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
                                    .id(ElementId::Name("settings-refresh".into()))
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
            // Tab content
            .child(content)
            .into_any_element()
    }
}
