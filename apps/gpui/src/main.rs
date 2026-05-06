use std::io::{BufRead, BufReader, Write as IoWrite};
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gpui::{
    App, AppContext as _, Application, Context, Entity, FontWeight, IntoElement, ParentElement,
    Render, SharedString, Styled, Window, WindowOptions, div, prelude::FluentBuilder as _, px,
    size,
};
use gpui_component::{
    Root,
    Theme,
    ThemeMode,
    button::{Button, ButtonVariants as _},
    checkbox::Checkbox,
    h_flex, v_flex,
};

use core_types::{PendingDecision, Rule, RuleAction, RuleDuration};
use control_api::{ControlRequest, ControlResponse};

const SOCKET_PATH: &str = "/tmp/logiguard.sock";

// ---------------------------------------------------------------------------
// Colors (Deep Slate security theme)
// ---------------------------------------------------------------------------

fn color_bg() -> gpui::Hsla {
    gpui::hsla(222. / 360., 0.47, 0.07, 1.)
}
fn color_border() -> gpui::Hsla {
    gpui::hsla(215. / 360., 0.14, 0.20, 1.)
}
fn color_amber() -> gpui::Hsla {
    gpui::hsla(38. / 360., 0.92, 0.50, 1.)
}
fn color_amber_dim() -> gpui::Hsla {
    gpui::hsla(38. / 360., 0.92, 0.30, 0.25)
}
fn color_text() -> gpui::Hsla {
    gpui::hsla(210. / 360., 0.40, 0.96, 1.)
}
fn color_muted() -> gpui::Hsla {
    gpui::hsla(215. / 360., 0.14, 0.58, 1.)
}

// ---------------------------------------------------------------------------
// Daemon socket communication
// ---------------------------------------------------------------------------

fn send_request(path: &str, req: &ControlRequest) -> Result<ControlResponse, String> {
    let mut stream =
        UnixStream::connect(path).map_err(|e| format!("connect failed: {e}"))?;
    let payload = serde_json::to_string(req).map_err(|e| e.to_string())?;
    stream
        .write_all(format!("{payload}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if line.trim().is_empty() {
        return Err("empty response from daemon".into());
    }
    serde_json::from_str(line.trim_end()).map_err(|e| e.to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

struct AppState {
    pending: Vec<PendingDecision>,
    now_secs: u64,
    daemon_connected: bool,
    make_permanent: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            now_secs: unix_now(),
            daemon_connected: false,
            make_permanent: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionApp — root view
// ---------------------------------------------------------------------------

struct DecisionApp {
    state: Entity<AppState>,
}

impl DecisionApp {
    fn new(state: Entity<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe(&state, |_, _, cx| cx.notify()).detach();
        Self { state }
    }

    fn render_empty(&self) -> impl IntoElement {
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .gap_3()
            .bg(color_bg())
            .child(
                div()
                    .text_color(color_amber())
                    .text_xl()
                    .font_weight(FontWeight::BOLD)
                    .child("LOGIGUARD"),
            )
            .child(
                div()
                    .text_color(color_muted())
                    .text_sm()
                    .child("No pending decisions"),
            )
    }

    fn render_connecting(&self) -> impl IntoElement {
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .gap_3()
            .bg(color_bg())
            .child(
                div()
                    .text_color(color_amber())
                    .text_xl()
                    .font_weight(FontWeight::BOLD)
                    .child("LOGIGUARD"),
            )
            .child(
                div()
                    .text_color(color_muted())
                    .text_sm()
                    .child("Connecting to daemon…"),
            )
    }

    fn render_decision(
        &self,
        item: &PendingDecision,
        now: u64,
        make_permanent: bool,
        _cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let remaining = item.deadline_at_secs.saturating_sub(now);
        let process = item
            .flow
            .process_name
            .clone()
            .unwrap_or_else(|| "unknown".into());
        let domain = item.flow.destination_domain.clone();
        let ip = item.flow.destination_ip.clone();
        let proto = format!("{:?}", item.flow.protocol).to_uppercase();
        let pending_id = item.id.clone();
        let flow = item.flow.clone();

        let state_weak = self.state.downgrade();
        let state_weak2 = self.state.downgrade();
        let state_weak3 = self.state.downgrade();
        let pid_allow = pending_id.clone();
        let pid_deny = pending_id.clone();
        let flow_allow = flow.clone();

        v_flex()
            .size_full()
            .bg(color_bg())
            // ── Header bar ──────────────────────────────────────────────
            .child(
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .px_4()
                    .py_3()
                    .bg(color_amber_dim())
                    .border_b_1()
                    .border_color(color_amber())
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                div()
                                    .text_color(color_amber())
                                    .font_weight(FontWeight::BOLD)
                                    .text_sm()
                                    .child("⚠  CONNECTION INTERCEPTED"),
                            ),
                    )
                    .child(
                        div()
                            .text_color(color_amber())
                            .font_weight(FontWeight::BOLD)
                            .text_lg()
                            .child(format!("{remaining}s")),
                    ),
            )
            // ── Content ──────────────────────────────────────────────────
            .child(
                v_flex()
                    .flex_1()
                    .px_5()
                    .py_4()
                    .gap_4()
                    // APPLICATION
                    .child(
                        v_flex()
                            .gap_1()
                            .child(
                                div()
                                    .text_color(color_muted())
                                    .text_xs()
                                    .font_weight(FontWeight::BOLD)
                                    
                                    .child("APPLICATION"),
                            )
                            .child(
                                h_flex()
                                    .gap_3()
                                    .items_center()
                                    .child(
                                        div()
                                            .text_color(color_text())
                                            .text_xl()
                                            .font_weight(FontWeight::BOLD)
                                            .child(SharedString::from(process.clone())),
                                    )
                                    .child(
                                        div()
                                            .px_2()
                                            .py_px()
                                            .rounded(px(4.))
                                            .bg(color_border())
                                            .text_color(color_muted())
                                            .text_xs()
                                            .child(SharedString::from(proto)),
                                    ),
                            ),
                    )
                    // DIVIDER
                    .child(div().w_full().h_px().bg(color_border()))
                    // DESTINATION
                    .child(
                        v_flex()
                            .gap_1()
                            .child(
                                div()
                                    .text_color(color_muted())
                                    .text_xs()
                                    .font_weight(FontWeight::BOLD)
                                    
                                    .child("DESTINATION"),
                            )
                            .when_some(domain.clone(), |el, d| {
                                el.child(
                                    div()
                                        .text_color(color_text())
                                        .text_lg()
                                        .font_weight(FontWeight::BOLD)
                                        .child(SharedString::from(d)),
                                )
                            })
                            .child(
                                div()
                                    .text_color(color_muted())
                                    .text_sm()
                                    .child(SharedString::from(ip.clone())),
                            ),
                    )
                    // DIVIDER
                    .child(div().w_full().h_px().bg(color_border()))
                    // REMEMBER CHECKBOX
                    .child(
                        Checkbox::new("make-permanent")
                            .label("Remember this decision (permanent rule)")
                            .checked(make_permanent)
                            .on_click({
                                move |checked, _, cx| {
                                    if let Some(state) = state_weak3.upgrade() {
                                        state.update(cx, |s, cx| {
                                            s.make_permanent = *checked;
                                            cx.notify();
                                        });
                                    }
                                }
                            }),
                    ),
            )
            // ── Footer buttons ──────────────────────────────────────────
            .child(
                h_flex()
                    .w_full()
                    .gap_3()
                    .px_5()
                    .py_4()
                    .border_t_1()
                    .border_color(color_border())
                    .child(
                        Button::new("deny-btn")
                            .label("Deny")
                            .danger()
                            .w_full()
                            .on_click(move |_, _, cx| {
                                let pid = pid_deny.clone();
                                let state_weak = state_weak2.clone();
                                cx.spawn(async move |cx| {
                                    let pid2 = pid.clone();
                                    let _ = cx
                                        .background_executor()
                                        .spawn(async move {
                                            send_request(
                                                SOCKET_PATH,
                                                &ControlRequest::ResolvePending {
                                                    pending_id: pid2,
                                                    action: RuleAction::Deny,
                                                },
                                            )
                                        })
                                        .await;
                                    if let Some(state) = state_weak.upgrade() {
                                        cx.update_entity(&state, |s, cx| {
                                            s.pending.retain(|p| p.id != pid);
                                            cx.notify();
                                        })
                                        .ok();
                                    }
                                })
                                .detach();
                            }),
                    )
                    .child(
                        Button::new("allow-btn")
                            .label("Allow")
                            .success()
                            .w_full()
                            .on_click(move |_, _, cx| {
                                let pid = pid_allow.clone();
                                let state_weak = state_weak.clone();
                                let mk_perm = make_permanent;
                                let flow = flow_allow.clone();
                                cx.spawn(async move |cx| {
                                    let pid2 = pid.clone();
                                    let _ = cx
                                        .background_executor()
                                        .spawn(async move {
                                            send_request(
                                                SOCKET_PATH,
                                                &ControlRequest::ResolvePending {
                                                    pending_id: pid2,
                                                    action: RuleAction::Allow,
                                                },
                                            )
                                        })
                                        .await;
                                    if mk_perm {
                                        let dest = if let Some(d) = &flow.destination_domain {
                                            core_types::DestinationMatcher::DomainExact(
                                                d.clone(),
                                            )
                                        } else {
                                            core_types::DestinationMatcher::IpExact(
                                                flow.destination_ip.clone(),
                                            )
                                        };
                                        let rule = Rule {
                                            id: format!("ui-{}", unix_now()),
                                            enabled: true,
                                            action: RuleAction::Allow,
                                            duration: RuleDuration::Permanent,
                                            process_name: flow.process_name.clone(),
                                            destination: dest,
                                        };
                                        let _ = cx
                                            .background_executor()
                                            .spawn(async move {
                                                send_request(
                                                    SOCKET_PATH,
                                                    &ControlRequest::AddRule(rule),
                                                )
                                            })
                                            .await;
                                    }
                                    if let Some(state) = state_weak.upgrade() {
                                        cx.update_entity(&state, |s, cx| {
                                            s.pending.retain(|p| p.id != pid);
                                            s.make_permanent = false;
                                            cx.notify();
                                        })
                                        .ok();
                                    }
                                })
                                .detach();
                            }),
                    ),
            )
    }
}

impl Render for DecisionApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let state = self.state.read(cx);
        let connected = state.daemon_connected;
        let has_pending = !state.pending.is_empty();
        let now = state.now_secs;
        let make_permanent = state.make_permanent;

        if !connected {
            return self.render_connecting().into_any_element();
        }
        if !has_pending {
            return self.render_empty().into_any_element();
        }

        let item = state.pending[0].clone();
        let _ = state;
        self.render_decision(&item, now, make_permanent, cx)
            .into_any_element()
    }
}

// ---------------------------------------------------------------------------
// Background polling task
// ---------------------------------------------------------------------------

fn start_polling(state: Entity<AppState>, cx: &mut App) {
    cx.spawn(async move |cx| {
        loop {
            let result = cx
                .background_executor()
                .spawn(async move {
                    send_request(SOCKET_PATH, &ControlRequest::ListPending)
                })
                .await;

            cx.update_entity(&state, |s, cx| {
                s.now_secs = unix_now();
                match result {
                    Ok(ControlResponse::PendingList(items)) => {
                        s.daemon_connected = true;
                        // Sort by deadline so we show the most urgent first
                        let mut items = items;
                        items.sort_by_key(|p| p.deadline_at_secs);
                        s.pending = items;
                    }
                    _ => {
                        s.daemon_connected = false;
                    }
                }
                cx.notify();
            })
            .ok();

            cx.background_executor()
                .timer(Duration::from_secs(1))
                .await;
        }
    })
    .detach();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    Application::new().run(|cx: &mut App| {
        gpui_component::init(cx);
        Theme::change(ThemeMode::Dark, None, cx);

        let state = cx.new(|_| AppState::default());
        start_polling(state.clone(), cx);

        cx.open_window(
            WindowOptions {
                window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds::centered(
                    None,
                    size(px(480.), px(580.)),
                    cx,
                ))),
                titlebar: Some(gpui::TitlebarOptions {
                    title: Some(SharedString::from("LogiGuard")),
                    appears_transparent: false,
                    ..Default::default()
                }),
                ..Default::default()
            },
            |window, cx| {
                let view = cx.new(|cx| DecisionApp::new(state, cx));
                cx.new(|cx| Root::new(view, window, cx))
            },
        )
        .expect("failed to open window");

        cx.activate(true);
    });
}
