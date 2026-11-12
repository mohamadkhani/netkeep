//! First-run + daemon-status window (#18).
//!
//! A single window that replaces silent polling with explicit state:
//! - daemon running → normal (welcome text on first run, interception-off banner)
//! - stopped cleanly → "not filtering" + Start button
//! - crashed while intercepting → "network blocked (fail-close)" + Start + Unblock
//!
//! State detection: daemon health over the control socket; when the socket is
//! dead, the `/run/netkeep/rules-active` marker (owned by the daemon, see
//! #19) tells the unprivileged GUI whether the ruleset is still installed.

use std::path::PathBuf;

use gpui::prelude::FluentBuilder as _;
use gpui::{
    div, px, App, AppContext as _, Context, Entity, FocusHandle, Focusable, InteractiveElement,
    IntoElement, ParentElement, Render, SharedString, Styled, Window,
};
use gpui_component::{h_flex, v_flex, Root};

use crate::colors;
use crate::components::ds;
use crate::daemon;

// ---------------------------------------------------------------------------
// Pure state logic (unit-tested)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DaemonStatus {
    Running,
    StoppedClean,
    CrashedBlocked,
}

/// Map (daemon reachable, ruleset marker present) to the user-facing state.
/// The marker only matters when the daemon is unreachable: while it answers,
/// health is the source of truth regardless of the marker.
pub fn daemon_status(health_ok: bool, rules_marker_present: bool) -> DaemonStatus {
    if health_ok {
        DaemonStatus::Running
    } else if rules_marker_present {
        DaemonStatus::CrashedBlocked
    } else {
        DaemonStatus::StoppedClean
    }
}

pub fn rules_marker_path() -> PathBuf {
    std::env::var("NETKEEP_RULES_MARKER")
        .unwrap_or_else(|_| "/run/netkeep/rules-active".to_string())
        .into()
}

pub fn rules_marker_present() -> bool {
    rules_marker_path().exists()
}

/// Display-once flag for the welcome section.
pub fn welcome_seen_path() -> PathBuf {
    let config = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_home().join(".config"));
    config.join("netkeep").join("welcome-seen")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}

pub fn welcome_marker_exists() -> bool {
    welcome_seen_path().exists()
}

pub fn mark_welcome_seen() {
    let path = welcome_seen_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, "seen\n");
}

/// One-click daemon enable (from #16): enable at boot and start now.
pub const START_CMD: &[&str] = &["pkexec", "systemctl", "enable", "--now", "netkeepd.service"];
/// Emergency escape hatch: delete the ruleset, restoring traffic without protection.
pub const UNBLOCK_CMD: &[&str] = &["pkexec", "nft", "delete", "table", "inet", "netkeep"];
/// Ground-truth check for the security-minded user.
pub const VERIFY_CMD: &[&str] = &["pkexec", "nft", "list", "table", "inet", "netkeep"];

/// Run a pkexec-wrapped command, returning (success, combined output).
pub fn run_command(cmd: &[&str]) -> (bool, String) {
    let (program, args) = cmd.split_first().expect("command must not be empty");
    match std::process::Command::new(program).args(args).output() {
        Ok(out) => {
            let mut text = String::new();
            text.push_str(&String::from_utf8_lossy(&out.stdout));
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            (out.status.success(), text.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

/// Health + marker → current status. Blocking (short socket timeout inside).
pub fn current_status() -> DaemonStatus {
    let health_ok = daemon::get_nfqueue_status().is_ok();
    daemon_status(health_ok, rules_marker_present())
}

// ---------------------------------------------------------------------------
// Window state + view
// ---------------------------------------------------------------------------

pub struct FirstRunState {
    status: DaemonStatus,
    /// `Some(false)` = daemon reachable but interception off (banner).
    nfqueue_enabled: Option<bool>,
    show_welcome: bool,
    /// (ok, message) of the last button action.
    result: Option<(bool, SharedString)>,
    /// A pkexec action is running (buttons disabled).
    busy: bool,
}

pub struct FirstRunApp {
    state: Entity<FirstRunState>,
    focus_handle: FocusHandle,
}

impl Focusable for FirstRunApp {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl FirstRunState {
    /// Run a privileged command in the background, then refresh status and
    /// surface the outcome in the result line.
    fn run_action(
        &mut self,
        cx: &mut Context<Self>,
        cmd: &'static [&'static str],
        ok_message: &'static str,
    ) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.result = None;
        cx.notify();
        let state = cx.entity();
        cx.spawn(async move |_this, cx| {
            let outcome = cx
                .background_executor()
                .spawn(async move { run_command(cmd) })
                .await;
            // Refresh status after the action (Start/Unblock change it).
            let health = cx
                .background_executor()
                .spawn(async { daemon::get_nfqueue_status().ok() })
                .await;
            let marker = cx
                .background_executor()
                .spawn(async { rules_marker_present() })
                .await;
            cx.update_entity(&state, |s, cx| {
                s.busy = false;
                s.status = daemon_status(health.is_some(), marker);
                s.nfqueue_enabled = health.map(|(enabled, _)| enabled);
                s.result = Some(if outcome.0 {
                    (true, ok_message.into())
                } else if outcome.1.contains("dismissed") || outcome.1.contains("120") {
                    (false, "Cancelled".into())
                } else {
                    (false, outcome.1.into())
                });
                cx.notify();
            });
        })
        .detach();
    }
}

impl FirstRunApp {
    pub fn new(state: Entity<FirstRunState>, cx: &mut Context<Self>) -> Self {
        cx.observe(&state, |_, _, cx| cx.notify()).detach();

        // 2-second refresh loop: daemon health (+ NFQUEUE flag when alive),
        // marker check when dead. Stops when the entity is gone.
        let state_weak = state.downgrade();
        cx.spawn(async move |_this, cx| loop {
            cx.background_executor()
                .timer(std::time::Duration::from_secs(2))
                .await;
            let Some(state) = state_weak.upgrade() else {
                break;
            };
            let health = cx
                .background_executor()
                .spawn(async { daemon::get_nfqueue_status().ok() })
                .await;
            let marker = cx
                .background_executor()
                .spawn(async { rules_marker_present() })
                .await;
            cx.update_entity(&state, |s, cx| {
                s.status = daemon_status(health.is_some(), marker);
                s.nfqueue_enabled = health.map(|(enabled, _)| enabled);
                cx.notify();
            });
        })
        .detach();

        Self {
            state,
            focus_handle: cx.focus_handle(),
        }
    }
}

impl Render for FirstRunApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let s = self.state.read(cx);
        let status = s.status;
        let nfqueue_enabled = s.nfqueue_enabled;
        let show_welcome = s.show_welcome;
        let busy = s.busy;
        let result = s.result.clone();
        let state_weak = self.state.downgrade();
        let state_weak2 = state_weak.clone();
        let state_weak3 = state_weak.clone();

        let (status_text, status_color) = match status {
            DaemonStatus::Running => ("RUNNING", colors::green()),
            DaemonStatus::StoppedClean => ("NOT FILTERING", colors::orange()),
            DaemonStatus::CrashedBlocked => ("NETWORK BLOCKED", colors::error()),
        };

        let body_text: SharedString = match status {
            DaemonStatus::Running => {
                "The Netkeep daemon is running. New connections will ask before they pass."
                    .into()
            }
            DaemonStatus::StoppedClean => {
                "The daemon is not running. Connections are not filtered while it is stopped."
                    .into()
            }
            DaemonStatus::CrashedBlocked => {
                "The daemon crashed while intercepting. New connections are being blocked (fail-close)."
                    .into()
            }
        };

        // Status row refreshes every 2s; rebuild the weak handle for actions.
        let mut card = v_flex()
            .w(px(480.))
            .bg(colors::surface_container())
            .border_1()
            .border_color(colors::border())
            .rounded(px(12.))
            .p(px(20.))
            .gap(px(14.))
            .child(
                h_flex()
                    .items_center()
                    .gap(px(8.))
                    .child(ds::badge("NETKEEP", colors::primary()))
                    .child(
                        div()
                            .text_size(px(13.))
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(colors::text())
                            .child("Status"),
                    ),
            );

        if show_welcome {
            card = card.child(
                v_flex()
                    .gap(px(4.))
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(colors::text())
                            .child("Welcome to Netkeep."),
                    )
                    .child(div().text_size(px(12.)).text_color(colors::muted()).child(
                        "Netkeep asks you before apps connect. Rules live in Settings \
                                 (tray menu). This window shows the daemon status.",
                    )),
            );
        }

        card = card
            .child(
                h_flex()
                    .items_center()
                    .gap(px(8.))
                    .child(ds::badge(status_text, status_color))
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(colors::text())
                            .child(body_text),
                    ),
            )
            // Interception-off banner: only meaningful while the daemon answers.
            .when(
                status == DaemonStatus::Running && nfqueue_enabled == Some(false),
                |el| {
                    el.child(
                        div()
                            .w_full()
                            .rounded(px(6.))
                            .border_1()
                            .border_color(colors::orange())
                            .bg(gpui::Hsla {
                                a: 0.10,
                                ..colors::orange()
                            })
                            .px(px(10.))
                            .py(px(6.))
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(colors::orange())
                                    .child("Interception is off — enable it from the tray menu."),
                            ),
                    )
                },
            );

        if let Some((ok, message)) = result {
            card = card.child(
                div()
                    .w_full()
                    .text_size(px(11.))
                    .text_color(if ok { colors::green() } else { colors::error() })
                    .child(message),
            );
        }

        let mut buttons = h_flex().items_center().gap(px(8.)).flex_wrap();
        if status != DaemonStatus::Running {
            buttons = buttons.child(ds::chip(
                "fr-start",
                "START NETKEEP",
                true,
                move |_, _, cx| {
                    if let Some(view) = state_weak.upgrade() {
                        view.update(cx, |s, cx| s.run_action(cx, START_CMD, "Daemon started."));
                    }
                },
            ));
        }
        if status == DaemonStatus::CrashedBlocked {
            buttons = buttons.child(ds::chip(
                "fr-unblock",
                "REMOVE BLOCK (UNPROTECTED)",
                false,
                move |_, _, cx| {
                    if let Some(view) = state_weak2.upgrade() {
                        view.update(cx, |s, cx| {
                            s.run_action(
                                cx,
                                UNBLOCK_CMD,
                                "Ruleset removed: traffic flows unfiltered.",
                            )
                        });
                    }
                },
            ));
        }
        if status != DaemonStatus::Running {
            buttons = buttons.child(ds::chip(
                "fr-verify",
                "VERIFY…",
                false,
                move |_, _, cx| {
                    if let Some(view) = state_weak3.upgrade() {
                        view.update(cx, |s, cx| s.run_action(cx, VERIFY_CMD, ""));
                    }
                },
            ));
        }
        buttons = buttons.child(ds::chip("fr-close", "CLOSE", false, |_, window, _| {
            window.remove_window();
        }));

        // Disable interaction while a pkexec action runs: overlay a hint row.
        let disabled_note = busy.then(|| {
            div()
                .text_size(px(11.))
                .text_color(colors::muted())
                .child("Waiting for authorization…")
        });

        card = card.child(buttons).children(disabled_note).child(
            div()
                .text_size(px(10.))
                .text_color(colors::muted())
                .child("Status refreshes automatically every 2 seconds."),
        );

        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .bg(colors::bg())
            .track_focus(&self.focus_handle)
            .child(card)
    }
}

// ---------------------------------------------------------------------------
// Window bootstrap (called from main.rs on the GPUI main thread)
// ---------------------------------------------------------------------------

/// Open the first-run/status window. `show_welcome` gates the one-time
/// welcome section; the marker is written by the caller at open time.
pub fn open_first_run_window(cx: &mut App, show_welcome: bool) {
    let state: Entity<FirstRunState> = cx.new(|_| FirstRunState {
        status: current_status(),
        nfqueue_enabled: daemon::get_nfqueue_status().ok().map(|(e, _)| e),
        show_welcome,
        result: None,
        busy: false,
    });
    let _ = cx.open_window(
        gpui::WindowOptions {
            window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds {
                origin: gpui::point(px(120.), px(120.)),
                size: gpui::size(px(520.), px(380.)),
            })),
            titlebar: Some(gpui_component::TitleBar::title_bar_options()),
            window_decorations: Some(gpui::WindowDecorations::Client),
            window_min_size: Some(gpui::size(px(420.), px(300.))),
            is_resizable: true,
            ..Default::default()
        },
        |window, cx| {
            window.set_app_id("netkeep");
            let view = cx.new(|cx| FirstRunApp::new(state, cx));
            cx.new(|cx| Root::new(view, window, cx))
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_status_mapping() {
        assert_eq!(daemon_status(true, false), DaemonStatus::Running);
        assert_eq!(daemon_status(true, true), DaemonStatus::Running);
        assert_eq!(daemon_status(false, true), DaemonStatus::CrashedBlocked);
        assert_eq!(daemon_status(false, false), DaemonStatus::StoppedClean);
    }

    #[test]
    fn rules_marker_path_env_override() {
        // Save + restore: tests run in-process, serially per binary.
        std::env::remove_var("NETKEEP_RULES_MARKER");
        assert_eq!(
            rules_marker_path(),
            PathBuf::from("/run/netkeep/rules-active")
        );
        std::env::set_var("NETKEEP_RULES_MARKER", "/tmp/kilo/marker");
        assert_eq!(rules_marker_path(), PathBuf::from("/tmp/kilo/marker"));
        std::env::remove_var("NETKEEP_RULES_MARKER");
    }

    #[test]
    fn welcome_marker_roundtrip() {
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/kilo/xdg-test");
        assert!(!welcome_marker_exists());
        mark_welcome_seen();
        assert!(welcome_marker_exists());
        std::fs::remove_dir_all("/tmp/kilo/xdg-test").ok();
        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn command_construction() {
        assert_eq!(START_CMD[0], "pkexec");
        assert_eq!(START_CMD[1], "systemctl");
        assert!(START_CMD.iter().any(|a| a.contains("netkeepd")));
        assert_eq!(UNBLOCK_CMD[..3], ["pkexec", "nft", "delete"]);
        assert_eq!(VERIFY_CMD[..3], ["pkexec", "nft", "list"]);
    }

    #[test]
    fn run_command_reports_missing_program() {
        let (ok, message) = run_command(&["definitely-not-a-real-binary-xyz"]);
        assert!(!ok);
        assert!(!message.is_empty());
    }
}
