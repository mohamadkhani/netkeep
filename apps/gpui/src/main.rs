mod app;
mod colors;
mod components;
mod daemon;
mod decision_dialog;
mod fonts;
mod log_viewer;
mod monitor;
mod settings;
mod state;
#[cfg(target_os = "linux")]
mod tray;

use std::time::Duration;

use gpui::{px, size, AnyView, App, AppContext as _, Entity, WindowOptions};
use gpui_component::{Root, Theme, ThemeMode};

use settings::{SettingsApp, SettingsState};

#[cfg(target_os = "linux")]
use tray::{spawn_tray, TrayAction};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    diag_log(&format!("netkeep-gpui starting, args={:?}", args));

    if let Some(idx) = args.iter().position(|a| a == "--pending-id") {
        let pending_id = args.get(idx + 1).expect("--pending-id requires a value");
        run_gui(pending_id.to_string());
    } else if let Some(idx) = args.iter().position(|a| a == "--log-viewer") {
        let socket_path = daemon::resolve_socket_path(args.get(idx + 1).map(|s| s.as_str()));
        run_log_viewer(&socket_path);
    } else if args.iter().any(|a| a == "--headless-monitor") {
        // Legacy: poll only (no tray). Useful for automated tests.
        let socket_path = daemon::resolve_socket_path(None);
        let gui_command = std::env::var("NETKEEP_GUI_COMMAND").unwrap_or_else(|_| {
            std::env::current_exe()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_else(|_| "netkeep-gpui".to_string())
        });
        monitor::poll_decision_spawner(socket_path, gui_command);
    } else {
        run_tray_monitor();
    }
}

/// Append a diagnostic line to `/tmp/netkeep-tray.log`. The tray monitor is
/// typically launched via a desktop file whose stderr is not visible, so
/// `eprintln!` output would be lost. Check the file when debugging tray behavior.
fn diag_log(msg: &str) {
    use std::io::Write;
    let path =
        std::env::var("NETKEEP_TRAY_LOG").unwrap_or_else(|_| "/tmp/netkeep-tray.log".to_string());
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{msg}");
    }
    eprintln!("{msg}");
}

/// Open (or raise) the settings window. `filter_rule_id` switches to the
/// Rules tab and filters by that rule id; `token` raises it authoritatively.
fn open_or_raise_settings(
    state: &Entity<SettingsState>,
    token: Option<String>,
    filter_rule_id: Option<String>,
    cx: &mut gpui::App,
) {
    if let Some(rule_id) = filter_rule_id {
        cx.update_entity(state, |s, cx| {
            s.active_tab = settings::SettingsTab::Rules;
            s.rules_filter.search = rule_id;
            cx.notify();
        });
    }
    // Settings is open iff some window's root `Root` wraps a view of type
    // `SettingsApp` (`AnyView::entity_type` is the concrete TypeId).
    let want = std::any::TypeId::of::<SettingsApp>();
    let existing = cx.windows().into_iter().find(|w| {
        w.downcast::<Root>()
            .and_then(|handle| {
                handle
                    .update(cx, move |root: &mut Root, _window, _cx| {
                        root.view().entity_type() == want
                    })
                    .ok()
            })
            .unwrap_or(false)
    });
    if let Some(window) = existing {
        raise_window(window, token, cx);
        return;
    }
    let state = state.clone();
    let _ = cx.open_window(
        WindowOptions {
            window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds {
                origin: gpui::point(px(80.), px(40.)),
                size: size(px(960.), px(720.)),
            })),
            titlebar: Some(gpui_component::TitleBar::title_bar_options()),
            window_decorations: Some(gpui::WindowDecorations::Client),
            window_min_size: Some(size(px(640.), px(420.))),
            is_resizable: true,
            ..Default::default()
        },
        |window, cx| {
            window.set_app_id("netkeep");
            let view = cx.new(|cx| SettingsApp::new(state, window, cx));
            cx.new(|cx| Root::new(view, window, cx))
        },
    );
}

/// Raise+focus `window` with the (optional) compositor activation token.
fn raise_window(window: gpui::AnyWindowHandle, token: Option<String>, cx: &mut gpui::App) {
    let _ = window.update(cx, move |_, w, _| {
        w.activate_window();
        if let Some(tok) = token.as_deref() {
            w.activate_with_token(tok);
        }
    });
}

/// Holds the settings state that log-viewer rule clicks route to. Tray mode
/// seeds it up front so both the Settings menu and rule clicks share one
/// state entity; standalone mode fills it lazily on the first click.
pub struct RuleClickSink {
    settings_state: Option<Entity<SettingsState>>,
}

fn run_tray_monitor() {
    let socket_path = daemon::resolve_socket_path(None);
    let gui_command = std::env::var("NETKEEP_GUI_COMMAND").unwrap_or_else(|_| {
        std::env::current_exe()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_else(|_| "netkeep-gpui".to_string())
    });

    diag_log(&format!(
        "netkeep-gpui: ksni tray + pending monitor, socket {socket_path}"
    ));
    #[cfg(target_os = "linux")]
    diag_log(
        "netkeep-gpui: GNOME hides legacy tray icons unless the shell extension          \"AppIndicator and KStatusNotifierItem Support\" (or equivalent) is enabled.",
    );

    // Sync the tray icon with the current NFQUEUE state on startup.
    let nfqueue_enabled = daemon::get_nfqueue_status()
        .map(|(e, _)| e)
        .unwrap_or(false);
    let (action_rx, state_tx, _stop_tx) = spawn_tray(nfqueue_enabled);

    // Pending-decision monitor runs on its own thread (spawns --pending-id GUIs).
    let sp = socket_path.clone();
    let gc = gui_command.clone();
    std::thread::spawn(move || monitor::poll_decision_spawner(sp, gc));

    gpui_platform::application()
        .with_assets(gpui_component_assets::Assets)
        // The tray must survive closing the settings window. Default QuitMode
        // quits the app when the last window closes, which would tear down the
        // ksni tray + daemon monitor. Quit only on the explicit "Quit" tray
        // action (cx.quit() in the TrayAction::Quit handler below).
        .with_quit_mode(gpui::QuitMode::Explicit)
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
            Theme::change(ThemeMode::Dark, None, cx);
            fonts::apply_design_fonts(cx);

            // Poll the tray action channel from the GPUI main loop.
            let sock = socket_path.clone();
            // One settings state for the process lifetime so the log viewer's
            // rule clicks filter the same window the Settings menu opens.
            let settings_state: Entity<SettingsState> =
                cx.new(|_| SettingsState::new(socket_path.clone()));
            let rule_clicks = cx.new(|_| RuleClickSink {
                settings_state: Some(settings_state.clone()),
            });
            cx.spawn(async move |app| loop {
                app.background_executor()
                    .timer(Duration::from_millis(50))
                    .await;
                while let Ok(action) = action_rx.try_recv() {
                    match action {
                        TrayAction::NfqueueEnable => {
                            if let Err(e) = daemon::set_nfqueue_enabled(true) {
                                diag_log(&format!("failed to enable NFQUEUE: {e}"));
                            } else {
                                // Refresh the tray icon to reflect the new state.
                                let _ = state_tx.send(true);
                            }
                        }
                        TrayAction::NfqueueDisable => {
                            if let Err(e) = daemon::set_nfqueue_enabled(false) {
                                diag_log(&format!("failed to disable NFQUEUE: {e}"));
                            } else {
                                let _ = state_tx.send(false);
                            }
                        }
                        TrayAction::Settings { token } => {
                            diag_log(&format!(
                                "tray: Settings action, token={}",
                                match &token {
                                    Some(t) => format!("Some({} chars)", t.len()),
                                    None => "None".to_string(),
                                }
                            ));
                            app.update(|cx| {
                                open_or_raise_settings(&settings_state, token, None, cx);
                                cx.activate(true);
                            });
                        }
                        TrayAction::LogViewer { token } => {
                            app.update(|cx| {
                                open_log_viewer_window(
                                    sock.clone(),
                                    token,
                                    rule_clicks.clone(),
                                    cx,
                                );
                                cx.activate(true);
                            });
                        }
                        TrayAction::Quit => {
                            app.update(|cx| cx.quit());
                        }
                    }
                }
            })
            .detach();

            cx.activate(true);
        });
}

/// Open (or raise) the activity-log window inside an already-running GPUI app.
/// If a viewer window is already open it is raised+focused with the
/// compositor token instead of spawning a duplicate subscription.
fn open_log_viewer_window(
    socket_path: String,
    token: Option<String>,
    rule_clicks: Entity<RuleClickSink>,
    cx: &mut gpui::App,
) {
    let existing = cx
        .windows()
        .into_iter()
        .find(|w| w.downcast::<log_viewer::LogViewerRoot>().is_some());
    if let Some(window) = existing {
        let _ = window.update(cx, move |_, w, _| {
            w.activate_window();
            if let Some(tok) = token.as_deref() {
                w.activate_with_token(tok);
            }
        });
        return;
    }

    let (tx, rx) = std::sync::mpsc::channel::<control_api::PushNotification>();

    // Subscriber thread: forwards every daemon notification into `tx`. It
    // exits when the receiving half is dropped (window closed).
    if let Err(e) = std::thread::Builder::new()
        .name("log-viewer-subscribe".into())
        .spawn(move || {
            if let Err(e) = daemon::subscribe_to_notifications(&socket_path, tx) {
                eprintln!("log viewer: subscription error: {e}");
            }
        })
    {
        eprintln!("log viewer: failed to spawn subscriber: {e}");
        return;
    }

    let opened = cx.open_window(
        WindowOptions {
            titlebar: Some(gpui_component::TitleBar::title_bar_options()),
            window_decorations: Some(gpui::WindowDecorations::Client),
            window_min_size: Some(size(px(780.), px(400.))),
            window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds {
                origin: gpui::point(px(80.), px(80.)),
                size: size(px(900.), px(520.)),
            })),
            ..Default::default()
        },
        |window, cx| {
            window.set_app_id("netkeep-log-viewer");
            let view = cx.new(|cx| log_viewer::LogViewer::new(window, cx));

            // Pump notifications from the subscriber thread into the view.
            spawn_drain(rx, view.clone(), cx);

            // Rule clicks jump to the settings window filtered by rule id.
            cx.subscribe(&view, move |_view_entity, event, cx| {
                let state = rule_clicks.read(cx).settings_state.clone();
                match state {
                    Some(state) => open_or_raise_settings(&state, None, Some(event.0.clone()), cx),
                    None => {
                        let state =
                            cx.new(|_| SettingsState::new(daemon::resolve_socket_path(None)));
                        cx.update_entity(&rule_clicks, |s, _| {
                            s.settings_state = Some(state.clone())
                        });
                        open_or_raise_settings(&state, None, Some(event.0.clone()), cx);
                    }
                }
            })
            .detach();

            let root = cx.new(|cx| log_viewer::LogViewerRoot::new(view.clone(), window, cx));
            cx.new(|cx| Root::new(AnyView::from(root), window, cx))
        },
    );
    match opened {
        Ok(handle) => {
            let _ = handle.update(cx, |_, w, _| {
                w.activate_window();
                if let Some(tok) = token.as_deref() {
                    w.activate_with_token(tok);
                }
            });
        }
        Err(e) => {
            eprintln!("log viewer: failed to open window: {e}");
        }
    }
}

/// Pump notifications from the subscriber thread into the view until the
/// viewer entity is dropped (window closed). The blocking `recv` runs on a
/// dedicated OS thread; results are delivered to the main loop through GPUI's
/// own async channel — std::sync channels must never be polled from executor
/// futures, and `app.update` panics when called from a non-main thread.
fn spawn_drain(
    rx: std::sync::mpsc::Receiver<control_api::PushNotification>,
    view: Entity<log_viewer::LogViewer>,
    cx: &mut gpui::App,
) {
    let weak = view.downgrade();
    let (tx, rx_async) = async_channel::unbounded::<control_api::PushNotification>();
    // Forwarder: blocks only on this dedicated OS thread, never on an executor.
    std::thread::Builder::new()
        .name("log-viewer-drain".into())
        .spawn(move || {
            while let Ok(notif) = rx.recv() {
                if tx.try_send(notif).is_err() {
                    break; // receiver gone: window closed
                }
            }
        })
        .expect("spawn log-viewer drain thread");

    // Receiver lives on the main loop: wakes on each notification.
    cx.spawn(async move |app| {
        while let Ok(notif) = rx_async.recv().await {
            let weak = weak.clone();
            app.update(move |cx| {
                if let Some(view) = weak.upgrade() {
                    cx.update_entity(&view, move |s, cx| s.push_notification(notif, cx));
                }
            });
        }
    })
    .detach();
}

fn run_log_viewer(socket_path: &str) {
    diag_log(&format!("netkeep-gpui: log viewer, socket {socket_path}"));
    let socket_path = socket_path.to_string();

    gpui_platform::application()
        .with_assets(gpui_component_assets::Assets)
        .with_quit_mode(gpui::QuitMode::Explicit)
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
            Theme::change(ThemeMode::Dark, None, cx);
            fonts::apply_design_fonts(cx);

            let rule_clicks = cx.new(|_| RuleClickSink {
                settings_state: None,
            });
            open_log_viewer_window(socket_path.clone(), None, rule_clicks, cx);

            cx.activate(true);
        });
}

fn run_gui(pending_id: String) {
    let item = daemon::fetch_pending(&pending_id).unwrap_or_else(|e| {
        eprintln!("failed to fetch pending decision: {e}");
        std::process::exit(1);
    });
    let egresses = daemon::fetch_egresses();
    decision_dialog::show_decision_dialog(item, egresses);
}
