mod app;
mod colors;
mod components;
mod daemon;
mod fonts;
mod monitor;
mod settings;
mod state;
#[cfg(target_os = "linux")]
mod tray;

use std::time::Duration;

use gpui::{px, size, App, AppContext as _, Entity, SharedString, WindowOptions};
use gpui_component::{Root, Theme, ThemeMode};

use app::DecisionApp;
use settings::{SettingsApp, SettingsState};
use state::{AppState, DestScope, ProcessScope};

#[cfg(target_os = "linux")]
use tray::{spawn_tray, TrayAction};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    diag_log(&format!("logiguard-gpui starting, args={:?}", args));

    if let Some(idx) = args.iter().position(|a| a == "--pending-id") {
        let pending_id = args.get(idx + 1).expect("--pending-id requires a value");
        run_gui(pending_id.to_string());
    } else if args.iter().any(|a| a == "--headless-monitor") {
        // Legacy: poll only (no tray). Useful for automated tests.
        let socket_path = std::env::var("LOGIGUARD_SOCKET_PATH")
            .unwrap_or_else(|_| daemon::SOCKET_PATH.to_string());
        let gui_command = std::env::var("LOGIGUARD_GUI_COMMAND").unwrap_or_else(|_| {
            std::env::current_exe()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_else(|_| "logiguard-gpui".to_string())
        });
        monitor::poll_decision_spawner(socket_path, gui_command);
    } else {
        run_tray_monitor();
    }
}

/// Append a diagnostic line to `/tmp/logiguard-tray.log`. The tray monitor is
/// typically launched via a desktop file whose stderr is not visible, so
/// `eprintln!` output would be lost. Check the file when debugging tray behavior.
fn diag_log(msg: &str) {
    use std::io::Write;
    let path = std::env::var("LOGIGUARD_TRAY_LOG")
        .unwrap_or_else(|_| "/tmp/logiguard-tray.log".to_string());
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{msg}");
    }
    eprintln!("{msg}");
}

fn run_tray_monitor() {
    let socket_path = std::env::var("LOGIGUARD_SOCKET_PATH")
        .unwrap_or_else(|_| daemon::SOCKET_PATH.to_string());
    let gui_command = std::env::var("LOGIGUARD_GUI_COMMAND").unwrap_or_else(|_| {
        std::env::current_exe()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_else(|_| "logiguard-gpui".to_string())
    });

    diag_log(&format!(
        "logiguard-gpui: ksni tray + pending monitor, socket {socket_path}"
    ));
    #[cfg(target_os = "linux")]
    diag_log(
        "logiguard-gpui: GNOME hides legacy tray icons unless the shell extension          \"AppIndicator and KStatusNotifierItem Support\" (or equivalent) is enabled.",
    );

    // Sync the tray icon with the current NFQUEUE state on startup.
    let nfqueue_enabled = daemon::get_nfqueue_status().map(|(e, _)| e).unwrap_or(false);
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
                            let sock = sock.clone();
                            diag_log(&format!(
                                "tray: Settings action, token={}",
                                match &token {
                                    Some(t) => format!("Some({} chars)", t.len()),
                                    None => "None".to_string(),
                                }
                            ));
                            app.update(|cx| {
                                let windows = cx.windows();
                                if windows.is_empty() {
                                    // No window yet (or closed): create it.
                                    let state: Entity<SettingsState> =
                                        cx.new(|_| SettingsState::new(sock));
                                    let _ = cx.open_window(
                                        WindowOptions {
                                            window_bounds: Some(gpui::WindowBounds::Windowed(
                                                gpui::Bounds {
                                                    origin: gpui::point(px(80.), px(40.)),
                                                    size: size(px(960.), px(720.)),
                                                },
                                            )),
                                            titlebar: Some(
                                                gpui_component::TitleBar::title_bar_options(),
                                            ),
                                            window_decorations: Some(
                                                gpui::WindowDecorations::Client,
                                            ),
                                            window_min_size: Some(size(px(640.), px(420.))),
                                            is_resizable: true,
                                            ..Default::default()
                                        },
                                        |window, cx| {
                                            window.set_app_id("logiguard");
                                            let view =
                                                cx.new(|cx| SettingsApp::new(state, window, cx));
                                            cx.new(|cx| Root::new(view, window, cx))
                                        },
                                    );
                                } else {
                                    // Already open: raise+focus. The compositor-minted
                                    // token (delivered via ProvideXdgActivationToken)
                                    // authoritatively raises the window. Without it
                                    // Mutter falls back to demand-attention.
                                    for window in windows {
                                        let t = token.clone();
                                        let _ = window.update(cx, move |_, w, _| {
                                            w.activate_window();
                                            if let Some(tok) = t.as_deref() {
                                                w.activate_with_token(tok);
                                            }
                                        });
                                    }
                                }
                                cx.activate(true);
                            });
                        }
                        TrayAction::Quit => {
                            let _ = app.update(|cx| cx.quit());
                        }
                    }
                }
            })
            .detach();

            cx.activate(true);
        });
}

fn run_gui(pending_id: String) {
    let item = daemon::fetch_pending(&pending_id).unwrap_or_else(|e| {
        eprintln!("failed to fetch pending decision: {e}");
        std::process::exit(1);
    });

    gpui_platform::application()
        .with_assets(gpui_component_assets::Assets)
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
            Theme::change(ThemeMode::Dark, None, cx);
            fonts::apply_design_fonts(cx);

            let mut egresses = daemon::fetch_egresses();
            // Sort: system default first, then available, then unavailable.
            egresses.sort_by(|a, b| match (a.is_system_default, b.is_system_default) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => match (a.is_available, b.is_available) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a.id.cmp(&b.id),
                },
            });
            let process_scope = if item.flow.process_name.is_some() {
                ProcessScope::Specific
            } else {
                ProcessScope::Specific // locked: shown as "unknown", cannot switch to All
            };
            let dest_scope = if item.flow.destination_domain.is_some() {
                DestScope::DomainExact
            } else {
                DestScope::IpCidr(4) // default: exact IP (/32)
            };

            // Estimate content height so the window fits its content:
            //   header          ~ 80  (py(16)×2 + content)
            //   flow_info       ~222  (outer py(16) + card py(16) + 5 grid rows × ~22 + 4 gaps × 12)
            //   action_footer   ~258  (pt+pb 28 + rule_scope ~96 + divider 1 + duration 30 + egress 30 + buttons 33 + gaps 40)
            //   status_bar      ~ 30  (py(8)×2 + text)
            //   ─────────────────────
            //   base (0 egress) ≈ 590
            // Add padding for borders, DPI variance, and text metrics.
            //
            // When process and domain are both unknown, `action_footer` shows a warning banner
            // above the rule scope (extra flex gap + padded multi-line text). Keep in sync with
            // `components::action_footer::rule_scope_section`.
            let has_device = item.flow.device_label.is_some();
            let device_extra: f32 = if has_device { 24. } else { 0. };
            let unknown_connection_warning =
                item.flow.process_name.is_none() && item.flow.destination_domain.is_none();
            let unknown_warning_extra: f32 = if unknown_connection_warning { 76. } else { 0. };
            let egress_rows = ((egresses.len().min(6) + 2) / 3) as f32; // ~3 chips per wrapped row
            let estimated_height = 600. + device_extra + egress_rows * 28. + unknown_warning_extra;

            // Cap at 90% of the primary display height.
            let screen_h = cx
                .primary_display()
                .map(|d| f32::from(d.bounds().size.height))
                .unwrap_or(1080.);
            let win_height = estimated_height.min(screen_h * 0.90);

            let state: Entity<AppState> = cx.new(|_| AppState {
                item,
                now_secs: daemon::unix_now(),
                make_permanent: false,
                pending_count: 0,
                egresses,
                selected_egress_index: 0,
                process_scope,
                dest_scope,
            });

            cx.open_window(
                WindowOptions {
                    window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds::centered(
                        None,
                        size(px(440.), px(win_height)),
                        cx,
                    ))),
                    titlebar: Some(gpui::TitlebarOptions {
                        title: Some(SharedString::from("LogiGuard - Connection Decision")),
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

