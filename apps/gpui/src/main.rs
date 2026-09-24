mod app;
mod colors;
mod components;
mod daemon;
mod decision_dialog;
mod fonts;
mod monitor;
mod settings;
mod state;
#[cfg(target_os = "linux")]
mod tray;

use std::time::Duration;

use gpui::{px, size, App, AppContext as _, Entity, WindowOptions};
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
    } else if args.iter().any(|a| a == "--headless-monitor") {
        // Legacy: poll only (no tray). Useful for automated tests.
        let socket_path = std::env::var("NETKEEP_SOCKET_PATH")
            .unwrap_or_else(|_| daemon::SOCKET_PATH.to_string());
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

fn run_tray_monitor() {
    let socket_path =
        std::env::var("NETKEEP_SOCKET_PATH").unwrap_or_else(|_| daemon::SOCKET_PATH.to_string());
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
                                            window.set_app_id("netkeep");
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
                            app.update(|cx| cx.quit());
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
    let egresses = daemon::fetch_egresses();
    decision_dialog::show_decision_dialog(item, egresses);
}
