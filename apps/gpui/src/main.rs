mod app;
mod colors;
mod components;
mod daemon;
mod management;
mod monitor;
mod state;

use std::time::Duration;

use gpui::{
    App, AppContext as _, Application, Entity, SharedString, WindowOptions, px, size,
};
use gpui_component::{Root, Theme, ThemeMode};
#[cfg(target_os = "linux")]
use gtk::prelude::WidgetExt as _;
#[cfg(target_os = "linux")]
use tray_icon::menu::ContextMenu as _;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, MenuId};
use tray_icon::{Icon, TrayIconBuilder};

use app::DecisionApp;
use management::{ManagementApp, ManagementState};
use state::AppState;

fn tray_pixel_icon() -> Icon {
    // StatusNotifier / libappindicator often scales tiny flat icons to nothing; use 64×64 with contrast.
    const S: u32 = 64;
    let mut rgba = vec![0u8; (S * S * 4) as usize];
    let cx = S as f32 / 2.0;
    let cy = S as f32 / 2.0;
    let r = S as f32 * 0.38;
    for y in 0..S {
        for x in 0..S {
            let i = ((y * S + x) * 4) as usize;
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            let inside = dx * dx + dy * dy <= r * r;
            if inside {
                rgba[i] = 0x14;
                rgba[i + 1] = 0xb8;
                rgba[i + 2] = 0xa6;
                rgba[i + 3] = 0xff;
            } else {
                rgba[i] = 0x21;
                rgba[i + 1] = 0x31;
                rgba[i + 2] = 0x42;
                rgba[i + 3] = 0xff;
            }
        }
    }
    Icon::from_rgba(rgba, S, S).expect("tray rgba icon")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

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

fn run_tray_monitor() {
    let socket_path = std::env::var("LOGIGUARD_SOCKET_PATH")
        .unwrap_or_else(|_| daemon::SOCKET_PATH.to_string());
    let gui_command = std::env::var("LOGIGUARD_GUI_COMMAND").unwrap_or_else(|_| {
        std::env::current_exe()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_else(|_| "logiguard-gpui".to_string())
    });

    eprintln!("logiguard-gpui: tray + pending monitor, socket {socket_path}");
    #[cfg(target_os = "linux")]
    {
        eprintln!(
            "logiguard-gpui: GNOME hides legacy tray icons unless the shell extension \
             \"AppIndicator and KStatusNotifierItem Support\" (or equivalent) is enabled."
        );
    }

    #[cfg(target_os = "linux")]
    gtk::init().expect("failed to init GTK (required for system tray on Linux)");

    Application::new().run(move |cx: &mut App| {
        gpui_component::init(cx);
        Theme::change(ThemeMode::Dark, None, cx);

        let sp = socket_path.clone();
        let gc = gui_command.clone();
        std::thread::spawn(move || monitor::poll_decision_spawner(sp, gc));

        // Build menu before the tray so GTK-backed `muda` sees items on the first `gtk_context_menu()`
        // build (see muda gtk/mod.rs: menu children are only populated once).
        let menu = Menu::new();
        menu
            .append(&MenuItem::with_id(
                MenuId::new("logiguard-manage"),
                "Rules and egresses…",
                true,
                None,
            ))
            .expect("menu manage item");
        menu
            .append(&MenuItem::with_id(
                MenuId::new("logiguard-quit"),
                "Quit",
                true,
                None,
            ))
            .expect("menu quit item");

        #[cfg(target_os = "linux")]
        {
            let gtk_menu = menu.gtk_context_menu();
            gtk_menu.show_all();
        }

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("LogiGuard")
            .with_title("LogiGuard")
            .with_icon(tray_pixel_icon())
            .build()
            .expect("system tray");

        // `Application::run`'s callback is `FnOnce`: it runs once and returns. If we drop
        // `TrayIcon` here, its `Drop` tears down libappindicator (Passive + temp PNG), which
        // yields an empty tray slot and a blank menu. Keep the indicator for process lifetime.
        std::mem::forget(tray_icon);

        #[cfg(target_os = "linux")]
        gtk_drain_events();

        let sock_mgmt = socket_path.clone();
        cx.spawn(async move |app| {
            let manage_id = MenuId::new("logiguard-manage");
            let quit_id = MenuId::new("logiguard-quit");
            loop {
                #[cfg(target_os = "linux")]
                gtk_drain_events();

                app.background_executor()
                    .timer(Duration::from_millis(50))
                    .await;
                while let Ok(event) = MenuEvent::receiver().try_recv() {
                    if event.id == manage_id {
                        let sock = sock_mgmt.clone();
                        let _ = app.open_window(
                            WindowOptions {
                                window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds {
                                    origin: gpui::point(px(120.), px(80.)),
                                    size: size(px(720.), px(560.)),
                                })),
                                titlebar: Some(gpui::TitlebarOptions {
                                    title: Some(SharedString::from(
                                        "LogiGuard - Rules && egresses",
                                    )),
                                    appears_transparent: false,
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                            move |window, cx| {
                                let state =
                                    cx.new(|_| ManagementState::new(sock.clone()));
                                let view =
                                    cx.new(|cx| ManagementApp::new(state.clone(), cx));
                                cx.new(|cx| Root::new(view, window, cx))
                            },
                        );
                    } else if event.id == quit_id {
                        let _ = app.update(|cx| cx.quit());
                    }
                }
            }
        })
        .detach();

        cx.activate(true);
    });
}

/// Linux tray uses GTK/AppIndicator; GPUI does not run `gtk_main`, so we must drain the GTK queue
/// or the indicator never updates and may not appear in the panel.
#[cfg(target_os = "linux")]
fn gtk_drain_events() {
    while gtk::events_pending() {
        gtk::main_iteration_do(false);
    }
}

fn run_gui(pending_id: String) {
    let item = daemon::fetch_pending(&pending_id).unwrap_or_else(|e| {
        eprintln!("failed to fetch pending decision: {e}");
        std::process::exit(1);
    });

    Application::new().run(move |cx: &mut App| {
        gpui_component::init(cx);
        Theme::change(ThemeMode::Dark, None, cx);

        let egresses = daemon::detect_egresses();
        let state: Entity<AppState> = cx.new(|_| AppState {
            item,
            now_secs: daemon::unix_now(),
            make_permanent: false,
            resolved: false,
            pending_count: 0,
            egresses,
            selected_egress_index: 0,
        });

        cx.open_window(
            WindowOptions {
                window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds::centered(
                    None,
                    size(px(420.), px(488.)),
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
