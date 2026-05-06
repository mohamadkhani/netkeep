mod app;
mod colors;
mod components;
mod daemon;
mod monitor;
mod state;

use gpui::{
    App, AppContext as _, Application, Entity, SharedString, WindowOptions, px, size,
};
use gpui_component::{Root, Theme, ThemeMode};

use app::DecisionApp;
use state::AppState;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if let Some(idx) = args.iter().position(|a| a == "--pending-id") {
        // GUI mode: show a single decision and exit
        let pending_id = args.get(idx + 1).expect("--pending-id requires a value");
        run_gui(pending_id.to_string());
    } else {
        // Monitor mode: poll daemon, spawn GUI on new decisions
        monitor::run();
    }
}

fn run_gui(pending_id: String) {
    let item = daemon::fetch_pending(&pending_id)
        .unwrap_or_else(|e| {
            eprintln!("failed to fetch pending decision: {e}");
            std::process::exit(1);
        });

    Application::new().run(move |cx: &mut App| {
        gpui_component::init(cx);
        Theme::change(ThemeMode::Dark, None, cx);

        let state: Entity<AppState> = cx.new(|_| AppState {
            item,
            now_secs: daemon::unix_now(),
            make_permanent: false,
            resolved: false,
        });

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
