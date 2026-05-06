mod app;
mod colors;
mod components;
mod daemon;
mod polling;
mod state;

use gpui::{
    App, AppContext as _, Application, Entity, SharedString, WindowOptions, px, size,
};
use gpui_component::{Root, Theme, ThemeMode};

use app::DecisionApp;
use polling::start_polling;
use state::AppState;

fn main() {
    Application::new().run(|cx: &mut App| {
        gpui_component::init(cx);
        Theme::change(ThemeMode::Dark, None, cx);

        let state: Entity<AppState> = cx.new(|_| AppState::default());
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
