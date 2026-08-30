//! Shared launcher for the connection decision dialog window.
//!
//! Used by both the daemon-driven binary (`--pending-id`) and the
//! `decision_modal` example; declaring it as a module keeps the window
//! bootstrap code in exactly one place.

use gpui::{
    px, size, App, AppContext as _, Entity, Focusable as _, SharedString, Styled, WindowKind,
    WindowOptions,
};
use gpui_component::{Root, Theme, ThemeMode};

use crate::app::DecisionApp;
use crate::daemon;
use crate::fonts;
use crate::state::{AppState, DestScope, ProcessScope};

use core_types::{Egress, PendingDecision};

/// Sort egresses, derive scopes, and open the dialog: a maximized,
/// transparent overlay window with a fixed-width card centered on both
/// axes. The compositor owns the window size (see the `Maximized` note
/// below); the card itself is sized in `DecisionApp::render`.
pub fn show_decision_dialog(item: PendingDecision, mut egresses: Vec<Egress>) {
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

    gpui_platform::application()
        .with_assets(gpui_component_assets::Assets)
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
            Theme::change(ThemeMode::Dark, None, cx);
            fonts::apply_design_fonts(cx);

            let state: Entity<AppState> = cx.new(|_| AppState {
                item,
                now_secs: daemon::unix_now(),
                make_permanent: false,
                pending_count: 0,
                egresses,
                selected_egress_index: 0,
                process_scope,
                dest_scope,
                closing: false,
            });

            // Mutter maps the window from its restore geometry before applying
            // the maximized state; a small restore rect at the origin flashes
            // in the top-left corner for a few frames. Give the full display
            // bounds so the pre-maximize frame already covers the screen.
            let restore_bounds = cx
                .primary_display()
                .map(|d| d.bounds())
                .unwrap_or(gpui::Bounds {
                    origin: gpui::point(px(0.), px(0.)),
                    size: size(px(1920.), px(1080.)),
                });

            cx.open_window(
                WindowOptions {
                    // Maximize instead of hardcoding the display height: the
                    // compositor then owns the size in true logical pixels.
                    // A hardcoded `display.bounds().height` breaks under
                    // fractional scaling (physical != logical) and produces
                    // an oversized, bottom-clipped window.
                    window_bounds: Some(gpui::WindowBounds::Maximized(restore_bounds)),
                    titlebar: Some(gpui::TitlebarOptions {
                        title: Some(SharedString::from("LogiGuard - Connection Decision")),
                        appears_transparent: false,
                        ..Default::default()
                    }),
                    is_resizable: false,
                    kind: WindowKind::PopUp,
                    window_background: gpui::WindowBackgroundAppearance::Transparent,
                    ..Default::default()
                },
                |window, cx| {
                    let view = cx.new(|cx| DecisionApp::new(state, cx));
                    // Focus the scrim so Esc dispatches to its key handler.
                    window.focus(&view.read(cx).focus_handle(cx), cx);
                    let root = cx.new(|cx| Root::new(view, window, cx));
                    // `Root` paints the theme background by default; clear it
                    // so only the dialog card is visible over the desktop.
                    root.update(cx, |root, _| {
                        root.style().background = Some(gpui::transparent_black().into());
                    });
                    root
                },
            )
            .expect("failed to open window");

            cx.activate(true);
        });
}
