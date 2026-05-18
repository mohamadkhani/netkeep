//! Typography aligned with `design/decision_dialog_window.html` (tailwind font tokens).

use std::borrow::Cow;

use gpui::{px, App};
use gpui_component::Theme;

// Embed the design-matched font files at compile time so they work regardless
// of what is installed on the host system.
static INTER: &[u8] = include_bytes!("../fonts/Inter.ttf");
static INTER_ITALIC: &[u8] = include_bytes!("../fonts/Inter-Italic.ttf");
static SPACE_GROTESK: &[u8] = include_bytes!("../fonts/SpaceGrotesk.ttf");

/// Register the bundled Inter + Space Grotesk fonts with GPUI's text system.
/// Call once at startup, **before** opening any window.
pub fn register_fonts(cx: &App) {
    let ts = cx.text_system();
    if let Err(e) = ts.add_fonts(vec![
        Cow::Borrowed(INTER),
        Cow::Borrowed(INTER_ITALIC),
        Cow::Borrowed(SPACE_GROTESK),
    ]) {
        eprintln!("logiguard-gpui: failed to register bundled fonts: {e}");
    }
}

/// Sets [`Theme`] font families and base size to match the LogiGuard HTML mockups:
/// - UI: Inter Variable (variable-weight TTF, family name "Inter Variable")
/// - Data / technical: Space Grotesk (family name "Space Grotesk Light")
/// - Base size: 14px (`body-md`)
pub fn apply_design_fonts(cx: &mut App) {
    register_fonts(cx);

    let theme = Theme::global_mut(cx);
    theme.font_family = "Inter Variable".into();
    theme.mono_font_family = "Space Grotesk Light".into();
    theme.font_size = px(14.);
}
