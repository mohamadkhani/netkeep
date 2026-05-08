// Material Design 3 dark theme colors from the HTML design spec.

/// Parse a hex color string like "#22c55e" or "#6b7280" into an Hsla value.
/// Returns a fallback gray if parsing fails.
pub fn hex_to_hsla(hex: &str) -> gpui::Hsla {
    let hex = hex.trim_start_matches('#');
    let parsed = u32::from_str_radix(hex, 16).unwrap_or(0x6b7280);
    gpui::rgb(parsed).into()
}

pub fn bg() -> gpui::Hsla {
    gpui::rgb(0x081425).into() // background / surface-dim
}

pub fn surface() -> gpui::Hsla {
    gpui::rgb(0x111c2d).into() // surface-container-low
}

pub fn surface_container() -> gpui::Hsla {
    gpui::rgb(0x152031).into() // surface-container (modal bg)
}

pub fn surface_container_high() -> gpui::Hsla {
    gpui::rgb(0x1f2a3c).into() // surface-container-high (header/footer bg)
}

pub fn surface_container_highest() -> gpui::Hsla {
    gpui::rgb(0x2a3548).into() // surface-container-highest / surface-variant
}

pub fn surface_bright() -> gpui::Hsla {
    gpui::rgb(0x2f3a4c).into() // surface-bright
}

pub fn border() -> gpui::Hsla {
    gpui::rgb(0x424754).into() // outline-variant
}

pub fn outline() -> gpui::Hsla {
    gpui::rgb(0x8c909f).into() // outline
}

pub fn primary() -> gpui::Hsla {
    gpui::rgb(0xadc6ff).into() // primary
}

pub fn primary_container() -> gpui::Hsla {
    gpui::rgb(0x4d8eff).into() // primary-container
}

pub fn on_primary() -> gpui::Hsla {
    gpui::rgb(0x002e6a).into() // on-primary (text on primary)
}

pub fn text() -> gpui::Hsla {
    gpui::rgb(0xd8e3fb).into() // on-surface
}

pub fn muted() -> gpui::Hsla {
    gpui::rgb(0xc2c6d6).into() // on-surface-variant
}

pub fn error() -> gpui::Hsla {
    gpui::rgb(0xffb4ab).into() // error
}

pub fn green() -> gpui::Hsla {
    gpui::rgb(0x22c55e).into() // allow green (#22c55e)
}

pub fn green_dim() -> gpui::Hsla {
    gpui::hsla(142. / 360., 0.71, 0.45, 0.50) // green with 50% alpha for border
}

pub fn teal() -> gpui::Hsla {
    gpui::rgb(0x14b8a6).into() // protocol teal
}

pub fn teal_dim() -> gpui::Hsla {
    gpui::hsla(174. / 360., 0.84, 0.40, 0.10) // teal with 10% alpha bg
}

pub fn teal_border() -> gpui::Hsla {
    gpui::hsla(174. / 360., 0.84, 0.40, 0.30) // teal with 30% alpha border
}

pub fn orange() -> gpui::Hsla {
    gpui::rgb(0xf97316).into() // fire icon orange
}
