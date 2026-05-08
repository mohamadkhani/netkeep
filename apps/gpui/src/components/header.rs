use gpui::{FontWeight, IntoElement, ParentElement, SharedString, Styled, div, px};
use gpui_component::{h_flex, v_flex};

use crate::colors;

pub fn decision_header(remaining_secs: u64) -> gpui::AnyElement {
    let ui_font: SharedString = "Inter Variable".into();

    v_flex()
        .w_full()
        .child(
            h_flex()
                .w_full()
                .px(px(16.))
                .py(px(16.))
                .items_center()
                .justify_between()
                .bg(colors::surface_container_high())
                .border_b_1()
                .border_color(colors::border())
                .child(
                    // Left: security icon + title
                    h_flex()
                        .gap_2()
                        .items_center()
                        .child(
                            div()
                                .text_color(colors::primary())
                                .text_sm()
                                .child("\u{1F6E1}"), // 🛡️ security shield
                        )
                        .child(
                            div()
                                .font_family(ui_font.clone())
                                .text_color(colors::primary())
                                .font_weight(FontWeight::BOLD)
                                .text_size(px(11.))
                                .child("CONNECTION INTERCEPTED"),
                        ),
                )
                .child(
                    // Right: circular countdown ring + auto-deny label
                    v_flex()
                        .items_center()
                        .child(
                            // Countdown number
                            div()
                                .size(px(32.))
                                .rounded_full()
                                .border_2()
                                .border_color(colors::green())
                                .flex()
                                .items_center()
                                .justify_center()
                                .child(
                                    div()
                                        .font_family(ui_font.clone())
                                        .text_color(colors::text())
                                        .font_weight(FontWeight::BOLD)
                                        .text_size(px(11.))
                                        .child(format!("{remaining_secs}s")),
                                ),
                        )
                        .child(
                            // AUTO-DENY label
                            div()
                                .font_family(ui_font)
                                .text_color(colors::error())
                                .font_weight(FontWeight::BOLD)
                                .text_size(px(9.))
                                .mt(px(4.))
                                .child("AUTO-DENY"),
                        ),
                ),
        )
        .into_any_element()
}
