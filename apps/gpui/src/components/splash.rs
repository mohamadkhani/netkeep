use gpui::{FontWeight, IntoElement, ParentElement, Styled, div};
use gpui_component::v_flex;

use crate::colors;

fn splash_logo() -> gpui::AnyElement {
    v_flex()
        .items_center()
        .gap_3()
        .child(
            div()
                .text_color(colors::amber())
                .text_xl()
                .font_weight(FontWeight::BOLD)
                .child("LOGIGUARD"),
        )
        .into_any_element()
}

pub fn splash_connecting() -> gpui::AnyElement {
    v_flex()
        .size_full()
        .items_center()
        .justify_center()
        .gap_3()
        .bg(colors::bg())
        .child(splash_logo())
        .child(
            div()
                .text_color(colors::muted())
                .text_sm()
                .child("Connecting to daemon..."),
        )
        .into_any_element()
}

pub fn splash_empty() -> gpui::AnyElement {
    v_flex()
        .size_full()
        .items_center()
        .justify_center()
        .gap_3()
        .bg(colors::bg())
        .child(splash_logo())
        .child(
            div()
                .text_color(colors::muted())
                .text_sm()
                .child("No pending decisions"),
        )
        .into_any_element()
}
