use gpui::{FontWeight, IntoElement, ParentElement, Styled, div};
use gpui_component::h_flex;

use crate::colors;

pub fn decision_header(remaining_secs: u64) -> gpui::AnyElement {
    h_flex()
        .w_full()
        .items_center()
        .justify_between()
        .px_4()
        .py_3()
        .bg(colors::amber_dim())
        .border_b_1()
        .border_color(colors::amber())
        .child(
            h_flex()
                .gap_2()
                .items_center()
                .child(
                    div()
                        .text_color(colors::amber())
                        .font_weight(FontWeight::BOLD)
                        .text_sm()
                        .child("\u{26A0}  CONNECTION INTERCEPTED"),
                ),
        )
        .child(
            div()
                .text_color(colors::amber())
                .font_weight(FontWeight::BOLD)
                .text_lg()
                .child(format!("{remaining_secs}s")),
        )
        .into_any_element()
}
