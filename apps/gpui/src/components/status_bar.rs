use gpui::{div, px, IntoElement, ParentElement, Styled};
use gpui_component::h_flex;

use crate::colors;

pub fn status_bar(pending_count: usize) -> gpui::AnyElement {
    h_flex()
        .w_full()
        .px(px(8.))
        .py(px(8.))
        .border_t_1()
        .border_color(colors::border())
        .bg(colors::surface_container_high())
        .justify_center()
        .child(
            div()
                .text_color(colors::muted())
                .text_size(px(10.))
                .opacity(0.7)
                .child(format!(
                    "LogiGuard \u{00B7} Fail-close active \u{00B7} Queue: {} pending",
                    pending_count
                )),
        )
        .into_any_element()
}
