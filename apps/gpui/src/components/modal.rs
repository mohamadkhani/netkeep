//! Reusable modal (dialog) components matching the LogiGuard design system.

use gpui::{
    AnyElement, Div, ElementId, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, Stateful, StatefulInteractiveElement, Styled, Window, div, px,
};
use gpui_component::{WindowExt as _, h_flex};

use crate::colors;

// ── Modal Header ───────────────────────────────────────────────────────────
//
// Full-width title bar: icon (primary colour) + UPPERCASE label-caps title on the
// left, ✕ close button on the right. Pass as `.title()` on a `Dialog` that has
// `.p(px(0.))` so the header becomes full-bleed.

pub fn modal_header(icon: &str, title: &str) -> impl IntoElement {
    h_flex()
        .w_full()
        .items_center()
        .justify_between()
        .bg(colors::surface_container_high())
        .border_b_1()
        .border_color(colors::border())
        .px(px(16.))
        .py(px(10.))
        .child(
            h_flex()
                .gap(px(8.))
                .items_center()
                .child(
                    div()
                        .text_size(px(14.))
                        .text_color(colors::primary())
                        .child(icon.to_string()),
                )
                .child(
                    div()
                        .font_weight(FontWeight::BOLD)
                        .text_size(px(11.))
                        .text_color(colors::text())
                        .child(title.to_string()),
                ),
        )
        .child(
            div()
                .id(ElementId::Name("modal-close-x".into()))
                .text_size(px(13.))
                .text_color(colors::muted())
                .p(px(5.))
                .rounded(px(4.))
                .cursor_pointer()
                .on_click(|_: &gpui::ClickEvent, window: &mut Window, cx: &mut gpui::App| {
                    window.close_dialog(cx);
                })
                .child("✕"),
        )
}

// ── Modal Footer ───────────────────────────────────────────────────────────
//
// Styled footer bar with border-top separator and surface-container-high
// background. Accepts already-rendered Cancel and OK `AnyElement`s from the
// Dialog's RenderButtonFn pair.
//
// Usage inside `dialog.footer(...)`:
//   dialog.footer(|ok, cancel, w, cx| {
//       vec![modal_footer(cancel(w, cx), ok(w, cx))]
//   })

#[allow(dead_code)]
pub fn modal_footer(cancel: AnyElement, ok: AnyElement) -> AnyElement {
    h_flex()
        .justify_end()
        .gap(px(8.))
        .w_full()
        .border_t_1()
        .border_color(colors::border())
        .bg(colors::surface_container_high())
        .px(px(16.))
        .py(px(10.))
        .child(cancel)
        .child(ok)
        .into_any_element()
}

// ── Form Field Label ───────────────────────────────────────────────────────

pub fn field_label(text: &str) -> AnyElement {
    div()
        .text_size(px(10.))
        .font_weight(FontWeight::BOLD)
        .text_color(colors::muted())
        .child(text.to_string())
        .into_any_element()
}

// ── Table Badge ────────────────────────────────────────────────────────────
//
// Inline bordered badge used for Status, Type, and Protocol columns.

pub fn table_badge(label: &str, color: Hsla) -> AnyElement {
    div()
        .flex()
        .items_center()
        .child(
            div()
                .text_size(px(10.))
                .text_color(color)
                .px(px(6.))
                .py(px(2.))
                .rounded(px(3.))
                .border_1()
                .border_color(color)
                .bg(colors::bg())
                .child(label.to_string()),
        )
        .into_any_element()
}

// ── Table Action Button ────────────────────────────────────────────────────
//
// Small outline button for table row actions (Edit, Delete, Enable, Disable).
// The border colour defaults to the text colour; chain `.border_color(other)`
// to override (e.g. for toggle buttons where the two colours differ).
// Chain `.on_click(...)` to attach the action.

pub fn action_btn(id: impl Into<SharedString>, label: &str, color: Hsla) -> Stateful<Div> {
    div()
        .id(ElementId::Name(id.into()))
        .text_size(px(10.))
        .text_color(color)
        .cursor_pointer()
        .px(px(6.))
        .py(px(2.))
        .rounded(px(3.))
        .border_1()
        .border_color(color)
        .child(label.to_string())
}

// ── Protocol Selector Button ───────────────────────────────────────────────
//
// Used in proxy form dialog for SOCKS5 / HTTP / SS selection.

pub fn proto_btn(
    label: &str,
    text_color: Hsla,
    border_color: Hsla,
    on_click: impl Fn(&gpui::ClickEvent, &mut gpui::Window, &mut gpui::App) + 'static,
) -> AnyElement {
    div()
        .id(ElementId::Name(
            format!("proto-btn-{}", label.to_lowercase()).into(),
        ))
        .flex()
        .flex_1()
        .items_center()
        .justify_center()
        .py(px(6.))
        .rounded(px(4.))
        .border_1()
        .border_color(border_color)
        .text_color(text_color)
        .text_size(px(10.))
        .font_weight(FontWeight::BOLD)
        .cursor_pointer()
        .on_click(on_click)
        .child(label.to_string())
        .into_any_element()
}
