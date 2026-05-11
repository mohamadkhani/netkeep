//! Design-system primitives.
//!
//! Every interactive or styled atom used across the decision dialog and settings
//! panels lives here so that visual consistency is enforced in one place.

use gpui::{
    AnyElement, FontWeight, InteractiveElement, IntoElement, ParentElement,
    StatefulInteractiveElement, Styled, WeakEntity, div, px,
    prelude::FluentBuilder as _,
};
use gpui_component::h_flex;

use core_types::DestinationMatcher;

use crate::colors;
use crate::state::{AppState, DestScope};

// ---------------------------------------------------------------------------
// Badge — read-only colored label chip
// ---------------------------------------------------------------------------

/// A compact pill-shaped label chip with a given text color.
/// Used for Action, Protocol, Direction, and similar read-only tags.
pub fn badge(text: impl Into<gpui::SharedString>, color: gpui::Hsla) -> AnyElement {
    div()
        .px(px(8.))
        .py(px(2.))
        .rounded(px(4.))
        .border_1()
        .border_color(gpui::Hsla { a: 0.35, ..color })
        .bg(gpui::Hsla { a: 0.10, ..color })
        .child(
            div()
                .text_size(px(11.))
                .font_weight(FontWeight::BOLD)
                .text_color(color)
                .child(text.into()),
        )
        .into_any_element()
}

// ---------------------------------------------------------------------------
// Chip — interactive toggle button
// ---------------------------------------------------------------------------

/// An interactive toggle chip used in scope selectors.
/// `selected` drives the active/inactive visual state.
pub fn chip<F>(
    id: impl Into<gpui::ElementId>,
    label: impl Into<gpui::SharedString>,
    selected: bool,
    on_click: F,
) -> AnyElement
where
    F: Fn(&gpui::ClickEvent, &mut gpui::Window, &mut gpui::App) + 'static,
{
    div()
        .id(id.into())
        .px(px(10.))
        .py(px(3.))
        .rounded(px(4.))
        .cursor_pointer()
        .border_1()
        .when(selected, |el| {
            el.bg(colors::primary()).border_color(colors::primary())
        })
        .when(!selected, |el| {
            el.bg(gpui::transparent_black()).border_color(colors::border())
        })
        .on_click(on_click)
        .child(
            div()
                .text_size(px(11.))
                .font_weight(FontWeight::BOLD)
                .text_color(if selected { colors::on_primary() } else { colors::muted() })
                .child(label.into()),
        )
        .into_any_element()
}

// ---------------------------------------------------------------------------
// dest_text — human-readable destination string
// ---------------------------------------------------------------------------

/// Returns a plain-language string describing a `DestinationMatcher`.
/// Used in rule summary lines, table cells, and tooltips.
pub fn dest_text(dest: &DestinationMatcher) -> String {
    match dest {
        DestinationMatcher::Any => "any destination".to_string(),
        DestinationMatcher::IpExact(ip) => ip.clone(),
        DestinationMatcher::Cidr(cidr) => cidr.clone(),
        DestinationMatcher::DomainExact(d) => d.clone(),
        DestinationMatcher::DomainWildcard(apex) => format!("*.{apex}"),
    }
}

/// Returns the short type tag for a `DestinationMatcher` (used in table badges).
pub fn dest_kind_label(dest: &DestinationMatcher) -> &'static str {
    match dest {
        DestinationMatcher::Any => "ANY",
        DestinationMatcher::IpExact(_) => "IP",
        DestinationMatcher::Cidr(_) => "CIDR",
        DestinationMatcher::DomainExact(_) => "DOMAIN",
        DestinationMatcher::DomainWildcard(_) => "WILDCARD",
    }
}

// ---------------------------------------------------------------------------
// CIDR octet picker
// ---------------------------------------------------------------------------

/// Renders an interactive IP octet picker for CIDR scope selection.
///
/// `ip` is the base IP address (e.g. `"142.250.80.100"`).
/// `active_octets` is the number of active (non-masked) octets from the left (1..=4).
/// Clicking an active octet masks it and all after; clicking a masked octet activates
/// it and all before. The `/prefix` badge updates live.
pub fn cidr_picker(
    ip: &str,
    active_octets: u8,
    state_weak: WeakEntity<AppState>,
) -> AnyElement {
    let parts: Vec<&str> = ip.splitn(4, '.').collect();
    let o: Vec<String> = (0..4)
        .map(|i| parts.get(i).copied().unwrap_or("0").to_string())
        .collect();
    let prefix = active_octets * 8;
    let cidr_label = format!("/{prefix}");

    h_flex()
        .items_center()
        .gap(px(2.))
        .child(octet_chip(1, &o[0], active_octets, state_weak.clone()))
        .child(octet_sep())
        .child(octet_chip(2, &o[1], active_octets, state_weak.clone()))
        .child(octet_sep())
        .child(octet_chip(3, &o[2], active_octets, state_weak.clone()))
        .child(octet_sep())
        .child(octet_chip(4, &o[3], active_octets, state_weak))
        .child(
            div()
                .w(px(32.))
                .text_size(px(11.))
                .text_color(colors::muted())
                .ml(px(3.))
                .child(cidr_label),
        )
        .into_any_element()
}

fn octet_chip(
    index: u8,
    value: &str,
    active_octets: u8,
    state_weak: WeakEntity<AppState>,
) -> AnyElement {
    let is_active = index <= active_octets;
    let display = gpui::SharedString::from(if is_active {
        value.to_string()
    } else {
        "0".to_string()
    });
    let id = gpui::ElementId::Name(format!("octet-{index}").into());

    div()
        .id(id)
        .w(px(38.))
        .flex()
        .items_center()
        .justify_center()
        .px(px(6.))
        .py(px(2.))
        .rounded(px(4.))
        .border_1()
        .cursor_pointer()
        .when(is_active, |el| {
            el.border_color(gpui::hsla(0.61, 1., 0.84, 0.40))
                .bg(gpui::hsla(0.61, 1., 0.84, 0.10))
        })
        .when(!is_active, |el| {
            el.border_color(colors::border()).bg(gpui::transparent_black())
        })
        .child(
            div()
                .text_size(px(12.))
                .text_color(if is_active {
                    gpui::hsla(0.61, 1., 0.84, 1.)
                } else {
                    colors::border()
                })
                .when(!is_active, |el| el.line_through())
                .child(display),
        )
        .on_click(move |_, _, cx| {
            if let Some(s) = state_weak.upgrade() {
                s.update(cx, |st, cx| {
                    let current = if let DestScope::IpCidr(n) = st.dest_scope { n } else { 4 };
                    let new_active = if index <= current {
                        (index - 1).max(1)
                    } else {
                        index
                    };
                    st.dest_scope = DestScope::IpCidr(new_active);
                    cx.notify();
                });
            }
        })
        .into_any_element()
}

fn octet_sep() -> AnyElement {
    div()
        .text_size(px(12.))
        .text_color(colors::border())
        .child(".")
        .into_any_element()
}

// ---------------------------------------------------------------------------
// Label row — fixed-width label + right-side content
// ---------------------------------------------------------------------------

/// A row with a 72px muted label on the left and arbitrary content on the right.
/// Standard layout unit for form-like sections (rule scope, flow info rows, etc.).
pub fn label_row(
    label: impl Into<gpui::SharedString>,
    content: AnyElement,
) -> AnyElement {
    h_flex()
        .w_full()
        .items_center()
        .gap(px(8.))
        .child(
            div()
                .text_size(px(11.))
                .text_color(colors::muted())
                .w(px(72.))
                .child(label.into()),
        )
        .child(content)
        .into_any_element()
}
