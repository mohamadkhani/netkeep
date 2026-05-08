use core_types::FlowDirection;
use gpui::{FontWeight, IntoElement, ParentElement, SharedString, Styled, div, px};
use gpui_component::{h_flex, v_flex};

use crate::colors;

pub fn flow_info_section(
    process_name: &str,
    protocol: &str,
    port: u16,
    domain: &Option<String>,
    ip: &str,
    direction: FlowDirection,
    device_label: &Option<String>,
    mono_font_family: SharedString,
) -> gpui::AnyElement {
    let destination = domain
        .as_deref()
        .unwrap_or("(unknown)");

    let direction_str = match direction {
        FlowDirection::Outbound => "OUTBOUND",
        FlowDirection::Inbound => "INBOUND",
    };

    let ui_font: SharedString = "Inter Variable".into();

    let mut card = v_flex()
        .bg(colors::surface())
        .border_1()
        .border_color(colors::border())
        .rounded(px(4.))
        .px(px(16.))
        .py(px(16.))
        .gap(px(12.))
        // Process row
        .child(grid_row(
            label_element("PROCESS", ui_font.clone()),
            process_value(process_name, ui_font.clone()),
        ))
        // Destination row
        .child(grid_row(
            label_element("DESTINATION", ui_font.clone()),
            destination_value(destination, mono_font_family.clone()),
        ))
        // IP Address row
        .child(grid_row(
            label_element("IP ADDRESS", ui_font.clone()),
            ip_value(ip, mono_font_family.clone()),
        ))
        // Protocol row
        .child(grid_row(
            label_element("PROTOCOL", ui_font.clone()),
            protocol_value(protocol, port, mono_font_family.clone()),
        ))
        // Direction row
        .child(grid_row(
            label_element("DIRECTION", ui_font.clone()),
            direction_value(direction_str, ui_font.clone()),
        ));

    if let Some(label) = device_label {
        card = card.child(grid_row(
            label_element("DEVICE", ui_font.clone()),
            device_value(label, mono_font_family.clone()),
        ));
    }

    v_flex()
        .px(px(16.))
        .py(px(16.))
        .child(card)
        .into_any_element()
}

fn grid_row(label: gpui::AnyElement, value: gpui::AnyElement) -> gpui::AnyElement {
    h_flex()
        .w_full()
        .child(
            div()
                .w(px(120.))
                .child(label),
        )
        .child(
            div()
                .flex_1()
                .child(value),
        )
        .into_any_element()
}

fn label_element(label: &str, ui_font: SharedString) -> gpui::AnyElement {
    div()
        .font_family(ui_font)
        .text_color(colors::muted())
        .font_weight(FontWeight::BOLD)
        .text_size(px(11.))
        .child(SharedString::from(label.to_string()))
        .into_any_element()
}

fn process_value(process_name: &str, ui_font: SharedString) -> gpui::AnyElement {
    h_flex()
        .gap_2()
        .items_center()
        .child(
            div()
                .text_color(colors::orange())
                .text_size(px(16.))
                .child("\u{1F525}"), // 🔥 fire
        )
        .child(
            div()
                .font_family(ui_font)
                .text_color(colors::text())
                .text_size(px(13.))
                .child(SharedString::from(process_name.to_string())),
        )
        .into_any_element()
}

fn destination_value(destination: &str, mono_font_family: SharedString) -> gpui::AnyElement {
    div()
        .font_family(mono_font_family)
        .text_color(colors::primary())
        .text_size(px(13.))
        .child(SharedString::from(destination.to_string()))
        .into_any_element()
}

fn ip_value(ip: &str, mono_font_family: SharedString) -> gpui::AnyElement {
    div()
        .font_family(mono_font_family)
        .bg(colors::surface_container_highest())
        .px(px(8.))
        .py(px(2.))
        .rounded(px(4.))
        .border_1()
        .border_color(colors::border())
        .text_color(colors::text())
        .text_size(px(12.))
        .child(SharedString::from(ip.to_string()))
        .into_any_element()
}

fn protocol_value(protocol: &str, port: u16, mono_font_family: SharedString) -> gpui::AnyElement {
    div()
        .font_family(mono_font_family)
        .bg(colors::teal_dim())
        .px(px(8.))
        .py(px(2.))
        .rounded(px(4.))
        .border_1()
        .border_color(colors::teal_border())
        .text_color(colors::teal())
        .text_size(px(12.))
        .child(format!("{protocol} : {port}"))
        .into_any_element()
}

fn direction_value(direction: &str, ui_font: SharedString) -> gpui::AnyElement {
    div()
        .font_family(ui_font)
        .bg(colors::surface_container_highest())
        .px(px(8.))
        .py(px(2.))
        .rounded(px(4.))
        .border_1()
        .border_color(colors::border())
        .text_color(colors::muted())
        .font_weight(FontWeight::BOLD)
        .text_size(px(11.))
        .child(SharedString::from(direction.to_string()))
        .into_any_element()
}

fn device_value(label: &str, mono_font_family: SharedString) -> gpui::AnyElement {
    h_flex()
        .gap_2()
        .items_center()
        .child(
            div()
                .text_color(colors::teal())
                .text_size(px(14.))
                .child("\u{1F5A7}"), // 🖧 network
        )
        .child(
            div()
                .font_family(mono_font_family)
                .bg(colors::teal_dim())
                .px(px(8.))
                .py(px(2.))
                .rounded(px(4.))
                .border_1()
                .border_color(colors::teal_border())
                .text_color(colors::teal())
                .text_size(px(12.))
                .child(SharedString::from(label.to_string())),
        )
        .into_any_element()
}
