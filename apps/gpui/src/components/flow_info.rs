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
) -> gpui::AnyElement {
    let destination = domain
        .as_deref()
        .unwrap_or("(unknown)");

    let direction_str = match direction {
        FlowDirection::Outbound => "OUTBOUND",
        FlowDirection::Inbound => "INBOUND",
    };

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
            "PROCESS",
            process_value(process_name),
        ))
        // Destination row
        .child(grid_row(
            "DESTINATION",
            destination_value(destination),
        ))
        // IP Address row
        .child(grid_row(
            "IP ADDRESS",
            ip_value(ip),
        ))
        // Protocol row
        .child(grid_row(
            "PROTOCOL",
            protocol_value(protocol, port),
        ))
        // Direction row
        .child(grid_row(
            "DIRECTION",
            direction_value(direction_str),
        ));

    if let Some(label) = device_label {
        card = card.child(grid_row(
            "DEVICE",
            device_value(label),
        ));
    }

    v_flex()
        .px(px(16.))
        .py(px(16.))
        .child(card)
        .into_any_element()
}

fn grid_row(label: &str, value: gpui::AnyElement) -> gpui::AnyElement {
    h_flex()
        .w_full()
        .child(
            // Label column (4/12)
            div()
                .w(px(120.))
                .child(label_element(label)),
        )
        .child(
            // Value column (8/12)
            div()
                .flex_1()
                .child(value),
        )
        .into_any_element()
}

fn label_element(label: &str) -> gpui::AnyElement {
    div()
        .text_color(colors::muted())
        .font_weight(FontWeight::BOLD)
        .text_size(px(11.))
        .child(SharedString::from(label.to_string()))
        .into_any_element()
}

fn process_value(process_name: &str) -> gpui::AnyElement {
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
                .text_color(colors::text())
                .text_size(px(13.))
                .child(SharedString::from(process_name.to_string())),
        )
        .into_any_element()
}

fn destination_value(destination: &str) -> gpui::AnyElement {
    div()
        .text_color(colors::primary())
        .text_size(px(13.))
        .child(SharedString::from(destination.to_string()))
        .into_any_element()
}

fn ip_value(ip: &str) -> gpui::AnyElement {
    div()
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

fn protocol_value(protocol: &str, port: u16) -> gpui::AnyElement {
    div()
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

fn direction_value(direction: &str) -> gpui::AnyElement {
    div()
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

fn device_value(label: &str) -> gpui::AnyElement {
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
