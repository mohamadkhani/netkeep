use gpui::{FontWeight, IntoElement, ParentElement, SharedString, Styled, div, prelude::FluentBuilder as _, px};
use gpui_component::{h_flex, v_flex};

use crate::colors;

fn application_row(process_name: &str, protocol: &str) -> gpui::AnyElement {
    v_flex()
        .gap_1()
        .child(
            div()
                .text_color(colors::muted())
                .text_xs()
                .font_weight(FontWeight::BOLD)
                .child("APPLICATION"),
        )
        .child(
            h_flex()
                .gap_3()
                .items_center()
                .child(
                    div()
                        .text_color(colors::text())
                        .text_xl()
                        .font_weight(FontWeight::BOLD)
                        .child(SharedString::from(process_name.to_string())),
                )
                .child(
                    div()
                        .px_2()
                        .py_px()
                        .rounded(px(4.))
                        .bg(colors::border())
                        .text_color(colors::muted())
                        .text_xs()
                        .child(SharedString::from(protocol.to_string())),
                ),
        )
        .into_any_element()
}

fn destination_row(domain: &Option<String>, ip: &str) -> gpui::AnyElement {
    v_flex()
        .gap_1()
        .child(
            div()
                .text_color(colors::muted())
                .text_xs()
                .font_weight(FontWeight::BOLD)
                .child("DESTINATION"),
        )
        .when_some(domain.clone(), |el, d| {
            el.child(
                div()
                    .text_color(colors::text())
                    .text_lg()
                    .font_weight(FontWeight::BOLD)
                    .child(SharedString::from(d)),
            )
        })
        .child(
            div()
                .text_color(colors::muted())
                .text_sm()
                .child(SharedString::from(ip.to_string())),
        )
        .into_any_element()
}

pub fn flow_info_section(
    process_name: &str,
    protocol: &str,
    domain: &Option<String>,
    ip: &str,
) -> gpui::AnyElement {
    v_flex()
        .flex_1()
        .px_5()
        .py_4()
        .gap_4()
        .child(application_row(process_name, protocol))
        .child(div().w_full().h_px().bg(colors::border()))
        .child(destination_row(domain, ip))
        .into_any_element()
}
