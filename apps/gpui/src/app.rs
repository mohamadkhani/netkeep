use gpui::{Context, Entity, IntoElement, ParentElement, Render, Styled, Window};
use gpui_component::v_flex;

use crate::colors;
use crate::components;
use crate::state::AppState;

pub struct DecisionApp {
    pub state: Entity<AppState>,
}

impl DecisionApp {
    pub fn new(state: Entity<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe(&state, |_, _, cx| cx.notify()).detach();
        Self { state }
    }
}

impl Render for DecisionApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let state = self.state.read(cx);

        if state.resolved {
            return v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .bg(colors::bg())
                .child(
                    gpui::div()
                        .text_color(colors::text())
                        .text_sm()
                        .child("Decision submitted. Closing..."),
                )
                .into_any_element();
        }

        let now = state.now_secs;
        let make_permanent = state.make_permanent;
        let state_weak = self.state.downgrade();
        let item = state.item.clone();

        let remaining = item.deadline_at_secs.saturating_sub(now);
        let process = item
            .flow
            .process_name
            .clone()
            .unwrap_or_else(|| "unknown".into());
        let proto = format!("{:?}", item.flow.protocol).to_uppercase();

        v_flex()
            .size_full()
            .bg(colors::bg())
            .child(components::decision_header(remaining))
            .child(components::flow_info_section(
                &process,
                &proto,
                &item.flow.destination_domain,
                &item.flow.destination_ip,
            ))
            .child(components::action_footer(
                components::ActionFooterProps {
                    pending_id: item.id.clone(),
                    flow: item.flow.clone(),
                    make_permanent,
                    state: state_weak,
                },
            ))
            .into_any_element()
    }
}
