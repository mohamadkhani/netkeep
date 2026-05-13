use gpui::{AppContext as _, Context, Entity, IntoElement, ParentElement, Render, Styled, Window};
use gpui_component::{Theme, v_flex};

use crate::colors;
use crate::components;
use crate::daemon;
use crate::state::AppState;

pub struct DecisionApp {
    pub state: Entity<AppState>,
}

impl DecisionApp {
    pub fn new(state: Entity<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe(&state, |_, _, cx| cx.notify()).detach();

        // Start a 1-second countdown ticker
        let state_weak = state.downgrade();
        cx.spawn(async move |_this, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(1))
                    .await;
                if let Some(state) = state_weak.upgrade() {
                    let expired = cx.update_entity(&state, |s, cx| {
                        s.now_secs = daemon::unix_now();
                        let remaining = s.item.deadline_at_secs.saturating_sub(s.now_secs);
                        cx.notify();
                        remaining == 0
                    });
                    if expired {
                        std::process::exit(0);
                    }
                } else {
                    break;
                }
            }
        })
        .detach();

        Self { state }
    }
}

impl Render for DecisionApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let state = self.state.read(cx);

        let now = state.now_secs;
        let make_permanent = state.make_permanent;
        let pending_count = state.pending_count;
        let process_scope = state.process_scope.clone();
        let dest_scope = state.dest_scope.clone();
        let state_weak = self.state.downgrade();
        let item = state.item.clone();
        let mono_font = Theme::global(cx).mono_font_family.clone();

        let remaining = item.deadline_at_secs.saturating_sub(now);
        let process = item
            .flow
            .process_name
            .clone()
            .unwrap_or_else(|| "unknown".into());
        let proto = format!("{:?}", item.flow.protocol).to_uppercase();

        v_flex()
            .w_full()
            .h_full()
            .overflow_hidden()
            .bg(colors::surface_container())
            .border_1()
            .border_color(colors::border())
            .child(components::decision_header(remaining))
            .child(components::flow_info_section(
                &process,
                &proto,
                item.flow.destination_port,
                &item.flow.destination_domain,
                &item.flow.destination_ip,
                item.flow.direction,
                &item.flow.device_label,
                mono_font,
            ))
            .child(components::action_footer(
                components::ActionFooterProps {
                    pending_id: item.id.clone(),
                    flow: item.flow.clone(),
                    make_permanent,
                    egresses: state.egresses.clone(),
                    selected_egress_index: state.selected_egress_index,
                    process_scope,
                    dest_scope,
                    state: state_weak,
                },
            ))
            .child(components::status_bar(pending_count))
            .into_any_element()
    }
}
