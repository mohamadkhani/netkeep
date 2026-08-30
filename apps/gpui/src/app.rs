use gpui::{
    div, ease_out_quint, px, Animation, AnimationExt, AppContext as _, Context, Entity,
    IntoElement, ParentElement, Render, Styled, Window,
};
use gpui_component::{v_flex, Theme};

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
        cx.spawn(async move |_this, cx| loop {
            cx.background_executor()
                .timer(std::time::Duration::from_secs(1))
                .await;
            if let Some(state) = state_weak.upgrade() {
                let expired = cx.update_entity(&state, |s, cx| {
                    s.now_secs = daemon::unix_now();
                    let remaining = s.item.deadline_at_secs.saturating_sub(s.now_secs);
                    // Deadline reached: play the close animation instead of
                    // exiting immediately (skipped if a decision already did).
                    if remaining == 0 && !s.closing {
                        s.closing = true;
                    }
                    cx.notify();
                    remaining == 0
                });
                if expired {
                    // Let the ~1s scrim fade-out finish, then quit.
                    cx.background_executor()
                        .timer(std::time::Duration::from_millis(1050))
                        .await;
                    std::process::exit(0);
                }
            } else {
                break;
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
        let closing = state.closing;

        // The window is a transparent full-work-area overlay (maximized).
        // The card fades in immediately; the scrim (black with alpha) waits
        // for a short latency and then fades in over the desktop, so the
        // dialog feels instant while the environment dims around it. The
        // delayed fade also softens the compositor's window-open animation.
        // When a decision was submitted (closing), both fade out instead and
        // the process exits once the scrim has finished.
        let scrim = div().absolute().inset_0().size_full().bg(colors::scrim());
        let card = v_flex()
            .w(px(440.))
            .bg(colors::surface_container())
            .border_1()
            .border_color(colors::border())
            // Floating-card drop shadow (black with alpha) over the scrim.
            .shadow(vec![gpui::BoxShadow::new(
                px(0.),
                px(16.),
                gpui::hsla(0., 0., 0., 0.5),
            )
            .blur_radius(px(40.))])
            .child(components::decision_header(remaining))
            .child(components::flow_info_section(
                &process,
                &item.flow.app_name,
                &proto,
                item.flow.destination_port,
                &item.flow.destination_domain,
                &item.flow.destination_ip,
                item.flow.direction,
                &item.flow.device_label,
                mono_font,
            ))
            .child(components::action_footer(components::ActionFooterProps {
                pending_id: item.id.clone(),
                flow: item.flow.clone(),
                make_permanent,
                egresses: state.egresses.clone(),
                selected_egress_index: state.selected_egress_index,
                process_scope,
                dest_scope,
                state: state_weak,
            }))
            .child(components::status_bar(pending_count));

        // Distinct element ids per direction: the id keys the animation
        // state, so switching ids restarts the timeline from zero.
        let (scrim, card) = if closing {
            (
                scrim
                    .with_animation(
                        "decision-scrim-fade-out",
                        Animation::new(std::time::Duration::from_millis(1000))
                            .with_easing(ease_out_quint()),
                        |scrim, delta| scrim.opacity(1.0 - delta),
                    )
                    .into_any_element(),
                card.with_animation(
                    "decision-card-fade-out",
                    Animation::new(std::time::Duration::from_millis(250))
                        .with_easing(ease_out_quint()),
                    |card, delta| card.opacity(1.0 - delta),
                )
                .into_any_element(),
            )
        } else {
            (
                scrim
                    .with_animation(
                        "decision-scrim-fade-in",
                        Animation::new(std::time::Duration::from_millis(1000))
                            .with_easing(scrim_easing),
                        |scrim, delta| scrim.opacity(delta),
                    )
                    .into_any_element(),
                card.with_animation(
                    "decision-card-fade-in",
                    Animation::new(std::time::Duration::from_millis(220))
                        .with_easing(ease_out_quint()),
                    |card, delta| card.opacity(delta),
                )
                .into_any_element(),
            )
        };

        div()
            .size_full()
            .relative()
            .flex()
            .items_center()
            .justify_center()
            .child(scrim)
            .child(card)
            .into_any_element()
    }
}

/// Easing for the scrim fade-in: hold fully transparent for the first 30%
/// of the timeline (300ms of the 1000ms animation), then ease the remaining
/// 700ms with an ease-out-quint curve.
fn scrim_easing(delta: f32) -> f32 {
    const HOLD: f32 = 0.3;
    if delta <= HOLD {
        0.0
    } else {
        ease_out_quint()((delta - HOLD) / (1.0 - HOLD))
    }
}
