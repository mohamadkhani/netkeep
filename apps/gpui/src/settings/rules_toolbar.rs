//! Rules tab filter toolbar — search input + facet selects + clear button.
//!
//! Matches the design mockup in `design/rules_filter_sort.html`: quiet
//! controls in the existing design language, active facets tinted, live
//! result count, and a Clear affordance shown only while filters are active.
//!
//! Facets use gpui-component's `Select` (`SelectState<Vec<String>>` entities
//! owned by `SettingsApp`). Selection is confirmed via `SelectEvent::Confirm`
//! subscriptions; the entities are reconciled with the filter state on every
//! state change so Clear / external resets stay in sync.


use std::rc::Rc;

use gpui::{
    div, px, AnyElement, InteractiveElement, IntoElement, ParentElement, StatefulInteractiveElement,
    Styled,
};
use gpui_component::h_flex;
use gpui_component::input::{Input, InputState};
use gpui_component::label::Label;
use gpui_component::select::Select;
use gpui_component::select::SelectState;

use crate::colors;
use crate::components::action_btn;

use super::rules_filter::RulesFilter;

/// The four facet select states (plain string items, "Any" = index 0).
#[derive(Clone)]
pub struct FacetSelects {
    pub action: gpui::Entity<SelectState<Vec<String>>>,
    pub duration: gpui::Entity<SelectState<Vec<String>>>,
    pub status: gpui::Entity<SelectState<Vec<String>>>,
    pub route: gpui::Entity<SelectState<Vec<String>>>,
}

pub struct RulesToolbar<'a> {
    pub filter: &'a RulesFilter,
    pub search_input: &'a gpui::Entity<InputState>,
    pub facets: &'a FacetSelects,
    /// "34 of 217 rules"
    pub shown: usize,
    pub total: usize,
    /// Called with (window, cx) when CLEAR is clicked — resets filter state,
    /// search input, and facet selects.
    pub on_clear: Rc<dyn Fn(&mut gpui::Window, &mut gpui::App)>,
}

impl<'a> RulesToolbar<'a> {
    pub fn render(self) -> AnyElement {
        let mut row = h_flex().gap(px(6.)).items_center();

        row = row.child(Input::new(self.search_input).h(px(28.)).w(px(220.)));

        // `Select` hardcodes `.size_full()` on its wrapper in this
        // gpui-component rev, so its own width styles are ignored —
        // constrain the parent div instead.
        let facet = |state: &'a gpui::Entity<SelectState<Vec<String>>>,
                     id: &'static str,
                     placeholder: &'static str,
                     w: f32| {
            div()
                .id(id)
                .w(px(w))
                .h(px(28.))
                .child(Select::new(state).placeholder(placeholder))
        };

        row = row
            .child(facet(&self.facets.action, "filter-action", "Action", 104.))
            .child(facet(
                &self.facets.duration,
                "filter-duration",
                "Duration",
                104.,
            ))
            .child(facet(&self.facets.status, "filter-status", "Status", 104.))
            .child(facet(&self.facets.route, "filter-route", "Route", 120.));


        row = row.child(
            Label::new(format!("{} of {} rules", self.shown, self.total))
                .text_size(px(10.))
                .text_color(colors::muted())
                .ml(px(4.)),
        );

        if self.filter.is_active() {
            let on_clear = self.on_clear.clone();
            row = row.child(
                action_btn("filter-clear", "CLEAR", colors::primary())
                    .on_click(move |_, window, cx| on_clear(window, cx)),
            );
        }

        row.into_any_element()
    }
}
