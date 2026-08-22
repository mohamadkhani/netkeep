//! Rules tab filter model — search + facet filters applied client-side.
//!
//! State lives in `SettingsState` so it survives tab switches but resets on
//! app restart (avoids the "filter ghost" confusion of persisted filters).

use core_types::{DestinationMatcher, Rule, RuleAction, RuleDuration};

/// Single-select facet values. `None` = "Any" (filter disabled).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RulesFilter {
    /// Case-insensitive substring, matched against process name, exe path,
    /// destination display text, and rule id.
    pub search: String,
    pub action: Option<ActionFilter>,
    pub duration: Option<DurationFilter>,
    /// Some(enabled) / Some(disabled)
    pub status: Option<bool>,
    pub route: Option<RouteFilter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionFilter {
    Allow,
    Deny,
    Ask,
    Route,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationFilter {
    Permanent,
    UntilRestart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteFilter {
    Unrouted,
    Egress(String),
}

impl RulesFilter {
    pub fn is_active(&self) -> bool {
        !self.search.is_empty()
            || self.action.is_some()
            || self.duration.is_some()
            || self.status.is_some()
            || self.route.is_some()
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn apply(&self, rules: &[Rule]) -> Vec<Rule> {
        // Space-separated terms, AND semantics: every term must match some
        // field (process, exe, destination, id). Lets users combine e.g.
        // "firefox mozilla.com".
        let terms: Vec<String> = self
            .search
            .to_lowercase()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        rules
            .iter()
            .filter(|r| {
                if !terms.is_empty() && !terms.iter().all(|t| self.matches_search(r, t)) {
                    return false;
                }
                if let Some(a) = self.action {
                    let matches = match (&r.action, a) {
                        (RuleAction::Allow, ActionFilter::Allow)
                        | (RuleAction::Deny, ActionFilter::Deny)
                        | (RuleAction::Ask, ActionFilter::Ask) => true,
                        (RuleAction::Route { .. }, ActionFilter::Route) => true,
                        _ => false,
                    };
                    if !matches {
                        return false;
                    }
                }
                if let Some(d) = self.duration {
                    let matches = match (r.duration, d) {
                        (RuleDuration::Permanent, DurationFilter::Permanent)
                        | (RuleDuration::UntilRestart, DurationFilter::UntilRestart) => true,
                        _ => false,
                    };
                    if !matches {
                        return false;
                    }
                }
                if let Some(status) = self.status {
                    if r.enabled != status {
                        return false;
                    }
                }
                if let Some(route) = &self.route {
                    let matches = match route {
                        RouteFilter::Unrouted => r.egress_id.is_none(),
                        RouteFilter::Egress(id) => r.egress_id.as_deref() == Some(id.as_str()),
                    };
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    fn matches_search(&self, rule: &Rule, needle: &str) -> bool {
        rule.id.to_lowercase().contains(needle)
            || rule
                .process_name
                .as_deref()
                .is_some_and(|p| p.to_lowercase().contains(needle))
            || rule
                .process_exe
                .as_deref()
                .is_some_and(|e| e.to_lowercase().contains(needle))
            || dest_search_text(&rule.destination).contains(needle)
    }
}

/// Plain-text form of a destination, for search matching. `dest_text` in
/// `components::ds` returns a display String; here we keep it allocation-free
/// for the common variants and fall back to it otherwise.
fn dest_search_text(dest: &DestinationMatcher) -> String {
    match dest {
        DestinationMatcher::Any => "any".to_string(),
        other => crate::components::dest_text(other),
    }
}
