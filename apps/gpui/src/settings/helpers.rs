//! Shared helper functions for the settings window.

use control_api::{ControlRequest, ControlResponse};
use core_types::RouteTarget;
use gpui::{AppContext as _, AsyncApp, WeakEntity};

use crate::daemon;

use super::SettingsState;

/// Fetch rules and egresses from the daemon and apply them to the state entity.
pub async fn fetch_and_apply(
    state: WeakEntity<SettingsState>,
    socket_path: &str,
    cx: &mut AsyncApp,
) {
    let rules_task = cx.background_executor().spawn({
        let p = socket_path.to_string();
        async move { daemon::send_request(&p, &ControlRequest::ListRules) }
    });
    let egress_task = cx.background_executor().spawn({
        let p = socket_path.to_string();
        async move { daemon::send_request(&p, &ControlRequest::ListEgresses) }
    });
    let (rules_r, egress_r) = (rules_task.await, egress_task.await);

    let Some(entity) = state.upgrade() else {
        return;
    };

    match (rules_r, egress_r) {
        (Ok(ControlResponse::RuleList(rules)), Ok(ControlResponse::EgressList(egresses))) => {
            let merged = daemon::merge_egress_availability(egresses);
            let _ = cx.update_entity(&entity, |s: &mut SettingsState, cx| {
                s.rules = rules;
                s.egresses = merged;
                s.load_generation = s.load_generation.saturating_add(1);
                s.status = None;
                cx.notify();
            });
        }
        (Err(e), _) | (_, Err(e)) => {
            let _ = cx.update_entity(&entity, |s: &mut SettingsState, cx| {
                s.status = Some(format!("load failed: {e}"));
                cx.notify();
            });
        }
        _ => {
            let _ = cx.update_entity(&entity, |s: &mut SettingsState, cx| {
                s.status = Some("unexpected response from daemon".into());
                cx.notify();
            });
        }
    }
}

/// Parse a comma/space/newline/tab-separated DNS server string into a list.
pub fn parse_dns_csv(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// Short human-readable summary of a route target.
pub fn route_summary(t: &RouteTarget) -> String {
    match t {
        RouteTarget::Tun(n) => format!("tun:{n}"),
        RouteTarget::Device(n) => format!("dev:{n}"),
    }
}
