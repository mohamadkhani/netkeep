use core_types::{FlowContext, FlowEvent, PendingDecision, Rule, RuleAction, TransportProtocol};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequest {
    AddRule(Rule),
    ListRules,
    DeleteRule { id: String },
    ListPending,
    ListFlows { limit: usize },
    RegisterUnknownFlow { flow: FlowContext, now_secs: u64 },
    AwaitPendingDecision { pending_id: String },
    ResolvePending { pending_id: String, action: RuleAction },
    Health,
    Unlock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlResponse {
    Ok,
    RuleList(Vec<Rule>),
    PendingList(Vec<PendingDecision>),
    FlowList(Vec<FlowEvent>),
    PendingCreated {
        pending_id: String,
        created_at_secs: u64,
        deadline_at_secs: u64,
        protocol: TransportProtocol,
    },
    ImmediateVerdict { action: RuleAction },
    PendingStillWaiting { pending_id: String },
    PendingResolved { action: RuleAction },
    Health {
        ready: bool,
        fail_close_active: bool,
        pending_limit: usize,
        default_timeout_secs: u64,
        tcp_timeout_secs: u64,
        udp_timeout_secs: u64,
        quic_timeout_secs: u64,
        other_timeout_secs: u64,
    },
    Unlocked,
    Error(String),
}

pub fn validate_request(req: &ControlRequest) -> Result<(), String> {
    match req {
        ControlRequest::DeleteRule { id } if id.trim().is_empty() => {
            Err("rule id cannot be empty".to_string())
        }
        ControlRequest::ResolvePending { pending_id, .. } if pending_id.trim().is_empty() => {
            Err("pending id cannot be empty".to_string())
        }
        ControlRequest::AwaitPendingDecision { pending_id } if pending_id.trim().is_empty() => {
            Err("pending id cannot be empty".to_string())
        }
        ControlRequest::ListFlows { limit } if *limit == 0 => {
            Err("flow list limit must be > 0".to_string())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{DestinationMatcher, RuleDuration};

    fn mk_rule(id: &str) -> Rule {
        Rule {
            id: id.to_string(),
            enabled: true,
            action: RuleAction::Allow,
            duration: RuleDuration::UntilRestart,
            process_name: None,
            destination: DestinationMatcher::IpExact("1.1.1.1".to_string()),
        }
    }

    #[test]
    fn accepts_valid_add_rule_request() {
        let req = ControlRequest::AddRule(mk_rule("r1"));
        assert_eq!(validate_request(&req), Ok(()));
    }

    #[test]
    fn rejects_empty_delete_rule_id() {
        let req = ControlRequest::DeleteRule { id: " ".to_string() };
        assert_eq!(validate_request(&req), Err("rule id cannot be empty".to_string()));
    }

    #[test]
    fn rejects_empty_pending_id() {
        let req = ControlRequest::ResolvePending {
            pending_id: "".to_string(),
            action: RuleAction::Deny,
        };
        assert_eq!(validate_request(&req), Err("pending id cannot be empty".to_string()));
    }

    #[test]
    fn rejects_empty_pending_id_for_await() {
        let req = ControlRequest::AwaitPendingDecision {
            pending_id: " ".to_string(),
        };
        assert_eq!(validate_request(&req), Err("pending id cannot be empty".to_string()));
    }

    #[test]
    fn rejects_zero_flow_list_limit() {
        let req = ControlRequest::ListFlows { limit: 0 };
        assert_eq!(validate_request(&req), Err("flow list limit must be > 0".to_string()));
    }
}
