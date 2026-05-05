use core_types::{FlowContext, Rule, RuleAction, TransportProtocol};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequest {
    AddRule(Rule),
    ListRules,
    DeleteRule { id: String },
    RegisterUnknownFlow { flow: FlowContext, now_secs: u64 },
    ResolvePending { pending_id: String, action: RuleAction },
    Health,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlResponse {
    Ok,
    RuleList(Vec<Rule>),
    PendingCreated {
        pending_id: String,
        created_at_secs: u64,
        deadline_at_secs: u64,
        protocol: TransportProtocol,
    },
    ImmediateVerdict { action: RuleAction },
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
}

