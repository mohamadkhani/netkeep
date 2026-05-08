use core_types::{FlowContext, FlowEvent, PendingDecision, RouteTarget, Rule, RuleAction, TransportProtocol};
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
    SubscribeToPending,  // NEW: Subscribe to push notifications
    OpenRoutedTcp {
        host: String,
        port: u16,
        target: RouteTarget,
    },
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
    SubscriptionAck,  // NEW: Confirms subscription established
    RoutedTcpReady {
        listen_addr: String,
    },
    Error(String),
}

// NEW: Push notifications sent from daemon to subscribers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushNotification {
    PendingCreated { decision: PendingDecision },
    PendingResolved {
        pending_id: String,
        action: RuleAction,
    },
    PendingExpired { pending_id: String },
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
        ControlRequest::SubscribeToPending => Ok(()),  // Always valid
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{DestinationMatcher, FlowDirection, RuleDuration};

    fn mk_rule(id: &str) -> Rule {
        Rule {
            id: id.to_string(),
            enabled: true,
            action: RuleAction::Allow,
            duration: RuleDuration::UntilRestart,
            process_name: None,
            destination: DestinationMatcher::IpExact("1.1.1.1".to_string()),
            route_target: None,
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

    #[test]
    fn accepts_subscribe_to_pending_request() {
        let req = ControlRequest::SubscribeToPending;
        assert_eq!(validate_request(&req), Ok(()));
    }

    #[test]
    fn subscription_ack_serializes() {
        let resp = ControlResponse::SubscriptionAck;
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("SubscriptionAck"));
    }

    #[test]
    fn push_notification_pending_created_serializes() {
        let decision = PendingDecision {
            id: "p1".to_string(),
            flow: FlowContext {
                process_name: Some("firefox".to_string()),
                destination_ip: "8.8.8.8".to_string(),
                destination_port: 443,
                destination_domain: Some("google.com".to_string()),
                protocol: TransportProtocol::Tcp,
                direction: FlowDirection::Outbound,
                device_label: None,
            },
            created_at_secs: 1000,
            deadline_at_secs: 1100,
        };
        let notif = PushNotification::PendingCreated { decision };
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("PendingCreated"));
        assert!(json.contains("firefox"));
    }

    #[test]
    fn push_notification_pending_resolved_serializes() {
        let notif = PushNotification::PendingResolved {
            pending_id: "p1".to_string(),
            action: RuleAction::Allow,
        };
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("PendingResolved"));
        assert!(json.contains("Allow"));
    }

    #[test]
    fn push_notification_pending_expired_serializes() {
        let notif = PushNotification::PendingExpired {
            pending_id: "p1".to_string(),
        };
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("PendingExpired"));
    }
}
