use core_types::{
    Egress, FlowContext, FlowEvent, PendingDecision, ProxyConfig, RouteTarget, Rule, RuleAction,
    TransportProtocol,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequest {
    AddRule(Rule),
    ListRules,
    DeleteRule {
        id: String,
    },
    ListPending,
    ListFlows {
        limit: usize,
    },
    RegisterUnknownFlow {
        flow: FlowContext,
        now_secs: u64,
    },
    AwaitPendingDecision {
        pending_id: String,
    },
    ResolvePending {
        pending_id: String,
        action: RuleAction,
    },
    /// Resolve a pending decision and atomically install the rule in one request,
    /// eliminating the race window between two separate ResolvePending + AddRule calls.
    ResolvePendingWithRule {
        pending_id: String,
        action: RuleAction,
        rule: Rule,
    },
    Health,
    Unlock,
    SubscribeToPending, // NEW: Subscribe to push notifications
    OpenRoutedTcp {
        host: String,
        port: u16,
        target: RouteTarget,
    },
    ListEgresses,
    UpsertEgress(Egress),
    DeleteEgress {
        id: String,
    },
    // Proxy management
    UpsertProxy(ProxyConfig),
    DeleteProxy {
        id: String,
    },
    ListProxies,
    // NFQUEUE management
    SetNfqueueEnabled {
        enabled: bool,
    },
    // Proxy connectivity testing
    /// Test HTTP/HTTPS connectivity through a proxy.
    TestProxyHttp {
        proxy_id: String,
        url: String,
    },
    /// Test DNS resolution through a proxy.
    TestProxyDns {
        proxy_id: String,
        domain: String,
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
    /// Returned when a flow immediately matches a stored rule.
    /// `route_target` is `Some` only when `action == Route`; it holds the
    /// first available target resolved from the rule's egress at decision time.
    ImmediateVerdict {
        action: RuleAction,
        route_target: Option<RouteTarget>,
    },
    PendingStillWaiting {
        pending_id: String,
    },
    /// Returned after a pending decision is resolved.
    /// `route_target` is `Some` only when `action == Route`.
    PendingResolved {
        action: RuleAction,
        route_target: Option<RouteTarget>,
    },
    Health {
        ready: bool,
        fail_close_active: bool,
        pending_limit: usize,
        default_timeout_secs: u64,
        tcp_timeout_secs: u64,
        udp_timeout_secs: u64,
        quic_timeout_secs: u64,
        other_timeout_secs: u64,
        nfqueue_enabled: bool,
        nfqueue_num: Option<u16>,
    },
    Unlocked,
    SubscriptionAck, // NEW: Confirms subscription established
    RoutedTcpReady {
        listen_addr: String,
    },
    Error(String),
    EgressList(Vec<Egress>),
    ProxyList(Vec<ProxyConfig>),
    NfqueueStatus {
        enabled: bool,
        queue_num: Option<u16>,
    },
    /// Result of a proxy connectivity test (HTTP or DNS).
    ProxyTestResult {
        success: bool,
        latency_ms: u64,
        error: Option<String>,
    },
}

// NEW: Push notifications sent from daemon to subscribers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushNotification {
    PendingCreated {
        decision: PendingDecision,
    },
    PendingResolved {
        pending_id: String,
        action: RuleAction,
    },
    PendingExpired {
        pending_id: String,
    },
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
        ControlRequest::SubscribeToPending => Ok(()), // Always valid
        ControlRequest::DeleteEgress { id } if id.trim().is_empty() => {
            Err("egress id cannot be empty".to_string())
        }
        ControlRequest::UpsertEgress(eg) if eg.id.trim().is_empty() => {
            Err("egress id cannot be empty".to_string())
        }
        ControlRequest::UpsertProxy(px) if px.id.trim().is_empty() => {
            Err("proxy id cannot be empty".to_string())
        }
        ControlRequest::DeleteProxy { id } if id.trim().is_empty() => {
            Err("proxy id cannot be empty".to_string())
        }
        ControlRequest::TestProxyHttp { proxy_id, .. } if proxy_id.trim().is_empty() => {
            Err("proxy id cannot be empty".to_string())
        }
        ControlRequest::TestProxyDns { proxy_id, .. } if proxy_id.trim().is_empty() => {
            Err("proxy id cannot be empty".to_string())
        }
        ControlRequest::TestProxyHttp { url, .. } if url.trim().is_empty() => {
            Err("url cannot be empty".to_string())
        }
        ControlRequest::TestProxyDns { domain, .. } if domain.trim().is_empty() => {
            Err("domain cannot be empty".to_string())
        }
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
            process_exe: None,
            destination: DestinationMatcher::IpExact("1.1.1.1".to_string()),
            egress_id: None,
        }
    }

    #[test]
    fn accepts_valid_add_rule_request() {
        let req = ControlRequest::AddRule(mk_rule("r1"));
        assert_eq!(validate_request(&req), Ok(()));
    }

    #[test]
    fn rejects_empty_delete_rule_id() {
        let req = ControlRequest::DeleteRule {
            id: " ".to_string(),
        };
        assert_eq!(
            validate_request(&req),
            Err("rule id cannot be empty".to_string())
        );
    }

    #[test]
    fn rejects_empty_pending_id() {
        let req = ControlRequest::ResolvePending {
            pending_id: "".to_string(),
            action: RuleAction::Deny,
        };
        assert_eq!(
            validate_request(&req),
            Err("pending id cannot be empty".to_string())
        );
    }

    #[test]
    fn rejects_empty_pending_id_for_await() {
        let req = ControlRequest::AwaitPendingDecision {
            pending_id: " ".to_string(),
        };
        assert_eq!(
            validate_request(&req),
            Err("pending id cannot be empty".to_string())
        );
    }

    #[test]
    fn rejects_zero_flow_list_limit() {
        let req = ControlRequest::ListFlows { limit: 0 };
        assert_eq!(
            validate_request(&req),
            Err("flow list limit must be > 0".to_string())
        );
    }

    #[test]
    fn accepts_subscribe_to_pending_request() {
        let req = ControlRequest::SubscribeToPending;
        assert_eq!(validate_request(&req), Ok(()));
    }

    #[test]
    fn rejects_empty_delete_egress_id() {
        let req = ControlRequest::DeleteEgress {
            id: " ".to_string(),
        };
        assert_eq!(
            validate_request(&req),
            Err("egress id cannot be empty".to_string())
        );
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
                process_exe: None,
                app_name: None,
                source_ip: "10.0.0.1".to_string(),
                source_port: 54321,
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

    #[test]
    fn rejects_empty_proxy_id_for_test_http() {
        let req = ControlRequest::TestProxyHttp {
            proxy_id: "".to_string(),
            url: "https://example.com".to_string(),
        };
        assert_eq!(
            validate_request(&req),
            Err("proxy id cannot be empty".to_string())
        );
    }

    #[test]
    fn rejects_empty_url_for_test_http() {
        let req = ControlRequest::TestProxyHttp {
            proxy_id: "px-1".to_string(),
            url: "  ".to_string(),
        };
        assert_eq!(
            validate_request(&req),
            Err("url cannot be empty".to_string())
        );
    }

    #[test]
    fn rejects_empty_domain_for_test_dns() {
        let req = ControlRequest::TestProxyDns {
            proxy_id: "px-1".to_string(),
            domain: "".to_string(),
        };
        assert_eq!(
            validate_request(&req),
            Err("domain cannot be empty".to_string())
        );
    }

    #[test]
    fn accepts_valid_test_proxy_http() {
        let req = ControlRequest::TestProxyHttp {
            proxy_id: "px-1".to_string(),
            url: "https://example.com".to_string(),
        };
        assert_eq!(validate_request(&req), Ok(()));
    }

    #[test]
    fn accepts_valid_test_proxy_dns() {
        let req = ControlRequest::TestProxyDns {
            proxy_id: "px-1".to_string(),
            domain: "google.com".to_string(),
        };
        assert_eq!(validate_request(&req), Ok(()));
    }

    #[test]
    fn proxy_test_result_serializes() {
        let resp = ControlResponse::ProxyTestResult {
            success: true,
            latency_ms: 150,
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("ProxyTestResult"));
        assert!(json.contains("150"));
    }
}
