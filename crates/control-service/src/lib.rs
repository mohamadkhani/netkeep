use control_api::{validate_request, ControlRequest, ControlResponse};
use core_types::{FlowContext, RuleAction};
use decision_engine::{DecisionEngine, DecisionOutcome, OverflowPolicy};
use enforcer::{FlowDecision, FlowRegistrar};
use policy_engine::resolve_action;
use state_store::RuleRepository;

pub struct ControlService<R: RuleRepository> {
    repo: R,
    decision_engine: DecisionEngine,
    health_config: HealthConfig,
}

#[derive(Debug, Clone, Copy)]
pub struct HealthConfig {
    pub pending_limit: usize,
    pub default_timeout_secs: u64,
    pub tcp_timeout_secs: u64,
    pub udp_timeout_secs: u64,
    pub quic_timeout_secs: u64,
    pub other_timeout_secs: u64,
}

impl<R: RuleRepository> ControlService<R> {
    pub fn new(repo: R) -> Self {
        let default_timeout_secs = 100;
        let pending_limit = 100;
        let health_config = HealthConfig {
            pending_limit,
            default_timeout_secs,
            tcp_timeout_secs: default_timeout_secs,
            udp_timeout_secs: default_timeout_secs,
            quic_timeout_secs: default_timeout_secs,
            other_timeout_secs: default_timeout_secs,
        };
        Self::with_decision_engine_and_health(
            repo,
            DecisionEngine::new(pending_limit, default_timeout_secs, OverflowPolicy::DenyNew),
            health_config,
        )
    }

    pub fn with_decision_engine(repo: R, decision_engine: DecisionEngine) -> Self {
        let default_timeout_secs = 100;
        let health_config = HealthConfig {
            pending_limit: 100,
            default_timeout_secs,
            tcp_timeout_secs: default_timeout_secs,
            udp_timeout_secs: default_timeout_secs,
            quic_timeout_secs: default_timeout_secs,
            other_timeout_secs: default_timeout_secs,
        };
        Self::with_decision_engine_and_health(repo, decision_engine, health_config)
    }

    pub fn with_decision_engine_and_health(
        repo: R,
        decision_engine: DecisionEngine,
        health_config: HealthConfig,
    ) -> Self {
        Self {
            repo,
            decision_engine,
            health_config,
        }
    }

    pub fn handle(&mut self, request: ControlRequest) -> ControlResponse {
        if let Err(err) = validate_request(&request) {
            return ControlResponse::Error(err);
        }

        match request {
            ControlRequest::AddRule(rule) => {
                self.repo.upsert_rule(rule);
                ControlResponse::Ok
            }
            ControlRequest::ListRules => {
                let mut rules = self.repo.list_rules();
                rules.sort_by(|a, b| a.id.cmp(&b.id));
                ControlResponse::RuleList(rules)
            }
            ControlRequest::DeleteRule { id } => {
                if self.repo.delete_rule(&id) {
                    ControlResponse::Ok
                } else {
                    ControlResponse::Error("rule not found".to_string())
                }
            }
            ControlRequest::ListPending => {
                ControlResponse::PendingList(self.decision_engine.list_pending())
            }
            ControlRequest::RegisterUnknownFlow { flow, now_secs } => {
                if let Some(resolved) = resolve_action(&self.repo.list_rules(), &flow) {
                    match resolved.action {
                        RuleAction::Allow | RuleAction::Deny => {
                            return ControlResponse::ImmediateVerdict {
                                action: resolved.action,
                            };
                        }
                        RuleAction::Ask => {}
                    }
                }
                match self.decision_engine.register_unknown_flow(flow, now_secs) {
                    DecisionOutcome::Immediate(action) => ControlResponse::ImmediateVerdict { action },
                    DecisionOutcome::Pending(p) => ControlResponse::PendingCreated {
                        pending_id: p.id,
                        created_at_secs: p.created_at_secs,
                        deadline_at_secs: p.deadline_at_secs,
                        protocol: p.flow.protocol,
                    },
                }
            }
            ControlRequest::AwaitPendingDecision { pending_id } => {
                if let Some(action) = self.decision_engine.take_resolved(&pending_id) {
                    ControlResponse::PendingResolved { action }
                } else if self.decision_engine.is_pending(&pending_id) {
                    ControlResponse::PendingStillWaiting { pending_id }
                } else {
                    ControlResponse::Error("pending decision not found".to_string())
                }
            }
            ControlRequest::ResolvePending { pending_id, action } => {
                if let Some(chosen) = self.decision_engine.resolve_pending(&pending_id, action) {
                    ControlResponse::PendingResolved { action: chosen }
                } else {
                    ControlResponse::Error("pending decision not found".to_string())
                }
            }
            ControlRequest::Health => ControlResponse::Health {
                ready: true,
                fail_close_active: true,
                pending_limit: self.health_config.pending_limit,
                default_timeout_secs: self.health_config.default_timeout_secs,
                tcp_timeout_secs: self.health_config.tcp_timeout_secs,
                udp_timeout_secs: self.health_config.udp_timeout_secs,
                quic_timeout_secs: self.health_config.quic_timeout_secs,
                other_timeout_secs: self.health_config.other_timeout_secs,
            },
        }
    }
}

/// Newtype wrapper that lets a shared `ControlService` be used as a `FlowRegistrar`
/// across threads (e.g., handed to the nfqueue processor thread).
pub struct SharedService<R: RuleRepository>(
    pub std::sync::Arc<std::sync::Mutex<ControlService<R>>>,
);

impl<R: RuleRepository> FlowRegistrar for SharedService<R> {
    fn register(&mut self, flow: FlowContext, now_secs: u64) -> FlowDecision {
        self.0.lock().expect("service lock poisoned").register(flow, now_secs)
    }
}

impl<R: RuleRepository> FlowRegistrar for ControlService<R> {
    fn register(&mut self, flow: FlowContext, now_secs: u64) -> FlowDecision {
        if let Some(resolved) = resolve_action(&self.repo.list_rules(), &flow) {
            match resolved.action {
                RuleAction::Allow | RuleAction::Deny => {
                    return FlowDecision::Immediate(resolved.action);
                }
                RuleAction::Ask => {}
            }
        }
        match self.decision_engine.register_unknown_flow(flow, now_secs) {
            DecisionOutcome::Immediate(action) => FlowDecision::Immediate(action),
            DecisionOutcome::Pending(p) => FlowDecision::Pending {
                id: p.id,
                deadline_at_secs: p.deadline_at_secs,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use control_api::{ControlRequest, ControlResponse};
    use core_types::{DestinationMatcher, FlowContext, Rule, RuleAction, RuleDuration, TransportProtocol};
    use state_store::InMemoryRuleRepository;

    use super::{ControlService, HealthConfig};
    use decision_engine::{DecisionEngine, OverflowPolicy};

    fn mk_rule(id: &str) -> Rule {
        Rule {
            id: id.to_string(),
            enabled: true,
            action: RuleAction::Allow,
            duration: RuleDuration::UntilRestart,
            process_name: None,
            destination: DestinationMatcher::DomainExact("example.com".to_string()),
        }
    }

    fn mk_flow() -> FlowContext {
        FlowContext {
            process_name: Some("curl".to_string()),
            destination_ip: "1.1.1.1".to_string(),
            destination_domain: Some("example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            device_label: None,
        }
    }

    #[test]
    fn add_then_list_rules() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let add = service.handle(ControlRequest::AddRule(mk_rule("r1")));
        assert_eq!(add, ControlResponse::Ok);

        let list = service.handle(ControlRequest::ListRules);
        match list {
            ControlResponse::RuleList(rules) => assert_eq!(rules.len(), 1),
            _ => panic!("expected rule list"),
        }
    }

    #[test]
    fn list_pending_returns_created_pending_items() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let _ = service.handle(ControlRequest::RegisterUnknownFlow {
            flow: mk_flow(),
            now_secs: 10,
        });
        let out = service.handle(ControlRequest::ListPending);
        match out {
            ControlResponse::PendingList(items) => assert_eq!(items.len(), 1),
            _ => panic!("expected pending list"),
        }
    }

    #[test]
    fn register_and_resolve_pending_decision() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let register = service.handle(ControlRequest::RegisterUnknownFlow {
            flow: mk_flow(),
            now_secs: 10,
        });
        let pending_id = match register {
            ControlResponse::PendingCreated { pending_id, .. } => pending_id,
            _ => panic!("expected pending creation"),
        };

        let resolved = service.handle(ControlRequest::ResolvePending {
            pending_id,
            action: RuleAction::Deny,
        });
        assert_eq!(resolved, ControlResponse::PendingResolved { action: RuleAction::Deny });
    }

    #[test]
    fn await_pending_decision_transitions_waiting_to_resolved() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let register = service.handle(ControlRequest::RegisterUnknownFlow {
            flow: mk_flow(),
            now_secs: 10,
        });
        let pending_id = match register {
            ControlResponse::PendingCreated { pending_id, .. } => pending_id,
            _ => panic!("expected pending creation"),
        };

        let waiting = service.handle(ControlRequest::AwaitPendingDecision {
            pending_id: pending_id.clone(),
        });
        assert_eq!(
            waiting,
            ControlResponse::PendingStillWaiting {
                pending_id: pending_id.clone()
            }
        );

        let _ = service.handle(ControlRequest::ResolvePending {
            pending_id: pending_id.clone(),
            action: RuleAction::Allow,
        });
        let resolved = service.handle(ControlRequest::AwaitPendingDecision {
            pending_id: pending_id.clone(),
        });
        assert_eq!(resolved, ControlResponse::PendingResolved { action: RuleAction::Allow });
    }

    #[test]
    fn matching_allow_rule_returns_immediate_verdict() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let _ = service.handle(ControlRequest::AddRule(mk_rule("allow-r1")));
        let out = service.handle(ControlRequest::RegisterUnknownFlow {
            flow: mk_flow(),
            now_secs: 10,
        });
        assert_eq!(
            out,
            ControlResponse::ImmediateVerdict {
                action: RuleAction::Allow
            }
        );
    }

    #[test]
    fn resolve_missing_pending_returns_error() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let out = service.handle(ControlRequest::ResolvePending {
            pending_id: "missing".to_string(),
            action: RuleAction::Allow,
        });
        assert_eq!(out, ControlResponse::Error("pending decision not found".to_string()));
    }

    #[test]
    fn custom_protocol_timeouts_propagate_to_pending_response() {
        let engine = DecisionEngine::new(100, 100, OverflowPolicy::DenyNew)
            .with_protocol_timeouts(120, 15, 20, 30);
        let health = HealthConfig {
            pending_limit: 100,
            default_timeout_secs: 100,
            tcp_timeout_secs: 120,
            udp_timeout_secs: 15,
            quic_timeout_secs: 20,
            other_timeout_secs: 30,
        };
        let mut service =
            ControlService::with_decision_engine_and_health(
                InMemoryRuleRepository::default(),
                engine,
                health,
            );

        let mut flow = mk_flow();
        flow.protocol = TransportProtocol::Udp;
        let register = service.handle(ControlRequest::RegisterUnknownFlow {
            flow,
            now_secs: 50,
        });
        match register {
            ControlResponse::PendingCreated {
                deadline_at_secs, ..
            } => assert_eq!(deadline_at_secs, 65),
            _ => panic!("expected pending creation"),
        }
    }

    #[test]
    fn health_includes_runtime_timeout_configuration() {
        let engine = DecisionEngine::new(100, 100, OverflowPolicy::DenyNew)
            .with_protocol_timeouts(120, 15, 20, 30);
        let health = HealthConfig {
            pending_limit: 100,
            default_timeout_secs: 100,
            tcp_timeout_secs: 120,
            udp_timeout_secs: 15,
            quic_timeout_secs: 20,
            other_timeout_secs: 30,
        };
        let mut service =
            ControlService::with_decision_engine_and_health(
                InMemoryRuleRepository::default(),
                engine,
                health,
            );
        let out = service.handle(ControlRequest::Health);
        assert_eq!(
            out,
            ControlResponse::Health {
                ready: true,
                fail_close_active: true,
                pending_limit: 100,
                default_timeout_secs: 100,
                tcp_timeout_secs: 120,
                udp_timeout_secs: 15,
                quic_timeout_secs: 20,
                other_timeout_secs: 30
            }
        );
    }
}

