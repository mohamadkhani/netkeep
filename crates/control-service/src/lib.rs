use control_api::{validate_request, ControlRequest, ControlResponse};
use decision_engine::{DecisionEngine, DecisionOutcome, OverflowPolicy};
use state_store::RuleRepository;

pub struct ControlService<R: RuleRepository> {
    repo: R,
    decision_engine: DecisionEngine,
}

impl<R: RuleRepository> ControlService<R> {
    pub fn new(repo: R) -> Self {
        Self {
            repo,
            decision_engine: DecisionEngine::new(100, 100, OverflowPolicy::DenyNew),
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
            ControlRequest::RegisterUnknownFlow { flow, now_secs } => {
                match self.decision_engine.register_unknown_flow(flow, now_secs) {
                    DecisionOutcome::Immediate(action) => ControlResponse::ImmediateVerdict { action },
                    DecisionOutcome::Pending(p) => ControlResponse::PendingCreated {
                        pending_id: p.id,
                        deadline_at_secs: p.deadline_at_secs,
                    },
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
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use control_api::{ControlRequest, ControlResponse};
    use core_types::{DestinationMatcher, FlowContext, Rule, RuleAction, RuleDuration};
    use state_store::InMemoryRuleRepository;

    use super::ControlService;

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
    fn resolve_missing_pending_returns_error() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let out = service.handle(ControlRequest::ResolvePending {
            pending_id: "missing".to_string(),
            action: RuleAction::Allow,
        });
        assert_eq!(out, ControlResponse::Error("pending decision not found".to_string()));
    }
}

