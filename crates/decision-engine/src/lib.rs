use std::collections::HashMap;

use core_types::{FlowContext, PendingDecision, RuleAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    DenyNew,
    AllowNew,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionOutcome {
    Immediate(RuleAction),
    Pending(PendingDecision),
}

#[derive(Debug)]
pub struct DecisionEngine {
    pending: HashMap<String, PendingDecision>,
    next_id: u64,
    pending_limit: usize,
    default_timeout_secs: u64,
    overflow_policy: OverflowPolicy,
}

impl DecisionEngine {
    pub fn new(pending_limit: usize, default_timeout_secs: u64, overflow_policy: OverflowPolicy) -> Self {
        Self {
            pending: HashMap::new(),
            next_id: 1,
            pending_limit,
            default_timeout_secs,
            overflow_policy,
        }
    }

    pub fn register_unknown_flow(&mut self, flow: FlowContext, now_secs: u64) -> DecisionOutcome {
        if self.pending.len() >= self.pending_limit {
            return match self.overflow_policy {
                OverflowPolicy::DenyNew => DecisionOutcome::Immediate(RuleAction::Deny),
                OverflowPolicy::AllowNew => DecisionOutcome::Immediate(RuleAction::Allow),
            };
        }

        let id = format!("pending-{}", self.next_id);
        self.next_id += 1;
        let decision = PendingDecision {
            id: id.clone(),
            flow,
            created_at_secs: now_secs,
            deadline_at_secs: now_secs + self.default_timeout_secs,
        };
        self.pending.insert(id, decision.clone());
        DecisionOutcome::Pending(decision)
    }

    pub fn resolve_pending(&mut self, pending_id: &str, action: RuleAction) -> Option<RuleAction> {
        if self.pending.remove(pending_id).is_some() {
            Some(action)
        } else {
            None
        }
    }

    pub fn expire_timeouts(&mut self, now_secs: u64) -> Vec<String> {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter_map(|(k, v)| (v.deadline_at_secs <= now_secs).then(|| k.clone()))
            .collect();
        for id in &expired {
            self.pending.remove(id);
        }
        expired
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_flow() -> FlowContext {
        FlowContext {
            process_name: Some("curl".to_string()),
            destination_ip: "1.1.1.1".to_string(),
            destination_domain: Some("example.com".to_string()),
        }
    }

    #[test]
    fn unknown_flow_creates_pending_decision() {
        let mut engine = DecisionEngine::new(100, 100, OverflowPolicy::DenyNew);
        let out = engine.register_unknown_flow(mk_flow(), 1000);
        match out {
            DecisionOutcome::Pending(p) => {
                assert_eq!(p.created_at_secs, 1000);
                assert_eq!(p.deadline_at_secs, 1100);
                assert_eq!(engine.pending_count(), 1);
            }
            _ => panic!("expected pending"),
        }
    }

    #[test]
    fn queue_overflow_denies_new_by_default() {
        let mut engine = DecisionEngine::new(1, 100, OverflowPolicy::DenyNew);
        let _ = engine.register_unknown_flow(mk_flow(), 0);
        let out = engine.register_unknown_flow(mk_flow(), 1);
        assert_eq!(out, DecisionOutcome::Immediate(RuleAction::Deny));
    }

    #[test]
    fn timeout_expiration_removes_pending() {
        let mut engine = DecisionEngine::new(10, 100, OverflowPolicy::DenyNew);
        let out = engine.register_unknown_flow(mk_flow(), 5);
        let id = match out {
            DecisionOutcome::Pending(p) => p.id,
            _ => panic!("expected pending"),
        };
        let expired = engine.expire_timeouts(105);
        assert_eq!(expired, vec![id]);
        assert_eq!(engine.pending_count(), 0);
    }
}

