use std::collections::HashMap;

use core_types::{FlowContext, FlowDirection, PendingDecision, RuleAction, TransportProtocol};

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

/// Stable identity for a logical flow, independent of ephemeral src_port or
/// whether the domain was inferred on this particular packet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    process_name: Option<String>,
    destination_ip: String,
    destination_port: u16,
    protocol: TransportProtocol,
}

impl FlowKey {
    fn from(flow: &FlowContext) -> Self {
        Self {
            process_name: flow.process_name.clone(),
            destination_ip: flow.destination_ip.clone(),
            destination_port: flow.destination_port,
            protocol: flow.protocol,
        }
    }
}

#[derive(Debug)]
pub struct DecisionEngine {
    pending: HashMap<String, PendingDecision>,
    /// Reverse index: FlowKey → pending_id. Kept in sync with `pending`.
    pending_by_flow: HashMap<FlowKey, String>,
    resolved: HashMap<String, RuleAction>,
    next_id: u64,
    pending_limit: usize,
    tcp_timeout_secs: u64,
    udp_timeout_secs: u64,
    quic_timeout_secs: u64,
    other_timeout_secs: u64,
    overflow_policy: OverflowPolicy,
}

impl DecisionEngine {
    pub fn new(pending_limit: usize, default_timeout_secs: u64, overflow_policy: OverflowPolicy) -> Self {
        Self {
            pending: HashMap::new(),
            pending_by_flow: HashMap::new(),
            resolved: HashMap::new(),
            next_id: 1,
            pending_limit,
            tcp_timeout_secs: default_timeout_secs,
            udp_timeout_secs: default_timeout_secs,
            quic_timeout_secs: default_timeout_secs,
            other_timeout_secs: default_timeout_secs,
            overflow_policy,
        }
    }

    pub fn with_protocol_timeouts(
        mut self,
        tcp_timeout_secs: u64,
        udp_timeout_secs: u64,
        quic_timeout_secs: u64,
        other_timeout_secs: u64,
    ) -> Self {
        self.tcp_timeout_secs = tcp_timeout_secs;
        self.udp_timeout_secs = udp_timeout_secs;
        self.quic_timeout_secs = quic_timeout_secs;
        self.other_timeout_secs = other_timeout_secs;
        self
    }

    fn timeout_for_protocol(&self, protocol: TransportProtocol) -> u64 {
        match protocol {
            TransportProtocol::Tcp => self.tcp_timeout_secs,
            TransportProtocol::Udp => self.udp_timeout_secs,
            TransportProtocol::Quic => self.quic_timeout_secs,
            TransportProtocol::Other => self.other_timeout_secs,
        }
    }

    pub fn register_unknown_flow(&mut self, flow: FlowContext, now_secs: u64) -> DecisionOutcome {
        // Dedup: if this flow is already pending, return the existing decision.
        // This prevents a flood of identical prompts for every retransmitted packet
        // while the user is looking at the dialog for the same logical connection.
        let key = FlowKey::from(&flow);
        if let Some(existing_id) = self.pending_by_flow.get(&key) {
            if let Some(existing) = self.pending.get(existing_id) {
                return DecisionOutcome::Pending(existing.clone());
            }
        }

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
            deadline_at_secs: now_secs + self.timeout_for_protocol(flow.protocol),
            flow,
            created_at_secs: now_secs,
        };
        self.pending_by_flow.insert(key, id.clone());
        self.pending.insert(id, decision.clone());
        DecisionOutcome::Pending(decision)
    }

    pub fn resolve_pending(&mut self, pending_id: &str, action: RuleAction) -> Option<RuleAction> {
        if let Some(decision) = self.pending.remove(pending_id) {
            let key = FlowKey::from(&decision.flow);
            self.pending_by_flow.remove(&key);
            self.resolved.insert(pending_id.to_string(), action.clone());
            Some(action)
        } else {
            None
        }
    }

    pub fn is_pending(&self, pending_id: &str) -> bool {
        self.pending.contains_key(pending_id)
    }

    pub fn take_resolved(&mut self, pending_id: &str) -> Option<RuleAction> {
        self.resolved.remove(pending_id)
    }

    pub fn expire_timeouts(&mut self, now_secs: u64) -> Vec<String> {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter_map(|(k, v)| (v.deadline_at_secs <= now_secs).then(|| k.clone()))
            .collect();
        for id in &expired {
            if let Some(decision) = self.pending.remove(id) {
                self.pending_by_flow.remove(&FlowKey::from(&decision.flow));
            }
        }
        expired
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn list_pending(&self) -> Vec<PendingDecision> {
        let mut items = self.pending.values().cloned().collect::<Vec<_>>();
        items.sort_by(|a, b| a.created_at_secs.cmp(&b.created_at_secs).then(a.id.cmp(&b.id)));
        items
    }

    /// Reload pending decisions from persistent storage (called at daemon startup).
    /// Advances `next_id` past any restored ids so no collision occurs.
    pub fn restore_pending(&mut self, decisions: Vec<PendingDecision>) {
        for d in decisions {
            if let Some(n) = d.id.strip_prefix("pending-").and_then(|s| s.parse::<u64>().ok()) {
                if n >= self.next_id {
                    self.next_id = n + 1;
                }
            }
            let key = FlowKey::from(&d.flow);
            self.pending_by_flow.insert(key, d.id.clone());
            self.pending.insert(d.id.clone(), d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_flow() -> FlowContext {
        FlowContext {
            process_name: Some("curl".to_string()),
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: Some("example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
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
    fn duplicate_flow_returns_existing_pending() {
        let mut engine = DecisionEngine::new(100, 100, OverflowPolicy::DenyNew);
        let out1 = engine.register_unknown_flow(mk_flow(), 0);
        let id1 = match &out1 { DecisionOutcome::Pending(p) => p.id.clone(), _ => panic!() };

        // Same flow key, different src_port / domain variance — still deduped.
        let mut flow2 = mk_flow();
        flow2.destination_domain = None; // domain not inferred on this packet
        let out2 = engine.register_unknown_flow(flow2, 1);
        let id2 = match &out2 { DecisionOutcome::Pending(p) => p.id.clone(), _ => panic!() };

        assert_eq!(id1, id2, "second packet should reuse the existing pending");
        assert_eq!(engine.pending_count(), 1, "only one pending should exist");
    }

    #[test]
    fn different_destination_port_creates_separate_pending() {
        let mut engine = DecisionEngine::new(100, 100, OverflowPolicy::DenyNew);
        let _ = engine.register_unknown_flow(mk_flow(), 0);
        let mut flow2 = mk_flow();
        flow2.destination_port = 80;
        let _ = engine.register_unknown_flow(flow2, 0);
        assert_eq!(engine.pending_count(), 2);
    }

    #[test]
    fn resolve_cleans_up_flow_index() {
        let mut engine = DecisionEngine::new(100, 100, OverflowPolicy::DenyNew);
        let out = engine.register_unknown_flow(mk_flow(), 0);
        let id = match out { DecisionOutcome::Pending(p) => p.id, _ => panic!() };
        engine.resolve_pending(&id, RuleAction::Allow);

        // After resolve, the same flow should create a new pending (not deduplicate).
        let out2 = engine.register_unknown_flow(mk_flow(), 1);
        let id2 = match out2 { DecisionOutcome::Pending(p) => p.id, _ => panic!() };
        assert_ne!(id, id2);
        assert_eq!(engine.pending_count(), 1);
    }

    #[test]
    fn expire_cleans_up_flow_index() {
        let mut engine = DecisionEngine::new(10, 100, OverflowPolicy::DenyNew);
        let out = engine.register_unknown_flow(mk_flow(), 5);
        let id = match out {
            DecisionOutcome::Pending(p) => p.id,
            _ => panic!("expected pending"),
        };
        let expired = engine.expire_timeouts(105);
        assert_eq!(expired, vec![id]);
        assert_eq!(engine.pending_count(), 0);

        // After expiry, the same flow creates a fresh pending.
        let out2 = engine.register_unknown_flow(mk_flow(), 106);
        assert!(matches!(out2, DecisionOutcome::Pending(_)));
        assert_eq!(engine.pending_count(), 1);
    }

    #[test]
    fn queue_overflow_denies_new_by_default() {
        let mut engine = DecisionEngine::new(1, 100, OverflowPolicy::DenyNew);
        let _ = engine.register_unknown_flow(mk_flow(), 0);
        // Different flow (different port) hits limit.
        let mut flow2 = mk_flow();
        flow2.destination_port = 80;
        let out = engine.register_unknown_flow(flow2, 1);
        assert_eq!(out, DecisionOutcome::Immediate(RuleAction::Deny));
    }

    #[test]
    fn protocol_specific_timeout_is_applied_for_udp() {
        let mut engine = DecisionEngine::new(10, 100, OverflowPolicy::DenyNew)
            .with_protocol_timeouts(120, 15, 20, 30);
        let mut flow = mk_flow();
        flow.protocol = TransportProtocol::Udp;
        let out = engine.register_unknown_flow(flow, 50);
        match out {
            DecisionOutcome::Pending(p) => assert_eq!(p.deadline_at_secs, 65),
            _ => panic!("expected pending"),
        }
    }

    #[test]
    fn protocol_specific_timeout_is_applied_for_tcp() {
        let mut engine = DecisionEngine::new(10, 100, OverflowPolicy::DenyNew)
            .with_protocol_timeouts(120, 15, 20, 30);
        let out = engine.register_unknown_flow(mk_flow(), 50);
        match out {
            DecisionOutcome::Pending(p) => assert_eq!(p.deadline_at_secs, 170),
            _ => panic!("expected pending"),
        }
    }

    #[test]
    fn resolved_action_can_be_polled_once() {
        let mut engine = DecisionEngine::new(10, 100, OverflowPolicy::DenyNew);
        let out = engine.register_unknown_flow(mk_flow(), 5);
        let id = match out {
            DecisionOutcome::Pending(p) => p.id,
            _ => panic!("expected pending"),
        };
        assert!(engine.is_pending(&id));
        let resolved = engine.resolve_pending(&id, RuleAction::Allow);
        assert_eq!(resolved, Some(RuleAction::Allow));
        assert!(!engine.is_pending(&id));
        assert_eq!(engine.take_resolved(&id), Some(RuleAction::Allow));
        assert_eq!(engine.take_resolved(&id), None);
    }

    #[test]
    fn list_pending_returns_sorted_items() {
        let mut engine = DecisionEngine::new(10, 100, OverflowPolicy::DenyNew);
        let f1 = mk_flow();
        let mut f2 = mk_flow();
        f2.destination_ip = "2.2.2.2".to_string();
        let _ = engine.register_unknown_flow(f1, 20);
        let _ = engine.register_unknown_flow(f2, 10);
        let list = engine.list_pending();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].created_at_secs, 10);
        assert_eq!(list[1].created_at_secs, 20);
    }
}
