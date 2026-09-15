use std::collections::HashMap;

#[cfg(test)]
use core_types::FlowDirection;
use core_types::{FlowContext, PendingDecision, RuleAction, TransportProtocol};
use metrics::{counter, gauge};

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
    resolved: HashMap<String, (RuleAction, Option<String>)>,
    next_id: u64,
    pending_limit: usize,
    tcp_timeout_secs: u64,
    udp_timeout_secs: u64,
    quic_timeout_secs: u64,
    other_timeout_secs: u64,
    overflow_policy: OverflowPolicy,
}

impl DecisionEngine {
    pub fn new(
        pending_limit: usize,
        default_timeout_secs: u64,
        overflow_policy: OverflowPolicy,
    ) -> Self {
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
                counter!("logiguard.pending.deduplicated", "type" => "exact").increment(1);
                return DecisionOutcome::Pending(existing.clone());
            }
        }

        // Process-name fallback dedup. proc_resolver loses the /proc/net/tcp
        // race for the first few packets of a new connection: the kernel hasn't
        // written the socket entry yet, so the first packet classifies as
        // process_name=None and later retransmits classify as Some("real-name").
        // Without this, every retransmit that finally learns the name would
        // spawn a fresh dialog. Dedup must be symmetric:
        //   * new packet without process_name → reuse existing pending for the
        //     same (dst_ip, dst_port, protocol).
        //   * new packet WITH process_name → reuse and *upgrade* an existing
        //     "unknown" pending so the dialog shows the real process name.
        // Two pendings with distinct known process_names are kept separate
        // (e.g. chrome and firefox to the same host:port at the same time).
        let dst_ip = flow.destination_ip.clone();
        let dst_port = flow.destination_port;
        let protocol = flow.protocol;
        let fallback = self
            .pending_by_flow
            .iter()
            .find(|(k, _)| {
                k.destination_ip == dst_ip
                    && k.destination_port == dst_port
                    && k.protocol == protocol
                    && (flow.process_name.is_none() || k.process_name.is_none())
            })
            .map(|(k, id)| (k.clone(), id.clone()));
        if let Some((existing_key, existing_id)) = fallback {
            // Upgrade path: rekey the index and patch the stored decision so
            // subsequent polls see the real process name. Also fill in newly
            // learned domain / device label if the original entry lacked them.
            if flow.process_name.is_some() && existing_key.process_name.is_none() {
                self.pending_by_flow.remove(&existing_key);
                if let Some(existing) = self.pending.get_mut(&existing_id) {
                    existing.flow.process_name = flow.process_name.clone();
                    if existing.flow.destination_domain.is_none() {
                        existing.flow.destination_domain = flow.destination_domain.clone();
                    }
                    if existing.flow.device_label.is_none() {
                        existing.flow.device_label = flow.device_label.clone();
                    }
                    let new_key = FlowKey::from(&existing.flow);
                    self.pending_by_flow.insert(new_key, existing_id.clone());
                    counter!("logiguard.pending.deduplicated", "type" => "name_upgrade")
                        .increment(1);
                    return DecisionOutcome::Pending(existing.clone());
                }
            }
            if let Some(existing) = self.pending.get(&existing_id) {
                counter!("logiguard.pending.deduplicated", "type" => "symmetric").increment(1);
                return DecisionOutcome::Pending(existing.clone());
            }
        }

        if self.pending.len() >= self.pending_limit {
            let policy_str = match self.overflow_policy {
                OverflowPolicy::DenyNew => "deny_new",
                OverflowPolicy::AllowNew => "allow_new",
            };
            counter!("logiguard.pending.overflow", "policy" => policy_str).increment(1);
            return match self.overflow_policy {
                OverflowPolicy::DenyNew => DecisionOutcome::Immediate(RuleAction::Deny),
                OverflowPolicy::AllowNew => DecisionOutcome::Immediate(RuleAction::Allow),
            };
        }

        let id = format!("pending-{}", self.next_id);
        self.next_id += 1;
        let proto_str = match flow.protocol {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
            TransportProtocol::Quic => "quic",
            TransportProtocol::Other => "other",
        };
        let decision = PendingDecision {
            id: id.clone(),
            deadline_at_secs: now_secs + self.timeout_for_protocol(flow.protocol),
            flow,
            created_at_secs: now_secs,
        };
        self.pending_by_flow.insert(key, id.clone());
        self.pending.insert(id, decision.clone());
        counter!("logiguard.pending.created", "protocol" => proto_str).increment(1);
        gauge!("logiguard.pending.decisions").set(self.pending.len() as f64);
        DecisionOutcome::Pending(decision)
    }

    pub fn resolve_pending(
        &mut self,
        pending_id: &str,
        action: RuleAction,
        egress_id: Option<String>,
    ) -> Option<RuleAction> {
        if let Some(decision) = self.pending.remove(pending_id) {
            let key = FlowKey::from(&decision.flow);
            self.pending_by_flow.remove(&key);
            self.resolved
                .insert(pending_id.to_string(), (action.clone(), egress_id));
            let action_str = match &action {
                RuleAction::Allow => "allow",
                RuleAction::Deny => "deny",
                RuleAction::Ask => "ask",
                RuleAction::Route => "route",
            };
            counter!("logiguard.pending.resolved", "action" => action_str).increment(1);
            gauge!("logiguard.pending.decisions").set(self.pending.len() as f64);
            Some(action)
        } else {
            None
        }
    }

    pub fn is_pending(&self, pending_id: &str) -> bool {
        self.pending.contains_key(pending_id)
    }

    /// Returns `(action, egress_id)` for the resolved pending, consuming the entry.
    pub fn take_resolved(&mut self, pending_id: &str) -> Option<(RuleAction, Option<String>)> {
        self.resolved.remove(pending_id)
    }

    pub fn expire_timeouts(&mut self, now_secs: u64) -> Vec<String> {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter_map(|(k, v)| (v.deadline_at_secs <= now_secs).then(|| k.clone()))
            .collect();
        let count = expired.len() as u64;
        for id in &expired {
            if let Some(decision) = self.pending.remove(id) {
                self.pending_by_flow.remove(&FlowKey::from(&decision.flow));
            }
        }
        if count > 0 {
            counter!("logiguard.pending.expired").increment(count);
            gauge!("logiguard.pending.decisions").set(self.pending.len() as f64);
        }
        expired
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn list_pending(&self) -> Vec<PendingDecision> {
        let mut items = self.pending.values().cloned().collect::<Vec<_>>();
        items.sort_by(|a, b| {
            a.created_at_secs
                .cmp(&b.created_at_secs)
                .then(a.id.cmp(&b.id))
        });
        items
    }

    /// Reload pending decisions from persistent storage (called at daemon startup).
    /// Advances `next_id` past any restored ids so no collision occurs.
    pub fn restore_pending(&mut self, decisions: Vec<PendingDecision>) {
        for d in decisions {
            if let Some(n) =
                d.id.strip_prefix("pending-")
                    .and_then(|s| s.parse::<u64>().ok())
            {
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
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: Some("example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
            tcp_syn: false,
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
        let id1 = match &out1 {
            DecisionOutcome::Pending(p) => p.id.clone(),
            _ => panic!(),
        };

        // Same flow key, different src_port / domain variance — still deduped.
        let mut flow2 = mk_flow();
        flow2.destination_domain = None; // domain not inferred on this packet
        let out2 = engine.register_unknown_flow(flow2, 1);
        let id2 = match &out2 {
            DecisionOutcome::Pending(p) => p.id.clone(),
            _ => panic!(),
        };

        assert_eq!(id1, id2, "second packet should reuse the existing pending");
        assert_eq!(engine.pending_count(), 1, "only one pending should exist");
    }

    #[test]
    fn unknown_then_named_packet_reuses_and_upgrades_pending() {
        // Reproduces the duplicate-dialog bug: first packet loses the
        // /proc/net/tcp race (process_name=None), retransmit wins it
        // (process_name=Some("electron")). Both packets must collapse to a
        // single pending and the pending must end up carrying the real name.
        let mut engine = DecisionEngine::new(100, 100, OverflowPolicy::DenyNew);
        let mut first = mk_flow();
        first.process_name = None;
        first.destination_domain = None;
        let out1 = engine.register_unknown_flow(first, 0);
        let id1 = match out1 {
            DecisionOutcome::Pending(p) => p.id,
            _ => panic!("expected pending"),
        };

        let second = mk_flow();
        let out2 = engine.register_unknown_flow(second, 1);
        let pending2 = match out2 {
            DecisionOutcome::Pending(p) => p,
            _ => panic!("expected pending"),
        };

        assert_eq!(
            pending2.id, id1,
            "retransmit must reuse the existing pending"
        );
        assert_eq!(
            engine.pending_count(),
            1,
            "no second pending should be created"
        );
        assert_eq!(pending2.flow.process_name.as_deref(), Some("curl"));
        assert_eq!(
            pending2.flow.destination_domain.as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn named_then_unknown_packet_reuses_pending() {
        // Reverse order of the upgrade case: the existing pending already has
        // a process name, a later packet without one must still dedup.
        let mut engine = DecisionEngine::new(100, 100, OverflowPolicy::DenyNew);
        let out1 = engine.register_unknown_flow(mk_flow(), 0);
        let id1 = match out1 {
            DecisionOutcome::Pending(p) => p.id,
            _ => panic!("expected pending"),
        };

        let mut second = mk_flow();
        second.process_name = None;
        let out2 = engine.register_unknown_flow(second, 1);
        let pending2 = match out2 {
            DecisionOutcome::Pending(p) => p,
            _ => panic!("expected pending"),
        };

        assert_eq!(pending2.id, id1);
        assert_eq!(engine.pending_count(), 1);
        assert_eq!(pending2.flow.process_name.as_deref(), Some("curl"));
    }

    #[test]
    fn distinct_named_processes_to_same_destination_are_not_deduped() {
        // Chrome and Firefox both opening google.com:443 at the same moment
        // must remain two independent decisions; the upgrade fallback must
        // never collapse them.
        let mut engine = DecisionEngine::new(100, 100, OverflowPolicy::DenyNew);
        let mut chrome = mk_flow();
        chrome.process_name = Some("chrome".to_string());
        let mut firefox = mk_flow();
        firefox.process_name = Some("firefox".to_string());

        let out1 = engine.register_unknown_flow(chrome, 0);
        let out2 = engine.register_unknown_flow(firefox, 0);
        let id1 = match out1 {
            DecisionOutcome::Pending(p) => p.id,
            _ => panic!("expected pending"),
        };
        let id2 = match out2 {
            DecisionOutcome::Pending(p) => p.id,
            _ => panic!("expected pending"),
        };
        assert_ne!(id1, id2);
        assert_eq!(engine.pending_count(), 2);
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
        let id = match out {
            DecisionOutcome::Pending(p) => p.id,
            _ => panic!(),
        };
        engine.resolve_pending(&id, RuleAction::Allow, None);

        // After resolve, the same flow should create a new pending (not deduplicate).
        let out2 = engine.register_unknown_flow(mk_flow(), 1);
        let id2 = match out2 {
            DecisionOutcome::Pending(p) => p.id,
            _ => panic!(),
        };
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
        let resolved = engine.resolve_pending(&id, RuleAction::Allow, None);
        assert_eq!(resolved, Some(RuleAction::Allow));
        assert!(!engine.is_pending(&id));
        assert_eq!(engine.take_resolved(&id), Some((RuleAction::Allow, None)));
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
