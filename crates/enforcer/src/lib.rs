pub mod nfqueue;

use std::collections::HashMap;
use std::io::Write;
use std::process::Stdio;

use core_types::{FlowContext, RuleAction, TransportProtocol};
use flow_classifier::{Classifier, RawPacket};

// ---------------------------------------------------------------------------
// Packet event — raw input from the network layer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PacketEvent {
    pub flow_id: String,
    pub raw: RawPacket,
}

// ---------------------------------------------------------------------------
// Verdict types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RouteTarget {
    Tun(String),
    Device(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementVerdict {
    Allow,
    Deny,
    Route { target: RouteTarget },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedVerdict {
    pub flow_id: String,
    pub verdict: EnforcementVerdict,
    pub fwmark: Option<u32>,
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

pub trait VerdictSink {
    fn apply(&mut self, verdict: AppliedVerdict) -> Result<(), String>;
}

pub trait PacketSource {
    fn next_packet(&mut self) -> Option<PacketEvent>;
}

/// Decision returned by `FlowRegistrar` for a classified flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowDecision {
    Immediate(RuleAction),
    Pending { id: String, deadline_at_secs: u64 },
}

/// Registers a classified flow and returns an immediate or pending decision.
/// Implemented by `ControlService` in the daemon.
pub trait FlowRegistrar {
    fn register(&mut self, flow: FlowContext, now_secs: u64) -> FlowDecision;
}

// ---------------------------------------------------------------------------
// PacketProcessor — wires source → classifier → registrar → sink
// ---------------------------------------------------------------------------

pub struct PacketProcessor<PS, C, VS, FR> {
    source: PS,
    classifier: C,
    sink: VS,
    registrar: FR,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResult {
    pub flow_id: String,
    pub verdict: EnforcementVerdict,
    pub decision: FlowDecision,
}

impl<PS, C, VS, FR> PacketProcessor<PS, C, VS, FR>
where
    PS: PacketSource,
    C: Classifier,
    VS: VerdictSink,
    FR: FlowRegistrar,
{
    pub fn new(source: PS, classifier: C, sink: VS, registrar: FR) -> Self {
        Self { source, classifier, sink, registrar }
    }

    /// Process one packet. Returns `None` when the source is exhausted.
    pub fn process_next(&mut self, now_secs: u64) -> Option<ProcessResult> {
        let event = self.source.next_packet()?;
        let flow = self.classifier.classify(&event.raw);
        let decision = self.registrar.register(flow, now_secs);

        let verdict = match &decision {
            FlowDecision::Immediate(RuleAction::Allow) => EnforcementVerdict::Allow,
            // Deny rule, Ask without resolution, or pending queue overflow all result in a drop.
            FlowDecision::Immediate(RuleAction::Deny)
            | FlowDecision::Immediate(RuleAction::Ask)
            | FlowDecision::Pending { .. } => EnforcementVerdict::Deny,
        };

        let _ = self.sink.apply(AppliedVerdict {
            flow_id: event.flow_id.clone(),
            verdict: verdict.clone(),
            fwmark: None,
        });

        Some(ProcessResult { flow_id: event.flow_id, verdict, decision })
    }
}

// ---------------------------------------------------------------------------
// Mark allocator (for routing verdicts)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MarkAllocator {
    next_mark: u32,
    marks_by_target: HashMap<RouteTarget, u32>,
}

impl MarkAllocator {
    pub fn new() -> Self {
        Self { next_mark: 1, marks_by_target: HashMap::new() }
    }

    pub fn mark_for_target(&mut self, target: &RouteTarget) -> u32 {
        if let Some(mark) = self.marks_by_target.get(target) {
            *mark
        } else {
            let mark = self.next_mark;
            self.next_mark += 1;
            self.marks_by_target.insert(target.clone(), mark);
            mark
        }
    }
}

// ---------------------------------------------------------------------------
// DryRunEnforcer (used by daemon before nftables is available)
// ---------------------------------------------------------------------------

pub struct DryRunEnforcer<S: VerdictSink> {
    sink: S,
    allocator: MarkAllocator,
}

impl<S: VerdictSink> DryRunEnforcer<S> {
    pub fn new(sink: S) -> Self {
        Self { sink, allocator: MarkAllocator::new() }
    }

    pub fn apply_verdict(
        &mut self,
        flow_id: &str,
        verdict: EnforcementVerdict,
    ) -> Result<(), String> {
        let fwmark = match &verdict {
            EnforcementVerdict::Route { target } => Some(self.allocator.mark_for_target(target)),
            EnforcementVerdict::Allow | EnforcementVerdict::Deny => None,
        };
        self.sink.apply(AppliedVerdict { flow_id: flow_id.to_string(), verdict, fwmark })
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }
}

// ---------------------------------------------------------------------------
// Nftables bootstrap — sets up/tears down the NFQUEUE interception rules
// ---------------------------------------------------------------------------

pub trait NftablesBootstrap {
    fn setup(&self, queue_num: u16) -> Result<(), String>;
    fn teardown(&self) -> Result<(), String>;
}

pub struct SystemNftablesBootstrap;

impl NftablesBootstrap for SystemNftablesBootstrap {
    fn setup(&self, queue_num: u16) -> Result<(), String> {
        // Idempotent: tear down first, ignore errors (table may not exist yet).
        let _ = self.teardown();
        let script = format!(
            "add table inet logiguard\n\
             add chain inet logiguard output {{ type filter hook output priority 0; policy accept; }}\n\
             add rule inet logiguard output queue num {queue_num}\n\
             add chain inet logiguard forward {{ type filter hook forward priority 0; policy accept; }}\n\
             add rule inet logiguard forward queue num {queue_num}\n"
        );
        run_nft_script(&script)
    }

    fn teardown(&self) -> Result<(), String> {
        run_nft_script("delete table inet logiguard\n")
    }
}

fn run_nft_script(script: &str) -> Result<(), String> {
    let mut child = std::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn nft: {e}"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("nft stdin write: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("nft wait: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("nft exited with {status}"))
    }
}

// ---------------------------------------------------------------------------
// Test fakes (pub so downstream crates can use them too)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct FakeBootstrap {
    pub setup_count: std::cell::Cell<u32>,
    pub teardown_count: std::cell::Cell<u32>,
    pub fail: bool,
}

impl NftablesBootstrap for FakeBootstrap {
    fn setup(&self, _queue_num: u16) -> Result<(), String> {
        self.setup_count.set(self.setup_count.get() + 1);
        if self.fail { Err("fake setup failure".to_string()) } else { Ok(()) }
    }
    fn teardown(&self) -> Result<(), String> {
        self.teardown_count.set(self.teardown_count.get() + 1);
        if self.fail { Err("fake teardown failure".to_string()) } else { Ok(()) }
    }
}

#[derive(Debug, Default)]
pub struct RecordingSink {
    pub applied: Vec<AppliedVerdict>,
}

impl VerdictSink for RecordingSink {
    fn apply(&mut self, verdict: AppliedVerdict) -> Result<(), String> {
        self.applied.push(verdict);
        Ok(())
    }
}

pub struct FakePacketSource {
    pub packets: Vec<PacketEvent>,
}

impl FakePacketSource {
    pub fn new(packets: Vec<PacketEvent>) -> Self {
        Self { packets }
    }
}

impl PacketSource for FakePacketSource {
    fn next_packet(&mut self) -> Option<PacketEvent> {
        if self.packets.is_empty() { None } else { Some(self.packets.remove(0)) }
    }
}

pub struct FakeFlowRegistrar {
    pub decisions: Vec<FlowDecision>,
}

impl FakeFlowRegistrar {
    pub fn new(decisions: Vec<FlowDecision>) -> Self {
        Self { decisions }
    }
}

impl FlowRegistrar for FakeFlowRegistrar {
    fn register(&mut self, _flow: FlowContext, _now_secs: u64) -> FlowDecision {
        if self.decisions.is_empty() {
            FlowDecision::Immediate(RuleAction::Deny)
        } else {
            self.decisions.remove(0)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::TransportProtocol;
    use flow_classifier::{FakeClassifier, RawPacket};

    fn raw_packet() -> RawPacket {
        RawPacket {
            src_ip: "10.0.0.1".to_string(),
            src_port: 12345,
            dst_ip: "1.1.1.1".to_string(),
            dst_port: 443,
            protocol: TransportProtocol::Tcp,
            sni_hint: None,
            ingress_interface: None,
        }
    }

    fn classified_flow() -> FlowContext {
        FlowContext {
            process_name: Some("curl".to_string()),
            destination_ip: "1.1.1.1".to_string(),
            destination_domain: Some("example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            device_label: None,
        }
    }

    fn event(id: &str) -> PacketEvent {
        PacketEvent { flow_id: id.to_string(), raw: raw_packet() }
    }

    fn processor(
        events: Vec<PacketEvent>,
        decisions: Vec<FlowDecision>,
    ) -> PacketProcessor<FakePacketSource, FakeClassifier, RecordingSink, FakeFlowRegistrar> {
        PacketProcessor::new(
            FakePacketSource::new(events),
            FakeClassifier { result: classified_flow() },
            RecordingSink::default(),
            FakeFlowRegistrar::new(decisions),
        )
    }

    #[test]
    fn allow_rule_applies_allow_verdict() {
        let mut p = processor(
            vec![event("f1")],
            vec![FlowDecision::Immediate(RuleAction::Allow)],
        );
        let result = p.process_next(1000).expect("result");
        assert_eq!(result.verdict, EnforcementVerdict::Allow);
        assert_eq!(result.flow_id, "f1");
    }

    #[test]
    fn deny_rule_applies_deny_verdict() {
        let mut p = processor(
            vec![event("f2")],
            vec![FlowDecision::Immediate(RuleAction::Deny)],
        );
        let result = p.process_next(1000).expect("result");
        assert_eq!(result.verdict, EnforcementVerdict::Deny);
    }

    #[test]
    fn unknown_flow_creates_pending_and_drops_packet() {
        let mut p = processor(
            vec![event("f3")],
            vec![FlowDecision::Pending {
                id: "p1".to_string(),
                deadline_at_secs: 1100,
            }],
        );
        let result = p.process_next(1000).expect("result");
        assert_eq!(result.verdict, EnforcementVerdict::Deny);
        assert!(matches!(result.decision, FlowDecision::Pending { .. }));
    }

    #[test]
    fn exhausted_source_returns_none() {
        let mut p = processor(vec![], vec![]);
        assert!(p.process_next(1000).is_none());
    }

    #[test]
    fn sink_receives_verdict_with_correct_flow_id() {
        let mut p = processor(
            vec![event("f4")],
            vec![FlowDecision::Immediate(RuleAction::Allow)],
        );
        p.process_next(1000);
        assert_eq!(p.sink.applied.len(), 1);
        assert_eq!(p.sink.applied[0].flow_id, "f4");
        assert_eq!(p.sink.applied[0].verdict, EnforcementVerdict::Allow);
    }

    // --- DryRunEnforcer / MarkAllocator tests (kept from previous iteration) ---

    #[test]
    fn deny_verdict_has_no_mark() {
        let mut enforcer = DryRunEnforcer::new(RecordingSink::default());
        enforcer.apply_verdict("f1", EnforcementVerdict::Deny).expect("apply");
        assert_eq!(enforcer.sink_mut().applied[0].fwmark, None);
    }

    #[test]
    fn route_verdict_assigns_stable_mark_per_target() {
        let mut enforcer = DryRunEnforcer::new(RecordingSink::default());
        let target = RouteTarget::Tun("tun0".to_string());
        enforcer.apply_verdict("f1", EnforcementVerdict::Route { target: target.clone() }).expect("apply");
        enforcer.apply_verdict("f2", EnforcementVerdict::Route { target: target.clone() }).expect("apply");
        let m1 = enforcer.sink_mut().applied[0].fwmark.expect("mark1");
        let m2 = enforcer.sink_mut().applied[1].fwmark.expect("mark2");
        assert_eq!(m1, m2);
    }

    #[test]
    fn different_targets_get_different_marks() {
        let mut enforcer = DryRunEnforcer::new(RecordingSink::default());
        enforcer.apply_verdict("f1", EnforcementVerdict::Route { target: RouteTarget::Tun("tun0".to_string()) }).expect("apply");
        enforcer.apply_verdict("f2", EnforcementVerdict::Route { target: RouteTarget::Device("eth1".to_string()) }).expect("apply");
        let m1 = enforcer.sink_mut().applied[0].fwmark.expect("mark1");
        let m2 = enforcer.sink_mut().applied[1].fwmark.expect("mark2");
        assert_ne!(m1, m2);
    }

    // --- NftablesBootstrap tests ---

    #[test]
    fn fake_bootstrap_setup_records_call() {
        let b = FakeBootstrap::default();
        assert!(b.setup(0).is_ok());
        assert_eq!(b.setup_count.get(), 1);
        assert_eq!(b.teardown_count.get(), 0);
    }

    #[test]
    fn fake_bootstrap_teardown_records_call() {
        let b = FakeBootstrap::default();
        assert!(b.teardown().is_ok());
        assert_eq!(b.teardown_count.get(), 1);
    }

    #[test]
    fn fake_bootstrap_propagates_failure() {
        let b = FakeBootstrap { fail: true, ..Default::default() };
        assert!(b.setup(0).is_err());
        assert!(b.teardown().is_err());
    }
}
