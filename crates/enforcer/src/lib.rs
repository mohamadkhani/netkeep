use std::collections::HashMap;

use core_types::FlowContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvent {
    pub flow_id: String,
    pub flow: FlowContext,
}

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

pub trait VerdictSink {
    fn apply(&mut self, verdict: AppliedVerdict) -> Result<(), String>;
}

pub trait PacketSource {
    fn next_packet(&mut self) -> Option<PacketEvent>;
}

#[derive(Debug, Default)]
pub struct MarkAllocator {
    next_mark: u32,
    marks_by_target: HashMap<RouteTarget, u32>,
}

impl MarkAllocator {
    pub fn new() -> Self {
        Self {
            // Reserve mark 0 for "no override"
            next_mark: 1,
            marks_by_target: HashMap::new(),
        }
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

pub struct DryRunEnforcer<S: VerdictSink> {
    sink: S,
    allocator: MarkAllocator,
}

impl<S: VerdictSink> DryRunEnforcer<S> {
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            allocator: MarkAllocator::new(),
        }
    }

    pub fn apply_verdict(
        &mut self,
        event: &PacketEvent,
        verdict: EnforcementVerdict,
    ) -> Result<(), String> {
        let fwmark = match &verdict {
            EnforcementVerdict::Route { target } => Some(self.allocator.mark_for_target(target)),
            EnforcementVerdict::Allow | EnforcementVerdict::Deny => None,
        };
        self.sink.apply(AppliedVerdict {
            flow_id: event.flow_id.clone(),
            verdict,
            fwmark,
        })
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
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

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::TransportProtocol;

    fn event(flow_id: &str) -> PacketEvent {
        PacketEvent {
            flow_id: flow_id.to_string(),
            flow: FlowContext {
                process_name: Some("curl".to_string()),
                destination_ip: "1.1.1.1".to_string(),
                destination_domain: Some("example.com".to_string()),
                protocol: TransportProtocol::Tcp,
            },
        }
    }

    #[test]
    fn deny_verdict_has_no_mark() {
        let sink = RecordingSink::default();
        let mut enforcer = DryRunEnforcer::new(sink);
        let e = event("f1");
        enforcer
            .apply_verdict(&e, EnforcementVerdict::Deny)
            .expect("apply");
        assert_eq!(enforcer.sink_mut().applied.len(), 1);
        assert_eq!(enforcer.sink_mut().applied[0].fwmark, None);
    }

    #[test]
    fn route_verdict_assigns_stable_mark_per_target() {
        let sink = RecordingSink::default();
        let mut enforcer = DryRunEnforcer::new(sink);
        let e1 = event("f1");
        let e2 = event("f2");
        let target = RouteTarget::Tun("tun0".to_string());
        enforcer
            .apply_verdict(
                &e1,
                EnforcementVerdict::Route {
                    target: target.clone(),
                },
            )
            .expect("apply");
        enforcer
            .apply_verdict(
                &e2,
                EnforcementVerdict::Route {
                    target: target.clone(),
                },
            )
            .expect("apply");
        let m1 = enforcer.sink_mut().applied[0].fwmark.expect("mark1");
        let m2 = enforcer.sink_mut().applied[1].fwmark.expect("mark2");
        assert_eq!(m1, m2);
    }

    #[test]
    fn different_targets_get_different_marks() {
        let sink = RecordingSink::default();
        let mut enforcer = DryRunEnforcer::new(sink);
        let e1 = event("f1");
        let e2 = event("f2");
        enforcer
            .apply_verdict(
                &e1,
                EnforcementVerdict::Route {
                    target: RouteTarget::Tun("tun0".to_string()),
                },
            )
            .expect("apply");
        enforcer
            .apply_verdict(
                &e2,
                EnforcementVerdict::Route {
                    target: RouteTarget::Device("eth1".to_string()),
                },
            )
            .expect("apply");
        let m1 = enforcer.sink_mut().applied[0].fwmark.expect("mark1");
        let m2 = enforcer.sink_mut().applied[1].fwmark.expect("mark2");
        assert_ne!(m1, m2);
    }
}

