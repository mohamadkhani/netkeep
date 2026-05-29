use control_api::{validate_request, ControlRequest, ControlResponse, PushNotification};
use core_types::{Egress, FlowContext, FlowEvent, FlowState, RouteTarget, RuleAction};
use decision_engine::{DecisionEngine, DecisionOutcome, OverflowPolicy};
use enforcer::{FlowDecision, FlowRegistrar};
use metrics::{counter, histogram};
use policy_engine::resolve_action;
use state_store::Repository;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

pub struct ControlService<R: Repository> {
    repo: R,
    decision_engine: DecisionEngine,
    health_config: HealthConfig,
    /// Wall-clock seconds, updated by `tick()`. Used for event timestamps.
    now_secs: u64,
    event_counter: u64,
    /// Broadcast channel for sending push notifications to subscribers
    notification_tx: tokio::sync::broadcast::Sender<PushNotification>,
    /// NFQUEUE state (enabled + queue number if active)
    nfqueue_enabled: AtomicBool,
    nfqueue_num: Option<u16>,
    /// Lazily install and return the fwmark for a RouteTarget.
    /// Set by the daemon to call `ensure_route_mark`; None in tests.
    route_mark_fn: Option<Box<dyn Fn(&RouteTarget) -> Option<u32> + Send>>,
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

impl<R: Repository> ControlService<R> {
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
        let (notification_tx, _) = tokio::sync::broadcast::channel(500);
        Self::with_decision_engine_and_health(
            repo,
            DecisionEngine::new(pending_limit, default_timeout_secs, OverflowPolicy::DenyNew),
            health_config,
            notification_tx,
        )
    }

    pub fn with_nfqueue(repo: R, nfqueue_enabled: bool, nfqueue_num: Option<u16>) -> Self {
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
        let (notification_tx, _) = tokio::sync::broadcast::channel(500);
        Self {
            repo,
            decision_engine: DecisionEngine::new(
                pending_limit,
                default_timeout_secs,
                OverflowPolicy::DenyNew,
            ),
            health_config,
            now_secs: 0,
            event_counter: 0,
            notification_tx,
            nfqueue_enabled: AtomicBool::new(nfqueue_enabled),
            nfqueue_num,
            route_mark_fn: None,
        }
    }

    /// Set the function used to install/retrieve fwmarks for route targets.
    /// Must be called before the NFQUEUE processor starts.
    pub fn set_route_mark_fn(&mut self, f: impl Fn(&RouteTarget) -> Option<u32> + Send + 'static) {
        self.route_mark_fn = Some(Box::new(f));
    }

    pub fn with_notification_tx(
        repo: R,
        notification_tx: tokio::sync::broadcast::Sender<PushNotification>,
    ) -> Self {
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
            notification_tx,
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
        let (notification_tx, _) = tokio::sync::broadcast::channel(500);
        Self::with_decision_engine_and_health(repo, decision_engine, health_config, notification_tx)
    }

    pub fn with_decision_engine_and_health(
        repo: R,
        decision_engine: DecisionEngine,
        health_config: HealthConfig,
        notification_tx: tokio::sync::broadcast::Sender<PushNotification>,
    ) -> Self {
        Self {
            repo,
            decision_engine,
            health_config,
            now_secs: 0,
            event_counter: 0,
            notification_tx,
            nfqueue_enabled: AtomicBool::new(false),
            nfqueue_num: None,
            route_mark_fn: None,
        }
    }

    /// Called every second by the daemon timer thread.
    /// Expires timed-out pending decisions and updates the internal clock.
    pub fn tick(&mut self, now_secs: u64) {
        self.now_secs = now_secs;
        let expired_ids = self.decision_engine.expire_timeouts(now_secs);
        for id in expired_ids {
            self.repo.delete_pending(&id);
            // NEW: Send push notification for expired pending
            let _ = self
                .notification_tx
                .send(PushNotification::PendingExpired { pending_id: id });
            // Record expiry as a flow event (best-effort; we may not have full context here)
        }
    }

    /// Load pending decisions from the persistent store back into the decision engine.
    pub fn restore_pending(&mut self, decisions: Vec<core_types::PendingDecision>) {
        self.decision_engine.restore_pending(decisions);
    }

    /// Get a clone of the notification sender for subscribers.
    pub fn notification_sender(&self) -> tokio::sync::broadcast::Sender<PushNotification> {
        self.notification_tx.clone()
    }

    /// Resolve the first available `RouteTarget` for a Route action.
    /// Checks interface operstate for Device/Tun targets; Proxy targets are
    /// considered available unless the ProxyRepository marks them disabled.
    fn resolve_route_target(&self, egress_id: &Option<String>) -> Option<RouteTarget> {
        let id = egress_id.as_deref()?;
        let egress = self.repo.get_egress(id)?;
        first_available_target(&egress, &self.repo)
    }

    fn next_event_id(&mut self) -> String {
        self.event_counter += 1;
        format!("evt-{}", self.event_counter)
    }

    fn record_event(&mut self, flow: &FlowContext, state: FlowState, timestamp_secs: u64) {
        let id = self.next_event_id();
        self.repo.append_event(FlowEvent {
            id,
            process_name: flow.process_name.clone(),
            device_label: flow.device_label.clone(),
            destination_ip: flow.destination_ip.clone(),
            destination_domain: flow.destination_domain.clone(),
            protocol: flow.protocol,
            state,
            timestamp_secs,
        });
    }

    pub fn handle(&mut self, request: ControlRequest) -> ControlResponse {
        if let Err(err) = validate_request(&request) {
            return ControlResponse::Error(err);
        }

        let request_type = match &request {
            ControlRequest::AddRule(_) => "add_rule",
            ControlRequest::ListRules => "list_rules",
            ControlRequest::DeleteRule { .. } => "delete_rule",
            ControlRequest::ListPending => "list_pending",
            ControlRequest::ListFlows { .. } => "list_flows",
            ControlRequest::RegisterUnknownFlow { .. } => "register_unknown_flow",
            ControlRequest::AwaitPendingDecision { .. } => "await_pending_decision",
            ControlRequest::ResolvePending { .. } => "resolve_pending",
            ControlRequest::ResolvePendingWithRule { .. } => "resolve_pending_with_rule",
            ControlRequest::SetNfqueueEnabled { .. } => "set_nfqueue_enabled",
            ControlRequest::Health => "health",
            ControlRequest::Unlock => "unlock",
            ControlRequest::SubscribeToPending => "subscribe_to_pending",
            ControlRequest::OpenRoutedTcp { .. } => "open_routed_tcp",
            ControlRequest::ListEgresses => "list_egresses",
            ControlRequest::UpsertEgress(_) => "upsert_egress",
            ControlRequest::DeleteEgress { .. } => "delete_egress",
            ControlRequest::UpsertProxy(_) => "upsert_proxy",
            ControlRequest::DeleteProxy { .. } => "delete_proxy",
            ControlRequest::ListProxies => "list_proxies",
        };
        counter!("logiguard.control.requests", "type" => request_type).increment(1);
        let handle_start = Instant::now();

        let response = match request {
            ControlRequest::AddRule(rule) => {
                self.repo.upsert_rule(rule);
                self.sweep_pending();
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
            ControlRequest::ListFlows { limit } => {
                ControlResponse::FlowList(self.repo.list_events(limit))
            }
            ControlRequest::RegisterUnknownFlow { flow, now_secs } => {
                if let Some(resolved) = resolve_action(&self.repo.list_rules(), &flow) {
                    eprintln!(
                        "policy matched rule: id={} action={:?} process={:?}{} domain={:?} ip={}",
                        resolved.rule_id,
                        resolved.action,
                        flow.process_name,
                        flow.app_name
                            .as_deref()
                            .map(|a| format!(" ({})", a))
                            .unwrap_or_default(),
                        flow.destination_domain,
                        flow.destination_ip
                    );
                    match resolved.action {
                        RuleAction::Allow | RuleAction::Deny | RuleAction::Route => {
                            let route_target = if resolved.action == RuleAction::Route {
                                self.resolve_route_target(&resolved.egress_id)
                            } else {
                                None
                            };
                            let state = match &resolved.action {
                                RuleAction::Allow | RuleAction::Route => FlowState::Allowed,
                                RuleAction::Deny => FlowState::Denied,
                                RuleAction::Ask => unreachable!(),
                            };
                            self.record_event(&flow, state, now_secs);
                            let response = ControlResponse::ImmediateVerdict {
                                action: resolved.action,
                                route_target,
                            };
                            histogram!("logiguard.control.request.duration", "type" => request_type)
                                .record(handle_start.elapsed().as_secs_f64());
                            return response;
                        }
                        RuleAction::Ask => {}
                    }
                }
                match self
                    .decision_engine
                    .register_unknown_flow(flow.clone(), now_secs)
                {
                    DecisionOutcome::Immediate(action) => {
                        let state = if action == RuleAction::Allow {
                            FlowState::Allowed
                        } else {
                            FlowState::Denied
                        };
                        self.record_event(&flow, state, now_secs);
                        ControlResponse::ImmediateVerdict {
                            action,
                            route_target: None,
                        }
                    }
                    DecisionOutcome::Pending(p) => {
                        self.record_event(&flow, FlowState::Pending, now_secs);
                        self.repo.upsert_pending(&p);
                        // NEW: Send push notification to subscribers
                        let decision = p.clone();
                        let _ = self
                            .notification_tx
                            .send(PushNotification::PendingCreated { decision });
                        ControlResponse::PendingCreated {
                            pending_id: p.id,
                            created_at_secs: p.created_at_secs,
                            deadline_at_secs: p.deadline_at_secs,
                            protocol: p.flow.protocol,
                        }
                    }
                }
            }
            ControlRequest::AwaitPendingDecision { pending_id } => {
                if let Some((action, egress_id)) = self.decision_engine.take_resolved(&pending_id) {
                    let route_target = if action == RuleAction::Route {
                        self.resolve_route_target(&egress_id)
                    } else {
                        None
                    };
                    ControlResponse::PendingResolved {
                        action,
                        route_target,
                    }
                } else if self.decision_engine.is_pending(&pending_id) {
                    ControlResponse::PendingStillWaiting { pending_id }
                } else {
                    ControlResponse::Error("pending decision not found".to_string())
                }
            }
            ControlRequest::ResolvePending { pending_id, action } => {
                if let Some(chosen) =
                    self.decision_engine
                        .resolve_pending(&pending_id, action, None)
                {
                    self.repo.delete_pending(&pending_id);
                    let route_target = if chosen == RuleAction::Route {
                        // No rule context here — best-effort: no target
                        None
                    } else {
                        None
                    };
                    let _ = self
                        .notification_tx
                        .send(PushNotification::PendingResolved {
                            pending_id: pending_id.clone(),
                            action: chosen.clone(),
                        });
                    ControlResponse::PendingResolved {
                        action: chosen,
                        route_target,
                    }
                } else {
                    ControlResponse::Error("pending decision not found".to_string())
                }
            }
            ControlRequest::ResolvePendingWithRule {
                pending_id,
                action,
                rule,
            } => {
                // Install the rule first, then sweep: any other pending decisions
                // already in the queue that the new rule covers are auto-resolved
                // without showing additional dialogs.
                let egress_id = rule.egress_id.clone();
                self.repo.upsert_rule(rule);
                self.sweep_pending();
                if let Some(chosen) =
                    self.decision_engine
                        .resolve_pending(&pending_id, action, egress_id.clone())
                {
                    self.repo.delete_pending(&pending_id);
                    let route_target = if chosen == RuleAction::Route {
                        self.resolve_route_target(&egress_id)
                    } else {
                        None
                    };
                    let _ = self
                        .notification_tx
                        .send(PushNotification::PendingResolved {
                            pending_id: pending_id.clone(),
                            action: chosen.clone(),
                        });
                    ControlResponse::PendingResolved {
                        action: chosen,
                        route_target,
                    }
                } else {
                    ControlResponse::Error("pending decision not found".to_string())
                }
            }
            ControlRequest::SetNfqueueEnabled { enabled } => {
                self.nfqueue_enabled.store(enabled, Ordering::Relaxed);
                ControlResponse::Ok
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
                nfqueue_enabled: self.nfqueue_enabled.load(Ordering::Relaxed),
                nfqueue_num: self.nfqueue_num,
            },
            // Unlock is handled by the daemon directly (needs nftables access + console check).
            // The service just acknowledges it; the daemon does the real work.
            ControlRequest::Unlock => ControlResponse::Unlocked,
            ControlRequest::SubscribeToPending => ControlResponse::SubscriptionAck,
            ControlRequest::OpenRoutedTcp { .. } => {
                ControlResponse::Error("OpenRoutedTcp is handled by daemon runtime".to_string())
            }
            ControlRequest::ListEgresses => {
                let mut egresses = self.repo.list_egresses();
                egresses.sort_by(|a, b| a.id.cmp(&b.id));
                ControlResponse::EgressList(egresses)
            }
            ControlRequest::UpsertEgress(egress) => {
                self.repo.upsert_egress(&egress);
                ControlResponse::Ok
            }
            ControlRequest::DeleteEgress { id } => {
                if let Some(eg) = self.repo.get_egress(&id) {
                    if eg.is_system_default {
                        let response = ControlResponse::Error(
                            "cannot delete the system default egress".to_string(),
                        );
                        histogram!("logiguard.control.request.duration", "type" => request_type)
                            .record(handle_start.elapsed().as_secs_f64());
                        return response;
                    }
                }
                if self.repo.delete_egress(&id) {
                    ControlResponse::Ok
                } else {
                    ControlResponse::Error("egress not found".to_string())
                }
            }
            ControlRequest::UpsertProxy(proxy) => {
                self.repo.upsert_proxy(&proxy);
                ControlResponse::Ok
            }
            ControlRequest::DeleteProxy { id } => {
                if self.repo.delete_proxy(&id) {
                    ControlResponse::Ok
                } else {
                    ControlResponse::Error("proxy not found".to_string())
                }
            }
            ControlRequest::ListProxies => {
                let mut proxies = self.repo.list_proxies();
                proxies.sort_by(|a, b| a.id.cmp(&b.id));
                ControlResponse::ProxyList(proxies)
            }
        };
        histogram!("logiguard.control.request.duration", "type" => request_type)
            .record(handle_start.elapsed().as_secs_f64());
        response
    }

    /// Re-evaluate all pending decisions against the current rule set.
    /// Any pending flow that now matches a non-Ask rule is auto-resolved immediately,
    /// so the user is never shown a dialog for a flow already covered by a rule they
    /// just created (e.g. "allow chromium → any" sweeps all other chromium pendings).
    fn sweep_pending(&mut self) {
        let rules = self.repo.list_rules();
        let pending = self.decision_engine.list_pending();
        for p in pending {
            if let Some(resolved) = resolve_action(&rules, &p.flow) {
                match resolved.action {
                    RuleAction::Ask => continue,
                    action => {
                        eprintln!(
                            "sweep_pending: auto-resolving {} ({:?} → {:?})",
                            p.id, p.flow.process_name, action
                        );
                        self.decision_engine.resolve_pending(
                            &p.id,
                            action.clone(),
                            resolved.egress_id.clone(),
                        );
                        self.repo.delete_pending(&p.id);
                        let _ = self
                            .notification_tx
                            .send(PushNotification::PendingResolved {
                                pending_id: p.id,
                                action,
                            });
                    }
                }
            }
        }
    }
}

/// Walk an egress's target list and return the first one that is currently
/// available. For Device/Tun targets availability is checked via
/// `/sys/class/net/<name>/operstate`; Proxy targets are available when the
/// `ProxyRepository` says `enabled == true`.
fn first_available_target<R: state_store::ProxyRepository>(
    egress: &Egress,
    repo: &R,
) -> Option<RouteTarget> {
    for target in &egress.targets {
        let available = match target {
            RouteTarget::Tun(name) | RouteTarget::Device(name) => {
                let state = std::fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
                    .unwrap_or_default();
                let s = state.trim();
                s == "up" || s == "unknown"
            }
            RouteTarget::Proxy(id) => repo.get_proxy(id).map(|p| p.enabled).unwrap_or(false),
        };
        if available {
            return Some(target.clone());
        }
    }
    None
}

/// Newtype wrapper that lets a shared `ControlService` be used as a `FlowRegistrar`
/// across threads (e.g., handed to the nfqueue processor thread).
pub struct SharedService<R: Repository>(pub std::sync::Arc<std::sync::Mutex<ControlService<R>>>);

impl<R: Repository> FlowRegistrar for SharedService<R> {
    fn register(&mut self, flow: FlowContext, now_secs: u64) -> FlowDecision {
        self.0
            .lock()
            .expect("service lock poisoned")
            .register(flow, now_secs)
    }

    fn route_mark(&mut self, target: &RouteTarget) -> Option<u32> {
        self.0
            .lock()
            .expect("service lock poisoned")
            .route_mark(target)
    }
}

impl<R: Repository> FlowRegistrar for ControlService<R> {
    fn register(&mut self, flow: FlowContext, now_secs: u64) -> FlowDecision {
        if let Some(resolved) = resolve_action(&self.repo.list_rules(), &flow) {
            eprintln!(
                "policy matched rule: id={} action={:?} process={:?}{} domain={:?} ip={}",
                resolved.rule_id,
                resolved.action,
                flow.process_name,
                flow.app_name
                    .as_deref()
                    .map(|a| format!(" ({})", a))
                    .unwrap_or_default(),
                flow.destination_domain,
                flow.destination_ip
            );
            match resolved.action {
                RuleAction::Allow | RuleAction::Deny | RuleAction::Route => {
                    let action_str = match resolved.action {
                        RuleAction::Allow => "allow",
                        RuleAction::Deny => "deny",
                        RuleAction::Route => "route",
                        RuleAction::Ask => unreachable!(),
                    };
                    counter!("logiguard.control.immediate_verdicts", "action" => action_str)
                        .increment(1);
                    let route_target = if resolved.action == RuleAction::Route {
                        self.resolve_route_target(&resolved.egress_id)
                    } else {
                        None
                    };
                    let state = match &resolved.action {
                        RuleAction::Allow | RuleAction::Route => FlowState::Allowed,
                        RuleAction::Deny => FlowState::Denied,
                        RuleAction::Ask => unreachable!(),
                    };
                    self.record_event(&flow, state, now_secs);
                    return FlowDecision::Immediate(resolved.action, route_target);
                }
                RuleAction::Ask => {}
            }
        }
        match self
            .decision_engine
            .register_unknown_flow(flow.clone(), now_secs)
        {
            DecisionOutcome::Immediate(action) => {
                let state = match &action {
                    RuleAction::Allow | RuleAction::Route => FlowState::Allowed,
                    RuleAction::Deny | RuleAction::Ask => FlowState::Denied,
                };
                self.record_event(&flow, state, now_secs);
                FlowDecision::Immediate(action, None)
            }
            DecisionOutcome::Pending(p) => {
                counter!("logiguard.control.pending_created").increment(1);
                self.record_event(&flow, FlowState::Pending, now_secs);
                self.repo.upsert_pending(&p);
                FlowDecision::Pending {
                    id: p.id,
                    deadline_at_secs: p.deadline_at_secs,
                }
            }
        }
    }

    fn route_mark(&mut self, target: &RouteTarget) -> Option<u32> {
        self.route_mark_fn.as_ref().and_then(|f| f(target))
    }
}

#[cfg(test)]
mod tests {
    use control_api::{ControlRequest, ControlResponse};
    use core_types::{
        DestinationMatcher, FlowContext, FlowDirection, Rule, RuleAction, RuleDuration,
        TransportProtocol,
    };
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
            process_exe: None,
            destination: DestinationMatcher::DomainExact("example.com".to_string()),
            egress_id: None,
        }
    }

    fn mk_flow() -> FlowContext {
        FlowContext {
            process_name: Some("curl".to_string()),
            process_exe: None,
            app_name: None,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: Some("example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
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
        assert_eq!(
            resolved,
            ControlResponse::PendingResolved {
                action: RuleAction::Deny,
                route_target: None
            }
        );
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
        assert_eq!(
            resolved,
            ControlResponse::PendingResolved {
                action: RuleAction::Allow,
                route_target: None
            }
        );
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
                action: RuleAction::Allow,
                route_target: None,
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
        assert_eq!(
            out,
            ControlResponse::Error("pending decision not found".to_string())
        );
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
        let (tx, _) = tokio::sync::broadcast::channel(100);
        let mut service = ControlService::with_decision_engine_and_health(
            InMemoryRuleRepository::default(),
            engine,
            health,
            tx,
        );

        let mut flow = mk_flow();
        flow.protocol = TransportProtocol::Udp;
        let register = service.handle(ControlRequest::RegisterUnknownFlow { flow, now_secs: 50 });
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
        let (tx, _) = tokio::sync::broadcast::channel(100);
        let mut service = ControlService::with_decision_engine_and_health(
            InMemoryRuleRepository::default(),
            engine,
            health,
            tx,
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
                other_timeout_secs: 30,
                nfqueue_enabled: false,
                nfqueue_num: None,
            }
        );
    }

    #[test]
    fn tick_expires_timed_out_pending() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let _ = service.handle(ControlRequest::RegisterUnknownFlow {
            flow: mk_flow(),
            now_secs: 0,
        });
        // deadline is 0 + 100 = 100; tick at 101 should expire it
        service.tick(101);
        let out = service.handle(ControlRequest::ListPending);
        match out {
            ControlResponse::PendingList(items) => assert!(items.is_empty()),
            _ => panic!("expected pending list"),
        }
    }

    #[test]
    fn flow_events_recorded_on_immediate_verdict() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let mut deny_rule = mk_rule("deny-r1");
        deny_rule.action = RuleAction::Deny;
        let _ = service.handle(ControlRequest::AddRule(deny_rule));
        let _ = service.handle(ControlRequest::RegisterUnknownFlow {
            flow: mk_flow(),
            now_secs: 50,
        });
        let out = service.handle(ControlRequest::ListFlows { limit: 10 });
        match out {
            ControlResponse::FlowList(events) => {
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].state, core_types::FlowState::Denied);
            }
            _ => panic!("expected flow list"),
        }
    }

    #[test]
    fn pending_persisted_in_repo_on_register() {
        use state_store::PendingRepository;
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let _ = service.handle(ControlRequest::RegisterUnknownFlow {
            flow: mk_flow(),
            now_secs: 10,
        });
        let live = service.repo.list_live_pending(10);
        assert_eq!(live.len(), 1);
    }

    #[test]
    fn pending_removed_from_repo_on_resolve() {
        use state_store::PendingRepository;
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let reg = service.handle(ControlRequest::RegisterUnknownFlow {
            flow: mk_flow(),
            now_secs: 10,
        });
        let pid = match reg {
            ControlResponse::PendingCreated { pending_id, .. } => pending_id,
            _ => panic!(),
        };
        let _ = service.handle(ControlRequest::ResolvePending {
            pending_id: pid,
            action: RuleAction::Allow,
        });
        let live = service.repo.list_live_pending(10);
        assert!(live.is_empty());
    }
}
