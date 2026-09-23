use control_api::{validate_request, ControlRequest, ControlResponse, PushNotification};
use core_types::{
    Egress, FlowContext, FlowEvent, FlowState, ProcessPriority, RouteTarget, Rule, RuleAction,
    TransportProtocol,
};
use decision_engine::{DecisionEngine, DecisionOutcome, OverflowPolicy};
use enforcer::{FlowDecision, FlowRegistrar};
use metrics::{counter, histogram};
use policy_engine::{resolve_action, seed_priority, ResolvedRule};
use state_store::Repository;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

const POLICY_LOG_DEDUP_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PolicyLogKey {
    process_name: Option<String>,
    domain: Option<String>,
    destination_ip: String,
}

impl PolicyLogKey {
    fn from_flow(flow: &FlowContext) -> Self {
        Self {
            process_name: flow.process_name.clone(),
            domain: flow.destination_domain.clone(),
            destination_ip: flow.destination_ip.clone(),
        }
    }
}

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
    /// Suppress repeated `policy:` stderr lines for the same flow identity.
    policy_log_dedup: HashMap<PolicyLogKey, u64>,
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
            policy_log_dedup: HashMap::new(),
        }
    }

    /// Report the actual interception state. The daemon calls this after the
    /// NFQUEUE processor starts (NETKEEP_NFQUEUE set) so Health reflects
    /// reality for clients like the tray, instead of the default `false`.
    pub fn set_nfqueue_state(&mut self, enabled: bool, nfqueue_num: Option<u16>) {
        self.nfqueue_enabled.store(enabled, Ordering::Relaxed);
        self.nfqueue_num = nfqueue_num;
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
            policy_log_dedup: HashMap::new(),
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

    /// Pure rule lookup without side effects: no pending registration, no event logging.
    /// Used by the DNS forwarder to find the egress for a `(process, domain)` pair.
    /// Returns `Some((action, egress_id))` for the best matching rule, or `None`.
    pub fn lookup_rule_only(&self, flow: &FlowContext) -> Option<(RuleAction, Option<String>)> {
        let resolved = policy_engine::resolve_action(&self.repo.list_rules(), flow)?;
        Some((resolved.action, resolved.egress_id))
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
            source_port: flow.source_port,
            destination_port: flow.destination_port,
        });
    }

    fn should_log_policy_match(&mut self, flow: &FlowContext, now_secs: u64) -> bool {
        let key = PolicyLogKey::from_flow(flow);
        self.policy_log_dedup
            .retain(|_, last| now_secs.saturating_sub(*last) < POLICY_LOG_DEDUP_SECS);
        if self
            .policy_log_dedup
            .get(&key)
            .is_some_and(|last| now_secs.saturating_sub(*last) < POLICY_LOG_DEDUP_SECS)
        {
            return false;
        }
        self.policy_log_dedup.insert(key, now_secs);
        true
    }

    fn log_policy_match(&mut self, flow: &FlowContext, resolved: &ResolvedRule, now_secs: u64) {
        if !self.should_log_policy_match(flow, now_secs) {
            return;
        }
        eprintln!(
            "policy: id={} action={:?} process={:?}{} domain={:?} dst={}:{} src=:{}",
            resolved.rule_id,
            resolved.action,
            flow.process_name,
            flow.app_name
                .as_deref()
                .map(|a| format!(" ({})", a))
                .unwrap_or_default(),
            flow.destination_domain,
            flow.destination_ip,
            flow.destination_port,
            flow.source_port
        );
    }

    pub fn handle(&mut self, request: ControlRequest) -> ControlResponse {
        if let Err(err) = validate_request(&request) {
            return ControlResponse::Error(err);
        }

        let request_type = match &request {
            ControlRequest::AddRule(_) => "add_rule",
            ControlRequest::AddRuleWithProcessPriority { .. } => "add_rule",
            ControlRequest::MoveRule { .. } => "move_rule",
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
            ControlRequest::TestProxyHttp { .. } => "test_proxy_http",
            ControlRequest::TestProxyDns { .. } => "test_proxy_dns",
        };
        counter!("netkeep.control.requests", "type" => request_type).increment(1);
        let handle_start = Instant::now();

        let response = match request {
            ControlRequest::AddRule(rule) => {
                self.add_rule_with_seeded_priority(rule, ProcessPriority::High);
                self.sweep_pending();
                ControlResponse::Ok
            }
            ControlRequest::AddRuleWithProcessPriority {
                rule,
                process_priority,
            } => {
                self.add_rule_with_seeded_priority(rule, process_priority);
                self.sweep_pending();
                ControlResponse::Ok
            }
            ControlRequest::MoveRule {
                id,
                before_id,
                after_id,
            } => self.move_rule(&id, before_id.as_deref(), after_id.as_deref()),
            ControlRequest::ListRules => {
                // Preserve the repository's priority-descending order
                // — it is the actual evaluation order, and both the settings
                // table and `netkeep rules list` present rules in it.
                ControlResponse::RuleList(self.repo.list_rules())
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
                    self.log_policy_match(&flow, &resolved, now_secs);
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
                            histogram!("netkeep.control.request.duration", "type" => request_type)
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
                self.add_rule_with_seeded_priority(rule, ProcessPriority::High);
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
                        histogram!("netkeep.control.request.duration", "type" => request_type)
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
                // Enforce unique proxy names. Two distinct proxies must not share
                // a name — names are what the user sees in selectors and the
                // egress targets column, so duplicates would be ambiguous.
                let name = proxy.name.trim();
                if name.is_empty() {
                    let response =
                        ControlResponse::Error("proxy name must not be empty".to_string());
                    histogram!("netkeep.control.request.duration", "type" => request_type)
                        .record(handle_start.elapsed().as_secs_f64());
                    return response;
                }
                let name_taken = self
                    .repo
                    .list_proxies()
                    .iter()
                    .any(|p| p.id != proxy.id && p.name == proxy.name);
                if name_taken {
                    let response =
                        ControlResponse::Error(format!("proxy name '{name}' is already in use"));
                    histogram!("netkeep.control.request.duration", "type" => request_type)
                        .record(handle_start.elapsed().as_secs_f64());
                    return response;
                }
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
            ControlRequest::TestProxyHttp { proxy_id, url } => {
                match self.repo.get_proxy(&proxy_id) {
                    Some(proxy) => {
                        let timeout = std::time::Duration::from_secs(10);
                        match proxy_client::test_http_connectivity(&proxy, &url, timeout) {
                            Ok(latency_ms) => ControlResponse::ProxyTestResult {
                                success: true,
                                latency_ms,
                                error: None,
                            },
                            Err(e) => ControlResponse::ProxyTestResult {
                                success: false,
                                latency_ms: 0,
                                error: Some(e.to_string()),
                            },
                        }
                    }
                    None => ControlResponse::Error(format!("proxy '{proxy_id}' not found")),
                }
            }
            ControlRequest::TestProxyDns { proxy_id, domain } => {
                match self.repo.get_proxy(&proxy_id) {
                    Some(proxy) => {
                        let timeout = std::time::Duration::from_secs(10);
                        match proxy_client::test_dns_connectivity(&proxy, &domain, timeout) {
                            Ok(latency_ms) => ControlResponse::ProxyTestResult {
                                success: true,
                                latency_ms,
                                error: None,
                            },
                            Err(e) => ControlResponse::ProxyTestResult {
                                success: false,
                                latency_ms: 0,
                                error: Some(e.to_string()),
                            },
                        }
                    }
                    None => ControlResponse::Error(format!("proxy '{proxy_id}' not found")),
                }
            }
        };
        histogram!("netkeep.control.request.duration", "type" => request_type)
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

    /// Install a rule with its priority seeded from the restriction ladder
    ///.
    ///
    /// - New rule: seed from the ladder using `process_priority`.
    /// - Existing rule, tier unchanged: carry over the stored priority so the
    ///   edit (e.g. fixing a process name) doesn't disturb a manual
    ///   drag-reorder position. Callers send `priority: 0.0`, so the carry-over
    ///   must be explicit or the edit would drop the rule to the bottom.
    /// - Existing rule, tier changed: re-seed from the new tier's base with a
    ///   fresh creation-seq fraction. This discards the prior manual position —
    ///   intended, since the user explicitly asked for a different slot.
    ///
    /// Reordering within a tier is `MoveRule`'s job, not edit's.
    fn add_rule_with_seeded_priority(&mut self, mut rule: Rule, process_priority: ProcessPriority) {
        let existing = self.repo.get_rule(&rule.id);
        match existing {
            Some(prior) => {
                let was_high = prior.priority >= 7.0;
                let tier_changed = match process_priority {
                    ProcessPriority::High => !was_high,
                    ProcessPriority::Low => was_high,
                };
                if tier_changed {
                    let seq = self.repo.next_creation_seq();
                    rule.priority = seed_priority(&rule, seq, process_priority);
                } else {
                    rule.priority = prior.priority;
                }
                self.repo.upsert_rule(rule);
            }
            None => {
                let seq = self.repo.next_creation_seq();
                rule.priority = seed_priority(&rule, seq, process_priority);
                self.repo.upsert_rule(rule);
            }
        }
    }

    /// Reorder a rule via midpoint insertion. `before_id` is the
    /// rule that should sit above the moved rule afterwards, `after_id` the
    /// one below. Both `None` → move to the very bottom.
    fn move_rule(
        &mut self,
        id: &str,
        before_id: Option<&str>,
        after_id: Option<&str>,
    ) -> ControlResponse {
        let ordered = self.repo.list_rules(); // priority-descending
        if !ordered.iter().any(|r| r.id == id) {
            return ControlResponse::Error("rule not found".to_string());
        }
        for other in [before_id, after_id].into_iter().flatten() {
            if !ordered.iter().any(|r| r.id == other) {
                return ControlResponse::Error(format!("neighbor rule not found: {other}"));
            }
        }
        let priority_of = |rid: &str| -> f64 {
            ordered
                .iter()
                .find(|r| r.id == rid)
                .map(|r| r.priority)
                .unwrap_or(0.0)
        };
        let new_priority = match (before_id, after_id) {
            // Explicit neighbors: midpoint between them.
            (Some(before), Some(after)) => {
                let p = (priority_of(before) + priority_of(after)) / 2.0;
                if p == priority_of(before) || p == priority_of(after) || !p.is_finite() {
                    // Precision exhausted — rebalance and retry once.
                    if self.repo.rebalance_priorities().is_none() {
                        return ControlResponse::Error("priority rebalance failed".to_string());
                    }
                    let ordered = self.repo.list_rules();
                    let get = |rid: &str| {
                        ordered
                            .iter()
                            .find(|r| r.id == rid)
                            .map(|r| r.priority)
                            .unwrap_or(0.0)
                    };
                    (get(before) + get(after)) / 2.0
                } else {
                    p
                }
            }
            // Top of the table (only "after" given → above `after`, i.e. new top).
            (None, Some(_)) => {
                let top = ordered.first().map(|r| r.priority).unwrap_or(1.0);
                top + 1.0
            }
            // Bottom (before given or both None).
            _ => {
                let bottom = ordered.last().map(|r| r.priority).unwrap_or(1.0);
                (bottom - 1.0).max(0.0001)
            }
        };
        if self.repo.set_rule_priority(id, new_priority) {
            ControlResponse::Ok
        } else {
            ControlResponse::Error("rule not found".to_string())
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
            self.log_policy_match(&flow, &resolved, now_secs);
            match resolved.action {
                RuleAction::Allow | RuleAction::Deny | RuleAction::Route => {
                    let action_str = match resolved.action {
                        RuleAction::Allow => "allow",
                        RuleAction::Deny => "deny",
                        RuleAction::Route => "route",
                        RuleAction::Ask => unreachable!(),
                    };
                    counter!("netkeep.control.immediate_verdicts", "action" => action_str)
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
        // Defer unknown TLS connections classified on their SYN. The SYN
        // carries no ClientHello, so `destination_domain` is unknowable —
        // and opening the pending now would both show the user a bare IP
        // and DROP the SYN, blocking the handshake so SNI could never
        // arrive. Accept the bare handshake instead: the ClientHello is
        // re-classified (pending verdicts are never cached) and either
        // matches a rule by hostname — no dialog at all — or opens the
        // pending with the real domain. No payload flows before a real
        // verdict: the ClientHello itself is the first gated packet.
        if flow.destination_domain.is_none()
            && flow.protocol == TransportProtocol::Tcp
            && flow.destination_port == 443
            && flow.tcp_syn
        {
            counter!("netkeep.control.deferred_sni").increment(1);
            return FlowDecision::DeferSni;
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
                counter!("netkeep.control.pending_created").increment(1);
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
        DestinationMatcher, FlowContext, FlowDirection, ProcessPriority, Rule, RuleAction,
        RuleDuration, TransportProtocol,
    };
    use state_store::InMemoryRuleRepository;

    use super::{ControlService, HealthConfig, POLICY_LOG_DEDUP_SECS};
    use decision_engine::{DecisionEngine, OverflowPolicy};
    use enforcer::{FlowDecision, FlowRegistrar as _};

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
            priority: 5.0,
        }
    }

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

    // -------------------------------------------------------------------
    // SNI deferral: unknown TLS connections classified on their SYN
    // -------------------------------------------------------------------

    /// A TCP:443 SYN with no matching rule and no hostname must be DEFERRED,
    /// not turned into a pending decision. Opening the pending here would
    /// (a) show the user a bare IP — the SYN cannot carry a hostname — and
    /// (b) DROP the SYN, blocking the handshake so the ClientHello (the only
    /// packet that carries the SNI) could never arrive.
    #[test]
    fn syn_without_domain_defers_instead_of_pending() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let mut flow = mk_flow();
        flow.destination_domain = None;
        flow.tcp_syn = true;

        match service.register(flow, 1000) {
            FlowDecision::DeferSni => {}
            other => panic!("expected DeferSni, got {other:?}"),
        }
        // No pending may exist, and no IP-keyed flow event recorded.
        assert!(
            service.decision_engine.list_pending().is_empty(),
            "deferred SYN must not create a pending decision"
        );
    }

    /// When the ClientHello arrives (same connection, SNI now known), the
    /// unknown flow must open the pending WITH the hostname — so the dialog
    /// shows the domain instead of the bare IP.
    #[test]
    fn client_hello_with_domain_opens_pending_with_domain() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let hello = mk_flow(); // domain = example.com, tcp_syn = false

        match service.register(hello, 1000) {
            FlowDecision::Pending { .. } => {}
            other => panic!("expected Pending, got {other:?}"),
        }
        let pendings = service.decision_engine.list_pending();
        assert_eq!(pendings.len(), 1);
        assert_eq!(
            pendings[0].flow.destination_domain.as_deref(),
            Some("example.com"),
            "pending must carry the SNI hostname, not a bare IP"
        );
    }

    /// A deferred SYN whose domain rule already exists resolves at the
    /// ClientHello with NO pending at all — the dialog never appears
    /// ("decisions reduced" — the point of the deferral).
    #[test]
    fn deferred_syn_resolves_silently_once_domain_known() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let allow_rule = mk_rule("allow-example");
        service.handle(ControlRequest::AddRule(allow_rule.clone()));

        let mut syn = mk_flow();
        syn.destination_domain = None;
        syn.tcp_syn = true;
        assert!(matches!(
            service.register(syn, 1000),
            FlowDecision::DeferSni
        ));

        let hello = mk_flow(); // ClientHello: SNI = example.com
        match service.register(hello, 1001) {
            FlowDecision::Immediate(RuleAction::Allow, _) => {}
            other => panic!("expected silent Allow after SNI, got {other:?}"),
        }
        assert!(
            service.decision_engine.list_pending().is_empty(),
            "no dialog expected"
        );
    }

    /// Non-TLS-443 first packets keep the old behavior: pending immediately
    /// (there is no SNI to wait for on other ports/protocols).
    #[test]
    fn non_https_syn_still_pends_immediately() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let mut flow = mk_flow();
        flow.destination_domain = None;
        flow.tcp_syn = true;
        flow.destination_port = 8080;

        match service.register(flow, 1000) {
            FlowDecision::Pending { .. } => {}
            other => panic!("expected Pending on non-443, got {other:?}"),
        }
    }

    #[test]
    fn list_rules_returns_priority_descending_not_id_order() {
        // Regression: ListRules used to re-sort by id, which discarded the
        // repository's priority ordering and made the settings table appear
        // unsorted.
        let mut service = ControlService::new(InMemoryRuleRepository::default());

        // Insert so that id order and priority order disagree: "a" is the
        // lowest priority, "z" the highest.
        for (id, priority) in [("a", 1.0), ("m", 7.0), ("z", 12.0)] {
            let mut rule = mk_rule(id);
            rule.priority = priority;
            assert_eq!(
                service.handle(ControlRequest::AddRule(rule)),
                ControlResponse::Ok
            );
        }

        match service.handle(ControlRequest::ListRules) {
            ControlResponse::RuleList(rules) => {
                let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
                assert_eq!(
                    ids,
                    vec!["z", "m", "a"],
                    "expected priority-descending order"
                );
            }
            other => panic!("expected rule list, got {other:?}"),
        }
    }

    #[test]
    fn editing_a_rule_preserves_its_priority() {
        // Regression: the GPUI edit form sends `priority: 0.0` (it has no
        // priority field), and upsert_rule writes every column. Without an
        // explicit carry-over the edit would slam the rule to the bottom of
        // the ladder (the priority ladder — reordering is MoveRule's job, not edit's).
        let mut service = ControlService::new(InMemoryRuleRepository::default());

        let mut rule = mk_rule("keep-me");
        rule.destination = DestinationMatcher::DomainExact("example.com".into());
        rule.process_name = Some("firefox".into());
        assert_eq!(
            service.handle(ControlRequest::AddRule(rule)),
            ControlResponse::Ok
        );

        let seeded = match service.handle(ControlRequest::ListRules) {
            ControlResponse::RuleList(rules) => rules[0].priority,
            other => panic!("expected rule list, got {other:?}"),
        };
        assert!(
            seeded >= 11.0,
            "process+domain should seed base 11, got {seeded}"
        );

        // Edit the same id, sending priority 0.0 exactly as the UI does.
        let mut edited = mk_rule("keep-me");
        edited.destination = DestinationMatcher::DomainExact("example.com".into());
        edited.process_name = Some("firefox".into());
        edited.action = RuleAction::Deny;
        edited.priority = 0.0;
        assert_eq!(
            service.handle(ControlRequest::AddRule(edited)),
            ControlResponse::Ok
        );

        match service.handle(ControlRequest::ListRules) {
            ControlResponse::RuleList(rules) => {
                assert_eq!(rules.len(), 1);
                assert_eq!(rules[0].action, RuleAction::Deny, "edit should apply");
                assert_eq!(
                    rules[0].priority, seeded,
                    "edit must preserve the stored priority, not reset it to 0.0"
                );
            }
            other => panic!("expected rule list, got {other:?}"),
        }
    }

    #[test]
    fn editing_process_any_rule_with_flipped_tier_re_seeds_priority() {
        // the priority ladder: changing HIGH/LOW on an existing process+Any rule must
        // re-seed its priority to the new tier's base. Leaving the tier
        // alone must preserve the stored (possibly drag-reordered) priority.
        let mut service = ControlService::new(InMemoryRuleRepository::default());

        // Create a process+Any rule as High (base 7).
        let mut rule = mk_rule("flip");
        rule.destination = DestinationMatcher::Any;
        rule.process_name = Some("firefox".into());
        assert_eq!(
            service.handle(ControlRequest::AddRuleWithProcessPriority {
                rule,
                process_priority: ProcessPriority::High,
            }),
            ControlResponse::Ok
        );
        let high_priority = match service.handle(ControlRequest::ListRules) {
            ControlResponse::RuleList(r) => r[0].priority,
            other => panic!("{other:?}"),
        };
        assert!(
            (7.0..8.0).contains(&high_priority),
            "High seeds base 7, got {high_priority}"
        );

        // Edit with the SAME tier → priority carried over (simulate a typo fix).
        let mut edited_same = mk_rule("flip");
        edited_same.destination = DestinationMatcher::Any;
        edited_same.process_name = Some("firefox-edited".into());
        edited_same.priority = 0.0;
        assert_eq!(
            service.handle(ControlRequest::AddRuleWithProcessPriority {
                rule: edited_same,
                process_priority: ProcessPriority::High,
            }),
            ControlResponse::Ok
        );
        assert_eq!(
            match service.handle(ControlRequest::ListRules) {
                ControlResponse::RuleList(r) => r[0].priority,
                other => panic!("{other:?}"),
            },
            high_priority,
            "unchanged tier must preserve stored priority"
        );

        // Edit with the FLIPPED tier (High → Low) → re-seed to base 2.
        let mut edited_flip = mk_rule("flip");
        edited_flip.destination = DestinationMatcher::Any;
        edited_flip.process_name = Some("firefox".into());
        edited_flip.priority = 0.0;
        assert_eq!(
            service.handle(ControlRequest::AddRuleWithProcessPriority {
                rule: edited_flip,
                process_priority: ProcessPriority::Low,
            }),
            ControlResponse::Ok
        );
        let low_priority = match service.handle(ControlRequest::ListRules) {
            ControlResponse::RuleList(r) => r[0].priority,
            other => panic!("{other:?}"),
        };
        assert!(
            (2.0..3.0).contains(&low_priority),
            "flipped to Low must re-seed base 2, got {low_priority}"
        );
    }

    #[test]
    fn policy_log_dedup_by_process_domain_ip() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let flow = mk_flow();
        assert!(service.should_log_policy_match(&flow, 100));

        let mut same_conn = mk_flow();
        same_conn.source_port = 60000;
        assert!(!service.should_log_policy_match(&same_conn, 150));

        let mut other_domain = mk_flow();
        other_domain.destination_domain = Some("other.example.com".to_string());
        assert!(service.should_log_policy_match(&other_domain, 150));

        assert!(service.should_log_policy_match(&flow, 100 + POLICY_LOG_DEDUP_SECS + 1));
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
