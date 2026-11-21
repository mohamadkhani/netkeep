use control_api::{
    validate_request, ControlRequest, ControlResponse, EgressAlertRecord, PushNotification,
};
use core_types::{
    Egress, EgressAlert, FlowContext, FlowEvent, FlowState, ProcessPriority, RouteTarget, Rule,
    RuleAction, TransportProtocol,
};
use decision_engine::{DecisionEngine, DecisionOutcome, OverflowPolicy};
use enforcer::{FlowDecision, FlowRegistrar};
use metrics::{counter, histogram};
use policy_engine::{resolve_action, seed_priority, ResolvedRule};
use state_store::Repository;
use std::collections::{HashMap, HashSet};
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

/// Callback returning the fwmark to use for a `RouteTarget`, if any.
type RouteMarkFn = Box<dyn Fn(&RouteTarget) -> Option<u32> + Send>;

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
    route_mark_fn: Option<RouteMarkFn>,
    /// Version of egress/proxy configuration used by NFQUEUE's verdict cache.
    routing_revision: u64,
    /// Suppress repeated `policy:` stderr lines for the same flow identity.
    policy_log_dedup: HashMap<PolicyLogKey, u64>,
    /// Recent data-path failures, one entry per (kind, target).
    egress_alerts: Vec<EgressAlertEntry>,
    /// Pending ids whose `Pending` flow event is already recorded. A
    /// retransmission carries the same id, and the row may already be past its
    /// deadline while `tick` has not swept it yet, so neither "is it live" nor
    /// "is it still in the table" answers whether the event exists.
    pending_events_recorded: HashSet<String>,
}

/// Stored alert plus when it was last published to subscribers.
#[derive(Debug, Clone)]
struct EgressAlertEntry {
    record: EgressAlertRecord,
    last_emit_secs: u64,
    /// Timestamps inside the recent window, oldest first.
    recent: Vec<u64>,
}

/// Window used for the tray's "sustained failure" signal.
const ALERT_RECENT_WINDOW_SECS: u64 = 300;

/// How often the same (kind, target) failure may be published. The proxy in a
/// reconnect loop can fail thousands of times an hour; the point is to tell the
/// user what is broken, not to stream every occurrence.
const ALERT_EMIT_INTERVAL_SECS: u64 = 30;
/// How many distinct failures the status endpoint keeps.
const ALERT_HISTORY_MAX: usize = 20;

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
            routing_revision: 0,
            policy_log_dedup: HashMap::new(),
            egress_alerts: Vec::new(),
            pending_events_recorded: HashSet::new(),
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
            routing_revision: 0,
            policy_log_dedup: HashMap::new(),
            egress_alerts: Vec::new(),
            pending_events_recorded: HashSet::new(),
        }
    }

    /// Called every second by the daemon timer thread.
    /// Expires timed-out pending decisions and updates the internal clock.
    pub fn tick(&mut self, now_secs: u64) {
        self.now_secs = now_secs;
        // Age the alert window here rather than only when a new failure
        // arrives. Otherwise the last computed `recent_count` never falls, and
        // the tray stays amber forever after three failures even once the path
        // recovers.
        for entry in &mut self.egress_alerts {
            entry
                .recent
                .retain(|t| now_secs.saturating_sub(*t) <= ALERT_RECENT_WINDOW_SECS);
            entry.record.recent_count = entry.recent.len() as u32;
        }
        let expired_ids = self.decision_engine.expire_timeouts(now_secs);
        for id in expired_ids {
            self.drop_pending(&id);
            // NEW: Send push notification for expired pending
            let _ = self
                .notification_tx
                .send(PushNotification::PendingExpired { pending_id: id });
            // Record expiry as a flow event (best-effort; we may not have full context here)
        }
    }

    /// Load pending decisions from the persistent store back into the decision engine.
    pub fn restore_pending(&mut self, decisions: Vec<core_types::PendingDecision>) {
        // These already have their Pending event from the run that created
        // them; a retransmit after the restart must not add a second row.
        for decision in &decisions {
            self.pending_events_recorded.insert(decision.id.clone());
        }
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

    /// Display name for an egress id, when the egress still exists. Log
    /// notifications carry the name so the viewer can render it without
    /// holding the egress list.
    fn egress_name(&self, egress_id: &Option<String>) -> Option<String> {
        let id = egress_id.as_deref()?;
        self.repo.get_egress(id).map(|egress| egress.name)
    }

    fn next_event_id(&mut self) -> String {
        self.event_counter += 1;
        format!("evt-{}", self.event_counter)
    }

    /// Record the Pending event for `pending` unless it is already recorded.
    ///
    /// A retransmitted SYN re-enters both the control-API handler and the live
    /// registrar with the same pending id. Recording it again added no
    /// information and multiplied the flow list: five NFS connections showed
    /// up as thirty unnamed rows, one per retransmit.
    fn record_pending_event_once(
        &mut self,
        flow: &FlowContext,
        pending: &core_types::PendingDecision,
        now_secs: u64,
    ) {
        // Ids are forgotten when the pending is deleted, so this stays bounded
        // by the pending limit. It answers "was an event written", which the
        // repository cannot: a row past its deadline is still present until
        // `tick` sweeps it, and a live filter would report it as new.
        if self.pending_events_recorded.insert(pending.id.clone()) {
            self.record_event(flow, FlowState::Pending, now_secs);
        }
    }

    /// Remove a pending from the store and forget that its event exists.
    fn drop_pending(&mut self, id: &str) {
        self.repo.delete_pending(id);
        self.pending_events_recorded.remove(id);
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
        // Also push a structured log event for clients that listen (e.g. the
        // --log-viewer) so every request is captured, not just the first in a
        // 5-min window. The UI groups by (process, destination_ip:port).
        let _ = self.notification_tx.send(PushNotification::PolicyMatch {
            process_name: flow.process_name.clone(),
            destination_ip: flow.destination_ip.clone(),
            destination_port: flow.destination_port,
            destination_domain: flow.destination_domain.clone(),
            rule_id: resolved.rule_id.clone(),
            action: resolved.action.clone(),
            egress_id: resolved.egress_id.clone(),
            egress_name: self.egress_name(&resolved.egress_id),
        });
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
            ControlRequest::EgressAlertStatus => "egress_alert_status",
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
                let rule_id = rule.id.clone();
                self.add_rule_with_seeded_priority(rule, ProcessPriority::High);
                if let Some(installed) = self.repo.get_rule(&rule_id) {
                    self.sweep_pending(&installed, None, None);
                }
                ControlResponse::Ok
            }
            ControlRequest::AddRuleWithProcessPriority {
                rule,
                process_priority,
            } => {
                let rule_id = rule.id.clone();
                self.add_rule_with_seeded_priority(rule, process_priority);
                if let Some(installed) = self.repo.get_rule(&rule_id) {
                    self.sweep_pending(&installed, None, None);
                }
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
            ControlRequest::EgressAlertStatus => {
                ControlResponse::EgressAlertList(self.egress_alert_records())
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
                            let state = if matches!(resolved.action, RuleAction::Deny) {
                                FlowState::Denied
                            } else {
                                FlowState::Allowed
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
                // A socket the kernel itself owns has no user-space process to
                // ask about; see `allow_kernel_owned`.
                if let Some((action, route_target)) = self.allow_kernel_owned(&flow, now_secs) {
                    return ControlResponse::ImmediateVerdict {
                        action,
                        route_target,
                    };
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
                        // A retransmission reuses the same pending id; see
                        // `record_pending_event_once`.
                        self.record_pending_event_once(&flow, &p, now_secs);
                        self.repo.upsert_pending(&p);
                        // NEW: Send push notification to subscribers
                        let decision = p.clone();
                        let _ = self.notification_tx.send(PushNotification::PendingCreated {
                            decision: *decision,
                        });
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
                    self.drop_pending(&pending_id);
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
                            egress_id: None,
                            egress_name: None,
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
                // Install the rule first, then sweep: any other pending
                // decision already in the queue that this rule covers *for
                // the same process* is auto-resolved without showing another
                // dialog. The answered pending is excluded — it is resolved
                // explicitly below with the user's chosen action.
                let egress_id = rule.egress_id.clone();
                let rule_id = rule.id.clone();
                let answered = self.decision_engine.pending_flow(&pending_id).cloned();
                self.add_rule_with_seeded_priority(rule, ProcessPriority::High);
                if let Some(installed) = self.repo.get_rule(&rule_id) {
                    self.sweep_pending(&installed, answered.as_ref(), Some(&pending_id));
                }
                if let Some(chosen) =
                    self.decision_engine
                        .resolve_pending(&pending_id, action, egress_id.clone())
                {
                    self.drop_pending(&pending_id);
                    let route_target = if chosen == RuleAction::Route {
                        self.resolve_route_target(&egress_id)
                    } else {
                        None
                    };
                    let egress_name = self.egress_name(&egress_id);
                    let _ = self
                        .notification_tx
                        .send(PushNotification::PendingResolved {
                            pending_id: pending_id.clone(),
                            action: chosen.clone(),
                            egress_id: egress_id.clone(),
                            egress_name,
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
                self.routing_revision = self.routing_revision.wrapping_add(1);
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
                    self.routing_revision = self.routing_revision.wrapping_add(1);
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
                self.routing_revision = self.routing_revision.wrapping_add(1);
                ControlResponse::Ok
            }
            ControlRequest::DeleteProxy { id } => {
                if self.repo.delete_proxy(&id) {
                    self.routing_revision = self.routing_revision.wrapping_add(1);
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
                        match proxy_client::test_http_connectivity(
                            &proxy,
                            &url,
                            timeout,
                            enforcer::DAEMON_BYPASS_MARK,
                        ) {
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
                        match proxy_client::test_dns_connectivity(
                            &proxy,
                            &domain,
                            timeout,
                            enforcer::DAEMON_BYPASS_MARK,
                        ) {
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

    /// Re-evaluate pending decisions against the rule just installed.
    ///
    /// A sweep may only resolve a pending that satisfies all three:
    ///
    /// 1. the installed rule matches it ([`policy_engine::rule_matches`]),
    ///    including the process fields the rule pins;
    /// 2. it resolves to *that* rule under current precedence — a different,
    ///    higher-priority rule's verdict is not what the user just chose;
    /// 3. there is an answered flow (a settings or CLI rule never sweeps).
    ///
    /// Anything else needs its own dialog. A rule for `brave → example.com`
    /// must never answer a pending for `ssh → 1.2.3.4`, which is how rules
    /// were previously applied to `(process, destination)` pairs that never
    /// occurred together.
    ///
    /// `answered` is the flow whose dialog the user just answered. When it is
    /// `None` the rule came from settings or the CLI, so the rule itself must
    /// pin the process for a pending to inherit it; a process-agnostic rule
    /// sweeps nothing.
    fn sweep_pending(
        &mut self,
        installed: &Rule,
        answered: Option<&FlowContext>,
        skip_pending: Option<&str>,
    ) {
        // An Ask rule decides nothing, so there is nothing to inherit.
        if installed.action == RuleAction::Ask {
            return;
        }
        if answered.is_none() && installed.process_name.is_none() && installed.process_exe.is_none()
        {
            return;
        }

        let rules = self.repo.list_rules();
        let pending = self.decision_engine.list_pending();
        let mut swept: u64 = 0;
        for p in pending {
            if skip_pending == Some(p.id.as_str()) {
                continue;
            }
            // The installed rule's own scope decides who inherits it.
            // `rule_matches` rejects a pending that names a different process
            // when the rule pins one, and a process-agnostic rule covers every
            // app — including an unattributed pending. Filtering by the
            // answered flow here made the dialog ("any app") and the sweep
            // disagree about who the rule covers.
            if !policy_engine::rule_matches(installed, &p.flow) {
                continue;
            }
            let Some(resolved) = resolve_action(&rules, &p.flow) else {
                continue;
            };
            if resolved.rule_id != installed.id {
                continue;
            }
            eprintln!(
                "sweep_pending: auto-resolving {} ({:?} → {:?}) via rule {} domain={:?} source={:?}",
                p.id,
                p.flow.process_name,
                resolved.action,
                installed.id,
                p.flow.destination_domain,
                p.flow.domain_source
            );
            swept += 1;
            self.decision_engine.resolve_pending(
                &p.id,
                resolved.action.clone(),
                resolved.egress_id.clone(),
            );
            self.drop_pending(&p.id);
            let egress_name = self.egress_name(&resolved.egress_id);
            let _ = self
                .notification_tx
                .send(PushNotification::PendingResolved {
                    pending_id: p.id,
                    action: resolved.action,
                    egress_id: resolved.egress_id,
                    egress_name,
                });
        }
        if swept > 0 {
            counter!("netkeep.pending.swept").increment(swept);
        }
    }

    /// Record a data-path failure and publish it, at most once per
    /// [`ALERT_EMIT_INTERVAL_SECS`] per (kind, target).
    ///
    /// The proxy relay and the DNS forwarder can fail thousands of times an
    /// hour when a proxy is down. The user needs to know *what* is broken; a
    /// stream of identical rows would bury it.
    pub fn record_egress_alert(&mut self, alert: EgressAlert, now_secs: u64) {
        let key_match = |e: &EgressAlertEntry| {
            e.record.kind == alert.kind && e.record.target_id == alert.target_id
        };

        let (count, should_emit) =
            if let Some(entry) = self.egress_alerts.iter_mut().find(|e| key_match(e)) {
                entry.record.count = entry.record.count.saturating_add(1);
                entry.record.last_at_secs = now_secs;
                entry.record.detail = alert.detail.clone();
                entry.recent.push(now_secs);
                entry
                    .recent
                    .retain(|t| now_secs.saturating_sub(*t) <= ALERT_RECENT_WINDOW_SECS);
                entry.record.recent_count = entry.recent.len() as u32;
                let due = now_secs.saturating_sub(entry.last_emit_secs) >= ALERT_EMIT_INTERVAL_SECS;
                if due {
                    entry.last_emit_secs = now_secs;
                }
                (entry.record.count, due)
            } else {
                if self.egress_alerts.len() >= ALERT_HISTORY_MAX {
                    // Drop the least recent failure.
                    if let Some((idx, _)) = self
                        .egress_alerts
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, e)| e.record.last_at_secs)
                    {
                        self.egress_alerts.remove(idx);
                    }
                }
                self.egress_alerts.push(EgressAlertEntry {
                    record: EgressAlertRecord {
                        kind: alert.kind,
                        target_id: alert.target_id.clone(),
                        detail: alert.detail.clone(),
                        count: 1,
                        recent_count: 1,
                        last_at_secs: now_secs,
                    },
                    last_emit_secs: now_secs,
                    recent: vec![now_secs],
                });
                (1, true)
            };

        if !should_emit {
            return;
        }
        let _ = self.notification_tx.send(PushNotification::EgressAlert {
            kind: alert.kind,
            target_id: alert.target_id,
            detail: alert.detail,
            count,
            at_secs: now_secs,
        });
    }

    /// Most recent failures, newest first, for the tray and the activity log.
    pub fn egress_alert_records(&self) -> Vec<EgressAlertRecord> {
        let mut rows: Vec<EgressAlertRecord> = self
            .egress_alerts
            .iter()
            .map(|e| e.record.clone())
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.last_at_secs));
        rows
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

    /// A socket the kernel itself owns has no user-space process to ask about:
    /// a dialog would name an app that does not exist, and the rule such a
    /// dialog produced would be pinned to a fiction. Allow it, record it, and
    /// publish the decision so the traffic still appears in the log.
    ///
    /// Returns `None` for every other flow, so the caller continues its normal
    /// decision path. Both entry points — intercepted packets
    /// ([`FlowRegistrar::register`]) and the control API
    /// (`RegisterUnknownFlow`) — call this, because a branch added to only one
    /// of them leaves the live path still asking the user.
    /// Returns the immediate verdict as data, so no caller has to unwrap a
    /// `FlowDecision` it cannot construct any other shape of.
    fn allow_kernel_owned(
        &mut self,
        flow: &FlowContext,
        now_secs: u64,
    ) -> Option<(RuleAction, Option<RouteTarget>)> {
        if flow.process_origin != core_types::ProcessOrigin::Kernel {
            return None;
        }
        counter!("netkeep.policy.kernel_allowed").increment(1);
        eprintln!("{}", kernel_policy_line(flow));
        self.record_event(flow, FlowState::Allowed, now_secs);
        let _ = self.notification_tx.send(PushNotification::KernelAllowed {
            source_port: flow.source_port,
            destination_ip: flow.destination_ip.clone(),
            destination_port: flow.destination_port,
            destination_domain: flow.destination_domain.clone(),
            protocol: flow.protocol,
        });
        Some((RuleAction::Allow, None))
    }
}

/// The `policy:` line for a kernel-owned socket.
///
/// Same grammar as a rule decision — `id=`, `action=`, the matched fields — so
/// a reader or parser keyed on `id=` does not lose these verdicts. There is no
/// rule row behind them, so the id is the fixed word `kernel-owned`.
fn kernel_policy_line(flow: &FlowContext) -> String {
    format!(
        "policy: id=kernel-owned action=Allow process=None domain={:?} dst={}:{} src=:{}",
        flow.destination_domain, flow.destination_ip, flow.destination_port, flow.source_port
    )
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
    fn routing_revision(&mut self) -> u64 {
        self.0
            .lock()
            .expect("service lock poisoned")
            .routing_revision()
    }

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
    fn routing_revision(&mut self) -> u64 {
        self.routing_revision
    }

    fn register(&mut self, flow: FlowContext, now_secs: u64) -> FlowDecision {
        if let Some(resolved) = resolve_action(&self.repo.list_rules(), &flow) {
            self.log_policy_match(&flow, &resolved, now_secs);
            match resolved.action {
                RuleAction::Allow | RuleAction::Deny | RuleAction::Route => {
                    // `Ask` is the only other variant, so these two wrappers
                    // are exhaustive by the time this arm runs.
                    let action_str = if matches!(resolved.action, RuleAction::Deny) {
                        "deny"
                    } else if matches!(resolved.action, RuleAction::Route) {
                        "route"
                    } else {
                        "allow"
                    };
                    counter!("netkeep.control.immediate_verdicts", "action" => action_str)
                        .increment(1);
                    let route_target = if resolved.action == RuleAction::Route {
                        self.resolve_route_target(&resolved.egress_id)
                    } else {
                        None
                    };
                    let state = if matches!(resolved.action, RuleAction::Deny) {
                        FlowState::Denied
                    } else {
                        FlowState::Allowed
                    };
                    self.record_event(&flow, state, now_secs);
                    return FlowDecision::Immediate(resolved.action, route_target);
                }
                RuleAction::Ask => {}
            }
        }
        // Kernel-owned sockets have no app to ask about, and the SNI deferral
        // below assumes a TLS client that could send a ClientHello — a kernel
        // service cannot. Decide it first.
        if let Some((action, route_target)) = self.allow_kernel_owned(&flow, now_secs) {
            return FlowDecision::Immediate(action, route_target);
        }

        // Defer unknown TLS connections until the name is in-band. A SYN
        // carries no ClientHello, so any domain on it is only a DNS/cache
        // prior — possibly learned from another app on the same anycast IP.
        // Opening the pending now would both show the user a name this
        // connection never presented and DROP the SYN, blocking the handshake
        // so SNI could never arrive. Only `Sni`/`Host` (read from the packet
        // being classified) may decide the flow; everything else defers.
        // Accept the bare handshake instead: the ClientHello is re-classified
        // (pending verdicts are never cached) and either matches a rule by
        // hostname — no dialog at all — or opens the pending with the real
        // domain. No payload flows before a real verdict: the ClientHello
        // itself is the first gated packet.
        if !(flow.domain_source.is_in_band() && flow.destination_domain.is_some())
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
                self.record_pending_event_once(&flow, &p, now_secs);
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
        DestinationMatcher, DomainSource, FlowContext, FlowDirection, FlowState, ProcessPriority,
        Rule, RuleAction, RuleDuration, TransportProtocol,
    };
    use state_store::InMemoryRuleRepository;

    use super::{
        kernel_policy_line, ControlService, HealthConfig, ALERT_RECENT_WINDOW_SECS,
        POLICY_LOG_DEDUP_SECS,
    };
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
            reverse_dns: None,
            process_origin: core_types::ProcessOrigin::Unresolved,
            process_name: Some("curl".to_string()),
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: Some("example.com".to_string()),
            domain_source: DomainSource::Sni,
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
        flow.domain_source = DomainSource::None;
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
        syn.domain_source = DomainSource::None;
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
        flow.domain_source = DomainSource::None;
        flow.tcp_syn = true;
        flow.destination_port = 8080;

        match service.register(flow, 1000) {
            FlowDecision::Pending { .. } => {}
            other => panic!("expected Pending on non-443, got {other:?}"),
        }
    }

    /// A name that came only from DNS (or from a cache hit) is a prior for the
    /// IP, not an observation for this connection: the SYN must still defer
    /// until the ClientHello supplies the real SNI.
    #[test]
    fn dns_only_domain_defers_syn() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let mut flow = mk_flow();
        flow.destination_domain = Some("api.zed.dev".to_string());
        flow.domain_source = DomainSource::Dns;
        flow.tcp_syn = true;

        assert!(
            matches!(service.register(flow, 1000), FlowDecision::DeferSni),
            "a cached/DNS name must not decide a TLS connection"
        );
        assert!(service.decision_engine.list_pending().is_empty());
    }

    /// In-band names read from the packet itself (SNI / HTTP Host) are
    /// authoritative and must not be deferred.
    #[test]
    fn in_band_domain_does_not_defer() {
        for source in [DomainSource::Sni, DomainSource::Host] {
            let mut service = ControlService::new(InMemoryRuleRepository::default());
            let mut flow = mk_flow();
            flow.domain_source = source;
            flow.tcp_syn = true;

            assert!(
                matches!(service.register(flow, 1000), FlowDecision::Pending { .. }),
                "in-band {source:?} must open the pending immediately"
            );
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

    /// A kernel-owned socket has no application behind it. Asking would name
    /// an app that does not exist, and the rule the answer produced would be
    /// pinned to a fiction. It must be allowed, recorded, published, and must
    /// leave no rule and no pending behind.
    #[test]
    fn kernel_owned_socket_is_allowed_without_a_dialog_or_a_rule() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let mut flow = mk_flow();
        flow.process_name = None;
        flow.process_exe = None;
        flow.app_name = None;
        flow.process_origin = core_types::ProcessOrigin::Kernel;

        let verdict = service.handle(ControlRequest::RegisterUnknownFlow {
            flow: flow.clone(),
            now_secs: 10,
        });
        assert_eq!(
            verdict,
            ControlResponse::ImmediateVerdict {
                action: RuleAction::Allow,
                route_target: None
            }
        );

        match service.handle(ControlRequest::ListPending) {
            ControlResponse::PendingList(items) => {
                assert!(items.is_empty(), "kernel traffic must not open a dialog")
            }
            _ => panic!("expected pending list"),
        }
        match service.handle(ControlRequest::ListRules) {
            ControlResponse::RuleList(rules) => assert!(rules.is_empty(), "no rule may be created"),
            _ => panic!("expected rule list"),
        }
        match service.handle(ControlRequest::ListFlows { limit: 10 }) {
            ControlResponse::FlowList(events) => {
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].state, FlowState::Allowed);
            }
            _ => panic!("expected flow list"),
        }
    }

    /// REGRESSION: intercepted packets enter the service through
    /// `FlowRegistrar::register`, not through the control API. The kernel
    /// allowance existed only on `RegisterUnknownFlow`, so live NFS traffic
    /// kept prompting while a control-socket probe passed.
    #[test]
    fn registrar_entry_point_allows_kernel_owned_flows() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let mut flow = mk_flow();
        flow.process_name = None;
        flow.process_exe = None;
        flow.app_name = None;
        flow.process_origin = core_types::ProcessOrigin::Kernel;

        let decision = service.register(flow, 10);
        assert!(
            matches!(decision, FlowDecision::Immediate(RuleAction::Allow, None)),
            "the live packet path must allow a kernel-owned flow"
        );
        match service.handle(ControlRequest::ListPending) {
            ControlResponse::PendingList(items) => {
                assert!(items.is_empty(), "no dialog for a kernel-owned flow")
            }
            _ => panic!("expected pending list"),
        }
        match service.handle(ControlRequest::ListRules) {
            ControlResponse::RuleList(rules) => assert!(rules.is_empty(), "no rule may be created"),
            _ => panic!("expected rule list"),
        }
    }

    /// Failures must be aggregated per (kind, target): a proxy in a reconnect
    /// loop fails thousands of times an hour, and the user needs one row that
    /// says what is broken, not thousands of identical rows.
    #[test]
    fn egress_alerts_aggregate_per_target_and_kind() {
        use core_types::{EgressAlert, EgressAlertKind};
        let mut service = ControlService::new(InMemoryRuleRepository::default());

        for now in [10, 11, 12] {
            service.record_egress_alert(
                EgressAlert {
                    kind: EgressAlertKind::Unreachable,
                    target_id: Some("px-1".into()),
                    detail: "connect timed out".into(),
                },
                now,
            );
        }
        service.record_egress_alert(
            EgressAlert {
                kind: EgressAlertKind::DnsFailed,
                target_id: Some("px-1".into()),
                detail: "8.8.8.8".into(),
            },
            13,
        );

        let rows = service.egress_alert_records();
        assert_eq!(rows.len(), 2, "one row per (kind, target)");
        let unreachable = rows
            .iter()
            .find(|r| r.kind == EgressAlertKind::Unreachable)
            .expect("unreachable row");
        assert_eq!(unreachable.count, 3, "repeats are counted, not repeated");
        assert_eq!(
            unreachable.recent_count, 3,
            "all three are inside the recent window"
        );
        assert_eq!(unreachable.last_at_secs, 12);
        assert_eq!(
            rows[0].kind,
            EgressAlertKind::DnsFailed,
            "newest failure first"
        );
    }

    /// The tray turns amber once a target failed `ALERT_SUSTAINED_THRESHOLD`
    /// times inside the recent window. That window must age out on its own:
    /// otherwise three failures leave the icon amber forever, even after the
    /// path recovers, because `recent_count` was only recomputed when a new
    /// failure of the same key arrived.
    #[test]
    fn egress_alert_recent_count_falls_out_of_the_window() {
        use core_types::{EgressAlert, EgressAlertKind};
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        for now in [10, 11, 12] {
            service.record_egress_alert(
                EgressAlert {
                    kind: EgressAlertKind::Unreachable,
                    target_id: Some("px-1".into()),
                    detail: "connect timed out".into(),
                },
                now,
            );
        }
        assert_eq!(service.egress_alert_records()[0].recent_count, 3);

        service.tick(12 + ALERT_RECENT_WINDOW_SECS + 1);
        let row = &service.egress_alert_records()[0];
        assert_eq!(
            row.recent_count, 0,
            "failures older than the window must stop counting as sustained"
        );
        assert_eq!(row.count, 3, "the lifetime occurrence count is kept");
    }

    /// The kernel verdict must use the same `policy:` grammar as every other
    /// verdict: a reader keyed on `id=` and `action=` must not lose it. The
    /// investigation quotes this line as evidence, so the format is pinned
    /// here rather than only in prose.
    #[test]
    fn kernel_policy_line_names_rule_action_and_fields() {
        let mut flow = mk_flow();
        flow.process_name = None;
        flow.process_exe = None;
        flow.app_name = None;
        flow.process_origin = core_types::ProcessOrigin::Kernel;
        flow.destination_domain = None;

        assert_eq!(
            kernel_policy_line(&flow),
            "policy: id=kernel-owned action=Allow process=None domain=None \
             dst=1.1.1.1:443 src=:54321"
        );
    }

    /// Destination-scoped sharing must hold on the path live traffic uses.
    /// A new source port to the same destination from the same app reuses the
    /// open dialog instead of asking the same question again; only the
    /// decision-engine unit tests covered this before.
    #[test]
    fn register_shares_one_pending_across_source_ports() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let mut first = mk_flow();
        first.source_port = 40001;
        let mut second = mk_flow();
        second.source_port = 40002;

        let first_id = match service.register(first, 10) {
            FlowDecision::Pending { id, .. } => id,
            other => panic!("expected a pending, got {other:?}"),
        };
        let second_id = match service.register(second, 11) {
            FlowDecision::Pending { id, .. } => id,
            other => panic!("expected a pending, got {other:?}"),
        };
        assert_eq!(
            first_id, second_id,
            "same app and destination share one dialog, whatever the source port"
        );
        assert_eq!(service.decision_engine.list_pending().len(), 1);
        let events = match service.handle(ControlRequest::ListFlows { limit: 100 }) {
            ControlResponse::FlowList(events) => events,
            _ => panic!("expected flow list"),
        };
        assert_eq!(events.len(), 1, "the shared pending is one flow event");
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

    /// A retransmission of a flow whose dialog is already open must not append
    /// another Pending event. Five NFS connections produced thirty unnamed rows
    /// in the flow list because every SYN retransmit was recorded again.
    ///
    /// Intercepted packets reach the service through `FlowRegistrar::register`,
    /// not through `RegisterUnknownFlow`, so this test must drive the registrar
    /// entry point; the control-API path had its own guard while live traffic
    /// kept multiplying rows.
    #[test]
    fn retransmission_of_a_pending_flow_records_one_event() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        for now in [10, 11, 12, 13] {
            let decision = service.register(mk_flow(), now);
            assert!(
                matches!(decision, FlowDecision::Pending { .. }),
                "every retransmit answers with the same pending"
            );
        }

        let events = match service.handle(ControlRequest::ListFlows { limit: 100 }) {
            ControlResponse::FlowList(events) => events,
            _ => panic!("expected flow list"),
        };
        assert_eq!(
            events.len(),
            1,
            "four retransmissions of one connection are one flow, not four"
        );
    }

    /// A retransmit can arrive after the pending's deadline but before `tick`
    /// sweeps the row. The event already exists; asking the repository whether
    /// the pending is live answered "no" and wrote a duplicate row.
    #[test]
    fn late_retransmission_before_the_sweep_adds_no_event() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let first = service.register(mk_flow(), 10);
        assert!(matches!(first, FlowDecision::Pending { .. }));

        // Past the 100 s deadline; `tick` has not run, so the same id answers.
        let late = service.register(mk_flow(), 500);
        assert!(matches!(late, FlowDecision::Pending { .. }));

        let events = match service.handle(ControlRequest::ListFlows { limit: 100 }) {
            ControlResponse::FlowList(events) => events,
            _ => panic!("expected flow list"),
        };
        assert_eq!(events.len(), 1, "one pending, one flow event");
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

    // -------------------------------------------------------------------
    // Pending sweep scoping (Stage 1 item 3)
    //
    // A rule installed from a dialog may answer other pendings, but only
    // those of the same proven process that the rule itself covers. Before
    // this, every pending matching *any* rule was silently resolved, which is
    // how `ssh → models.dev` was created without an ssh dialog.
    // -------------------------------------------------------------------

    fn flow_for(process: &str, domain: &str, src_port: u16) -> FlowContext {
        let mut flow = mk_flow();
        flow.process_name = Some(process.to_string());
        flow.source_port = src_port;
        flow.destination_domain = Some(domain.to_string());
        if domain != "example.com" {
            flow.destination_ip = format!("93.184.216.{src_port}");
        }
        flow
    }

    fn create_pending(
        service: &mut ControlService<InMemoryRuleRepository>,
        flow: FlowContext,
    ) -> String {
        match service.handle(ControlRequest::RegisterUnknownFlow { flow, now_secs: 10 }) {
            ControlResponse::PendingCreated { pending_id, .. } => pending_id,
            other => panic!("expected a pending decision, got {other:?}"),
        }
    }

    fn any_destination_rule(id: &str, process: Option<&str>, action: RuleAction) -> Rule {
        let mut rule = mk_rule(id);
        rule.action = action;
        rule.process_name = process.map(str::to_string);
        rule.destination = DestinationMatcher::Any;
        rule
    }

    /// A dialog answered for an unattributed flow installs a rule the dialog
    /// describes as "any app". Another unattributed pending that the same rule
    /// covers must inherit that answer; the previous sweep compared the two
    /// flows with a strict identity rule and left the second dialog open.
    #[test]
    fn answered_unattributed_dialog_sweeps_other_unattributed_pendings() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let mut first_flow = flow_for("curl", "example.com", 41051);
        first_flow.process_name = None;
        first_flow.process_exe = None;
        first_flow.app_name = None;
        let mut second_flow = flow_for("curl", "other.example", 41052);
        second_flow.process_name = None;
        second_flow.process_exe = None;
        second_flow.app_name = None;

        let first = create_pending(&mut service, first_flow);
        let second = create_pending(&mut service, second_flow);

        let rule = any_destination_rule("ui-any", None, RuleAction::Allow);
        service.handle(ControlRequest::ResolvePendingWithRule {
            pending_id: first,
            action: RuleAction::Allow,
            rule,
        });

        assert!(
            !service.decision_engine.is_pending(&second),
            "an any-app rule must answer every pending it covers"
        );
    }

    #[test]
    fn answered_dialog_only_sweeps_pendings_of_the_same_process() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let curl_pending = create_pending(&mut service, flow_for("curl", "example.com", 41001));
        let ssh_pending = create_pending(&mut service, flow_for("ssh", "shell.example", 41002));

        // Answer the curl dialog with "always allow curl".
        let rule = any_destination_rule("ui-curl", Some("curl"), RuleAction::Allow);
        let response = service.handle(ControlRequest::ResolvePendingWithRule {
            pending_id: curl_pending,
            action: RuleAction::Allow,
            rule,
        });
        assert!(
            matches!(response, ControlResponse::PendingResolved { .. }),
            "the answered pending must still resolve directly, got {response:?}"
        );

        assert!(
            service.decision_engine.is_pending(&ssh_pending),
            "a rule answered for curl must never resolve an ssh dialog"
        );
        let live: Vec<Option<String>> = service
            .decision_engine
            .list_pending()
            .into_iter()
            .map(|p| p.flow.process_name)
            .collect();
        assert_eq!(live, vec![Some("ssh".to_string())]);
    }

    #[test]
    fn answered_dialog_sweeps_other_pendings_of_the_same_process() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let first = create_pending(&mut service, flow_for("curl", "example.com", 41011));
        let second = create_pending(&mut service, flow_for("curl", "other.example", 41012));

        let rule = any_destination_rule("ui-curl", Some("curl"), RuleAction::Allow);
        service.handle(ControlRequest::ResolvePendingWithRule {
            pending_id: first,
            action: RuleAction::Allow,
            rule,
        });

        assert!(
            service.decision_engine.list_pending().is_empty(),
            "the second curl dialog inherits the answered curl rule"
        );
        assert!(!service.decision_engine.is_pending(&second));
    }

    #[test]
    fn sweep_skips_pendings_the_installed_rule_does_not_cover() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let answered = create_pending(&mut service, flow_for("curl", "example.com", 41021));
        let other_domain = create_pending(&mut service, flow_for("curl", "other.example", 41022));

        // The rule covers example.com only (mk_rule's default destination).
        let mut rule = mk_rule("ui-curl-example");
        rule.process_name = Some("curl".to_string());

        service.handle(ControlRequest::ResolvePendingWithRule {
            pending_id: answered,
            action: RuleAction::Allow,
            rule,
        });

        assert!(
            service.decision_engine.is_pending(&other_domain),
            "a rule for example.com must not answer the other.example dialog"
        );
        let remaining: Vec<Option<String>> = service
            .decision_engine
            .list_pending()
            .into_iter()
            .map(|p| p.flow.destination_domain)
            .collect();
        assert_eq!(remaining, vec![Some("other.example".to_string())]);
    }

    #[test]
    fn settings_rule_without_a_process_sweeps_nothing() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let pending = create_pending(&mut service, flow_for("curl", "example.com", 41031));

        service.handle(ControlRequest::AddRule(any_destination_rule(
            "ui-any",
            None,
            RuleAction::Allow,
        )));

        assert!(
            service.decision_engine.is_pending(&pending),
            "a process-agnostic rule may not decide an unknown app's dialog"
        );
    }

    #[test]
    fn settings_rule_pinned_to_a_process_sweeps_that_process_only() {
        let mut service = ControlService::new(InMemoryRuleRepository::default());
        let curl_pending = create_pending(&mut service, flow_for("curl", "example.com", 41041));
        let ssh_pending = create_pending(&mut service, flow_for("ssh", "shell.example", 41042));

        service.handle(ControlRequest::AddRule(any_destination_rule(
            "ui-curl",
            Some("curl"),
            RuleAction::Allow,
        )));

        assert!(!service.decision_engine.is_pending(&curl_pending));
        assert!(
            service.decision_engine.is_pending(&ssh_pending),
            "a curl rule must never answer an ssh dialog"
        );
    }
}
