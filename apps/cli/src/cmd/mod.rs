pub mod args;

use control_api::ControlRequest;
use std::str::FromStr;

use crate::{daemon, CliError};

pub use args::*;

fn build_request(cmd: args::Command) -> Result<ControlRequest, CliError> {
    match cmd {
        args::Command::Rule { action } => match action {
            args::RuleAction::Add(args) => {
                let rule = args.parse_rule()?;
                Ok(ControlRequest::AddRule(rule))
            }
            args::RuleAction::Move { id, before, after } => {
                let before_id = before.clone();
                let after_id = after.clone();
                Ok(ControlRequest::MoveRule {
                    id,
                    before_id,
                    after_id,
                })
            }
            args::RuleAction::List {
                process,
                id,
                search,
                action,
                duration,
            } => {
                let _ = (process, id, search, action, duration);
                Ok(ControlRequest::ListRules)
            }
            args::RuleAction::Delete { id, force } => {
                if !force {
                    return Err(CliError::Usage(format!(
                        "deleting rule {id:?} is irreversible; add --force to confirm"
                    )));
                }
                Ok(ControlRequest::DeleteRule { id })
            }
        },

        args::Command::Allow(_) | args::Command::Deny(_) | args::Command::Route(_) => {
            unreachable!("shortcut commands are handled before request building")
        }

        args::Command::Pending { action } => match action {
            args::PendingAction::List => Ok(ControlRequest::ListPending),
            args::PendingAction::Await { id, count } => {
                if count == 1 {
                    Ok(ControlRequest::AwaitPendingDecision {
                        pending_id: id.unwrap_or_default(),
                    })
                } else {
                    Ok(ControlRequest::SubscribeToPending)
                }
            }
            args::PendingAction::Resolve { id, action } => Ok(ControlRequest::ResolvePending {
                pending_id: id,
                action: action.into(),
            }),
            args::PendingAction::ResolveWithRule {
                id,
                action,
                rule_id,
                destination,
                rule_action,
                rule_duration,
                rule_process,
                rule_egress,
            } => {
                let req_action = action.into();
                let dest = args::parse_destination(&destination).map_err(CliError::Usage)?;
                let rule_action_type = rule_action
                    .map(|a| parse_rule_action(&a))
                    .unwrap_or(req_action);
                let req_action = rule_action_type;
                let rule = core_types::Rule {
                    id: rule_id,
                    enabled: true,
                    action: req_action.clone(),
                    duration: args::Duration::from_str(&rule_duration)
                        .map_err(CliError::Usage)?
                        .into(),
                    process_name: rule_process,
                    process_exe: None,
                    destination: dest,
                    egress_id: rule_egress,
                    priority: 0.0,
                };
                Ok(ControlRequest::ResolvePendingWithRule {
                    pending_id: id,
                    action: req_action,
                    rule,
                })
            }
        },

        args::Command::Flow { action } => match action {
            args::FlowAction::List { limit, process } => {
                let _ = process;
                Ok(ControlRequest::ListFlows { limit })
            }
        },

        args::Command::Egress { action } => match action {
            args::EgressAction::List => Ok(ControlRequest::ListEgresses),
            args::EgressAction::Upsert {
                id,
                name,
                default,
                targets,
                dns,
            } => {
                let targets: Vec<core_types::RouteTarget> = targets
                    .split(',')
                    .filter_map(|s| {
                        let s = s.trim();
                        if s.is_empty() {
                            None
                        } else {
                            Some(core_types::RouteTarget::Device(s.to_string()))
                        }
                    })
                    .collect();
                let dns_servers: Vec<String> = if dns.eq_ignore_ascii_case("system") {
                    Vec::new()
                } else {
                    dns.split(',').map(|s| s.trim().to_string()).collect()
                };
                let egress = core_types::Egress {
                    id,
                    name,
                    color: "blue".to_string(),
                    is_system_default: default,
                    is_available: true,
                    targets,
                    dns_servers,
                };
                Ok(ControlRequest::UpsertEgress(egress))
            }
            args::EgressAction::Delete { id, force } => {
                if !force {
                    return Err(CliError::Usage(format!(
                        "deleting egress {id:?} is irreversible; add --force to confirm"
                    )));
                }
                Ok(ControlRequest::DeleteEgress { id })
            }
        },

        args::Command::Proxy { action } => match action {
            args::ProxyAction::List => Ok(ControlRequest::ListProxies),
            args::ProxyAction::Upsert {
                id,
                name,
                protocol,
                host_port,
                enabled,
                auth,
            } => {
                let (host, port) = host_port.rsplit_once(':').ok_or_else(|| {
                    CliError::Usage("host_port must be <host>:<port>".to_string())
                })?;
                let port: u16 = port
                    .parse()
                    .map_err(|_| CliError::Usage("port must be a number".to_string()))?;
                let proxy_protocol = match protocol {
                    args::LocalProxyProtocol::Http => core_types::ProxyProtocol::Http,
                    args::LocalProxyProtocol::Socks5 => core_types::ProxyProtocol::Socks5,
                    args::LocalProxyProtocol::Shadowsocks => core_types::ProxyProtocol::Shadowsocks,
                };
                let proxy_auth = match auth {
                    args::LocalProxyAuth::None => core_types::ProxyAuth::None,
                    args::LocalProxyAuth::Basic => core_types::ProxyAuth::Basic {
                        username: "".to_string(),
                        password: "".to_string(),
                    },
                };
                let proxy = core_types::ProxyConfig {
                    id,
                    name,
                    protocol: proxy_protocol,
                    host: host.to_string(),
                    port,
                    auth: proxy_auth,
                    enabled,
                };
                Ok(ControlRequest::UpsertProxy(proxy))
            }
            args::ProxyAction::Delete { id, force } => {
                if !force {
                    return Err(CliError::Usage(format!(
                        "deleting proxy {id:?} is irreversible; add --force to confirm"
                    )));
                }
                Ok(ControlRequest::DeleteProxy { id })
            }
            args::ProxyAction::TestHttp { id, url } => {
                Ok(ControlRequest::TestProxyHttp { proxy_id: id, url })
            }
            args::ProxyAction::TestDns { id, domain } => Ok(ControlRequest::TestProxyDns {
                proxy_id: id,
                domain,
            }),
        },

        args::Command::Nfqueue { action } => match action {
            args::NfqueueAction::Enable { queue_num: _ } => {
                Ok(ControlRequest::SetNfqueueEnabled { enabled: true })
            }
            args::NfqueueAction::Disable => {
                Ok(ControlRequest::SetNfqueueEnabled { enabled: false })
            }
            args::NfqueueAction::Status => Ok(ControlRequest::Health),
        },

        args::Command::Config { action } => match action {
            args::ConfigAction::Show => Ok(ControlRequest::Health),
            args::ConfigAction::Unlock => Ok(ControlRequest::Unlock),
        },

        args::Command::RegisterFlow {
            process,
            ip,
            domain,
            protocol,
            now_secs,
        } => {
            let domain = domain.filter(|d| d != "-");
            let flow = core_types::FlowContext {
                process_name: Some(process),
                process_exe: None,
                app_name: None,
                source_ip: "0.0.0.0".to_string(),
                source_port: 0,
                destination_ip: ip,
                destination_port: 443,
                destination_domain: domain,
                protocol: protocol.into_transport(),
                direction: core_types::FlowDirection::Outbound,
                device_label: None,
                tcp_syn: false,
            };
            Ok(ControlRequest::RegisterUnknownFlow { flow, now_secs })
        }
        args::Command::OpenRoutedTcp { host, port, target } => {
            let target = core_types::RouteTarget::Device(target);
            Ok(ControlRequest::OpenRoutedTcp { host, port, target })
        }
    }
}

// ---------- impls for arg types ----------

fn parse_rule_action(s: &str) -> core_types::RuleAction {
    match s {
        "allow" => core_types::RuleAction::Allow,
        "deny" => core_types::RuleAction::Deny,
        "ask" => core_types::RuleAction::Ask,
        "route" => core_types::RuleAction::Route,
        other => {
            panic!("unknown action {other:?}; use allow, deny, ask, or route");
        }
    }
}

impl args::RuleAddArgs {
    fn parse_rule(&self) -> Result<core_types::Rule, CliError> {
        let destination =
            args::resolve_destination(self.destination.as_deref(), self.target.as_ref())
                .map_err(CliError::Usage)?;
        if self.destination.is_none() && self.target.is_none() {
            return Err(CliError::Usage(
                "missing destination value: provide a positional DESTINATION (e.g. example.com)"
                    .to_string(),
            ));
        }
        let action = match self.action.as_str() {
            "allow" => core_types::RuleAction::Allow,
            "deny" => core_types::RuleAction::Deny,
            "ask" => core_types::RuleAction::Ask,
            "route" => core_types::RuleAction::Route,
            other => {
                return Err(CliError::Usage(format!(
                    "unknown action {other:?}; use allow, deny, ask, or route"
                )))
            }
        };

        let duration = match self.duration.as_str() {
            "until-restart" | "session" => core_types::RuleDuration::UntilRestart,
            "permanent" => core_types::RuleDuration::Permanent,
            other => {
                return Err(CliError::Usage(format!(
                    "unknown duration {other:?}; use until-restart or permanent"
                )))
            }
        };

        Ok(core_types::Rule {
            id: self.id.clone().unwrap_or_default(),
            enabled: true,
            action,
            duration,
            process_name: self.process.clone(),
            process_exe: self.process_exe.clone(),
            destination,
            egress_id: self.egress.clone(),
            priority: 0.0,
        })
    }
}

impl args::PendingActionValue {
    fn into(self) -> core_types::RuleAction {
        match self {
            args::PendingActionValue::Allow => core_types::RuleAction::Allow,
            args::PendingActionValue::Deny => core_types::RuleAction::Deny,
            args::PendingActionValue::Ask => core_types::RuleAction::Ask,
        }
    }
}

fn parse_rule_duration(value: &str) -> Result<core_types::RuleDuration, CliError> {
    match value {
        "until-restart" | "session" => Ok(core_types::RuleDuration::UntilRestart),
        "permanent" => Ok(core_types::RuleDuration::Permanent),
        other => Err(CliError::Usage(format!(
            "unknown duration {other:?}; use until-restart or permanent"
        ))),
    }
}

/// Generate a rule id for shortcuts that did not receive one.
fn shortcut_rule_id(explicit: Option<String>) -> String {
    explicit.unwrap_or_else(|| {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        format!("cli-{millis}")
    })
}

impl args::ShortcutArgs {
    fn into_rule(self, action: core_types::RuleAction) -> Result<core_types::Rule, CliError> {
        if self.destination.is_none()
            && self.target.is_none()
            && self.process.is_none()
            && self.process_exe.is_none()
        {
            return Err(CliError::Usage(
                "provide a DESTINATION, --process, or --process-exe to scope the rule \
                 (use `any` to match every destination)"
                    .to_string(),
            ));
        }
        let destination =
            args::resolve_destination(self.destination.as_deref(), self.target.as_ref())
                .map_err(CliError::Usage)?;
        Ok(core_types::Rule {
            id: shortcut_rule_id(self.id),
            enabled: true,
            action,
            duration: parse_rule_duration(&self.duration)?,
            process_name: self.process,
            process_exe: self.process_exe,
            destination,
            egress_id: None,
            priority: 0.0,
        })
    }
}

impl args::RouteShortcutArgs {
    fn into_rule(self, egress_id: String) -> Result<core_types::Rule, CliError> {
        if self.destination.is_none()
            && self.target.is_none()
            && self.process.is_none()
            && self.process_exe.is_none()
        {
            return Err(CliError::Usage(
                "provide a DESTINATION, --process, or --process-exe to scope the rule \
                 (use `any` to match every destination)"
                    .to_string(),
            ));
        }
        let destination =
            args::resolve_destination(self.destination.as_deref(), self.target.as_ref())
                .map_err(CliError::Usage)?;
        Ok(core_types::Rule {
            id: shortcut_rule_id(self.id),
            enabled: true,
            action: core_types::RuleAction::Route,
            duration: parse_rule_duration(&self.duration)?,
            process_name: self.process,
            process_exe: self.process_exe,
            destination,
            egress_id: Some(egress_id),
            priority: 0.0,
        })
    }
}

// ---------- execute integration ----------

fn send_request(
    socket: &str,
    request: ControlRequest,
) -> Result<control_api::ControlResponse, crate::CliError> {
    daemon::send_request(socket, request).map_err(|e| match e {
        daemon::DaemonError::Connection => crate::CliError::Connection,
        daemon::DaemonError::Protocol(msg) => crate::CliError::Daemon(msg),
    })
}

/// Install a shortcut rule and echo the created rule back to the caller.
fn add_shortcut_rule(
    socket: &str,
    rule: core_types::Rule,
) -> Result<control_api::ControlResponse, crate::CliError> {
    let response = send_request(socket, ControlRequest::AddRule(rule.clone()))?;
    match response {
        control_api::ControlResponse::Ok => Ok(control_api::ControlResponse::RuleList(vec![rule])),
        other => Ok(other),
    }
}

/// Resolve an egress by id or name so `route --via <name>` feels natural.
fn resolve_egress(socket: &str, via: &str) -> Result<String, crate::CliError> {
    let response = send_request(socket, ControlRequest::ListEgresses)?;
    let control_api::ControlResponse::EgressList(egresses) = response else {
        return Err(crate::CliError::Daemon(
            "unexpected response while listing egresses".to_string(),
        ));
    };
    if let Some(egress) = egresses.iter().find(|e| e.id == via) {
        return Ok(egress.id.clone());
    }
    if let Some(egress) = egresses.iter().find(|e| e.name.eq_ignore_ascii_case(via)) {
        return Ok(egress.id.clone());
    }
    Err(crate::CliError::Usage(format!(
        "unknown egress {via:?}; run `netkeep-cli egress list` to see available egresses"
    )))
}

impl args::Command {
    pub(crate) fn execute(
        self,
        socket: &str,
        _format: crate::Format,
    ) -> Result<control_api::ControlResponse, crate::CliError> {
        match self {
            args::Command::Allow(args) => {
                add_shortcut_rule(socket, args.into_rule(core_types::RuleAction::Allow)?)
            }
            args::Command::Deny(args) => {
                add_shortcut_rule(socket, args.into_rule(core_types::RuleAction::Deny)?)
            }
            args::Command::Route(args) => {
                let egress_id = resolve_egress(socket, &args.via)?;
                add_shortcut_rule(socket, args.into_rule(egress_id)?)
            }
            other => {
                let request = build_request(other)?;
                send_request(socket, request)
            }
        }
    }
}

// ---------- impls for arg types ----------
