pub mod args;

use control_api::{ControlRequest, ControlResponse};
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
                let before_id = before.as_ref().map(Clone::clone);
                let after_id = after.as_ref().map(Clone::clone);
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
                let dest = args::parse_destination(&destination).map_err(|e| CliError::Usage(e))?;
                let rule_action_type = rule_action
                    .map(|a| parse_rule_action(&a))
                    .unwrap_or(req_action);
                let req_action = rule_action_type;
                let rule = core_types::Rule {
                    id: rule_id,
                    enabled: true,
                    action: req_action.clone(),
                    duration: args::Duration::from_str(&rule_duration)
                        .map_err(|e| CliError::Usage(e))?
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
            args::NfqueueAction::Enable { queue_num } => {
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
        let destination = if let Some((target_type, explicit_value)) = &self.target {
            // --target TYPE,VALUE or --target TYPE=VALUE fully specifies the matcher.
            let value = explicit_value.as_deref().or_else(|| {
                // --target TYPE flag with a positional destination value.
                self.destination.as_deref()
            });
            let value = value.ok_or_else(|| {
                CliError::Usage("missing destination value: provide a positional DESTINATION or --target TYPE,VALUE".to_string())
            })?;
            args::parse_destination_with_target(value, Some(target_type.clone()))
                .map_err(CliError::Usage)?
        } else {
            // Auto-detect the matcher type from the positional destination.
            let value = self.destination.as_deref().ok_or_else(|| {
                CliError::Usage("missing destination value: provide a positional DESTINATION (e.g. example.com)".to_string())
            })?;
            args::parse_destination(value).map_err(CliError::Usage)?
        };
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

// ---------- execute integration ----------

impl args::Command {
    pub fn execute(
        self,
        socket: &str,
        _format: crate::Format,
    ) -> Result<control_api::ControlResponse, crate::CliError> {
        let request = build_request(self)?;
        daemon::send_request(socket, request).map_err(|e| match e {
            daemon::DaemonError::Connection => crate::CliError::Connection,
            daemon::DaemonError::Protocol(msg) | daemon::DaemonError::Daemon(msg) => {
                crate::CliError::Daemon(msg)
            }
        })
    }
}

// ---------- impls for arg types ----------
