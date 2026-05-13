use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use core_types::{DestinationMatcher, FlowContext, FlowDirection, Rule, RuleAction, RuleDuration, TransportProtocol};
use control_api::{ControlRequest, ControlResponse};
use serde_json::json;

const DEFAULT_SOCKET_PATH: &str = "/tmp/logiguard.sock";
const DEFAULT_FLOW_LIST_LIMIT: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Text,
    Json,
}

/// Infer the destination matcher type from the value string.
/// *.x    → DomainWildcard
/// contains '/' → Cidr
/// all digits/dots → IpExact
/// else  → DomainExact
fn parse_destination(value: &str) -> DestinationMatcher {
    if let Some(rest) = value.strip_prefix("*.") {
        return DestinationMatcher::DomainWildcard(rest.to_string());
    }
    if value.contains('/') {
        return DestinationMatcher::Cidr(value.to_string());
    }
    if value.chars().all(|c| c.is_ascii_digit() || c == '.') && value.contains('.') {
        return DestinationMatcher::IpExact(value.to_string());
    }
    DestinationMatcher::DomainExact(value.to_string())
}

/// Parse `--flag value` pairs out of a slice, returning (remaining_positional_args, value_or_None)
/// for each expected flag.  Returns an error string if an unknown flag is encountered.
fn extract_flag<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].as_str())
}

fn parse_request(args: &[String]) -> Result<(ControlRequest, OutputMode), String> {
    let (output_mode, cmd_args): (OutputMode, &[String]) =
        if args.first().map(|s| s.as_str()) == Some("--json") {
            (OutputMode::Json, &args[1..])
        } else {
            (OutputMode::Text, args)
        };

    if cmd_args.is_empty() {
        return Err(
            "usage: add-rule <id> <destination> [--action allow|deny|ask|route] \
             [--duration until-restart|permanent] [--process <name>] [--route <device>] | \
             list-rules | list-pendings | list-flows [--limit N] | \
             delete-rule <id> | \
             register-flow <process> <ip> <domain|-> <tcp|udp|quic|other> <now-secs> | \
             resolve-pending <id> <allow|deny|ask> | \
             health | show-config | unlock"
                .to_string(),
        );
    }

    match cmd_args[0].as_str() {
        "add-rule" => {
            let flags_rest = &cmd_args[1..];
            let mut positionals = Vec::new();
            let mut i = 0;
            while i < flags_rest.len() {
                if flags_rest[i].starts_with("--") {
                    i += 2; // skip flag + value
                } else {
                    positionals.push(flags_rest[i].as_str());
                    i += 1;
                }
            }
            if positionals.len() < 2 {
                return Err("usage: add-rule <id> <destination> [--action allow|deny|ask|route] \
                            [--duration until-restart|permanent] [--process <name>] [--route <device>]"
                    .to_string());
            }
            let id = positionals[0].to_string();
            let destination = parse_destination(positionals[1]);

            let action = match extract_flag(flags_rest, "--action") {
                Some("allow") => RuleAction::Allow,
                Some("deny") => RuleAction::Deny,
                Some("ask") => RuleAction::Ask,
                Some("route") => RuleAction::Route,
                Some(other) => {
                    return Err(format!("unknown action: {other}; use allow, deny, ask, or route"))
                }
                None => RuleAction::Allow,
            };
            let duration = match extract_flag(flags_rest, "--duration") {
                Some("until-restart") | Some("session") => RuleDuration::UntilRestart,
                Some("permanent") => RuleDuration::Permanent,
                Some(other) => {
                    return Err(format!(
                        "unknown duration: {other}; use until-restart or permanent"
                    ))
                }
                None => RuleDuration::UntilRestart,
            };
            let process_name = extract_flag(flags_rest, "--process").map(|s| s.to_string());
            let egress_id = extract_flag(flags_rest, "--egress").map(|s| s.to_string());

            Ok((
                ControlRequest::AddRule(Rule {
                    id,
                    enabled: true,
                    action,
                    duration,
                    process_name,
                    destination,
                    egress_id,
                }),
                output_mode,
            ))
        }
        "list-rules" => Ok((ControlRequest::ListRules, output_mode)),
        "list-pendings" => Ok((ControlRequest::ListPending, output_mode)),
        "list-flows" => {
            let limit = extract_flag(&cmd_args[1..], "--limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(DEFAULT_FLOW_LIST_LIMIT);
            Ok((ControlRequest::ListFlows { limit }, output_mode))
        }
        "delete-rule" => {
            if cmd_args.len() != 2 {
                return Err("usage: delete-rule <id>".to_string());
            }
            Ok((
                ControlRequest::DeleteRule { id: cmd_args[1].clone() },
                output_mode,
            ))
        }
        "register-flow" => {
            if cmd_args.len() != 6 {
                return Err(
                    "usage: register-flow <process> <ip> <domain|-> <tcp|udp|quic|other> <now-secs>"
                        .to_string(),
                );
            }
            let now_secs = cmd_args[5]
                .parse::<u64>()
                .map_err(|_| "now-secs must be an unsigned integer".to_string())?;
            let protocol = match cmd_args[4].as_str() {
                "tcp" => TransportProtocol::Tcp,
                "udp" => TransportProtocol::Udp,
                "quic" => TransportProtocol::Quic,
                "other" => TransportProtocol::Other,
                _ => return Err("protocol must be one of: tcp, udp, quic, other".to_string()),
            };
            let domain = if cmd_args[3] == "-" { None } else { Some(cmd_args[3].clone()) };
            Ok((
                ControlRequest::RegisterUnknownFlow {
                    flow: FlowContext {
                        process_name: Some(cmd_args[1].clone()),
                        destination_ip: cmd_args[2].clone(),
                        destination_port: 443,
                        destination_domain: domain,
                        protocol,
                        direction: FlowDirection::Outbound,
                        device_label: None,
                    },
                    now_secs,
                },
                output_mode,
            ))
        }
        "resolve-pending" => {
            if cmd_args.len() != 3 {
                return Err("usage: resolve-pending <id> <allow|deny|ask>".to_string());
            }
            let action = match cmd_args[2].as_str() {
                "allow" => RuleAction::Allow,
                "deny" => RuleAction::Deny,
                "ask" => RuleAction::Ask,
                _ => return Err("action must be one of: allow, deny, ask".to_string()),
            };
            Ok((
                ControlRequest::ResolvePending {
                    pending_id: cmd_args[1].clone(),
                    action,
                },
                output_mode,
            ))
        }
        "health" => Ok((ControlRequest::Health, output_mode)),
        "show-config" => Ok((ControlRequest::Health, OutputMode::Json)),
        "unlock" => Ok((ControlRequest::Unlock, output_mode)),
        _ => Err("unknown command".to_string()),
    }
}

fn render_response(response: ControlResponse, output_mode: OutputMode) -> Result<String, String> {
    if output_mode == OutputMode::Json {
        return match response {
            ControlResponse::Error(err) => Err(json!({ "error": err }).to_string()),
            other => serde_json::to_string(&other).map_err(|e| e.to_string()),
        };
    }

    match response {
        ControlResponse::Ok => Ok("ok".to_string()),
        ControlResponse::RuleList(rules) => {
            if rules.is_empty() {
                Ok("no rules".to_string())
            } else {
                let body = rules
                    .iter()
                    .map(|r| {
                        let egress = match &r.egress_id {
                            Some(id) => format!(" egress={id}"),
                            None => String::new(),
                        };
                        format!(
                            "{} {:?} action={:?} duration={:?} process={:?}{egress}",
                            r.id, r.destination, r.action, r.duration, r.process_name
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(body)
            }
        }
        ControlResponse::PendingList(items) => {
            if items.is_empty() {
                Ok("no pendings".to_string())
            } else {
                let body = items
                    .iter()
                    .map(|p| {
                        format!(
                            "{} protocol={:?} created={} deadline={}",
                            p.id, p.flow.protocol, p.created_at_secs, p.deadline_at_secs
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(body)
            }
        }
        ControlResponse::FlowList(events) => {
            if events.is_empty() {
                Ok("no flow events".to_string())
            } else {
                let body = events
                    .iter()
                    .map(|e| {
                        format!(
                            "{} process={:?} ip={} domain={:?} proto={:?} state={:?} t={}",
                            e.id,
                            e.process_name,
                            e.destination_ip,
                            e.destination_domain,
                            e.protocol,
                            e.state,
                            e.timestamp_secs,
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(body)
            }
        }
        ControlResponse::PendingCreated {
            pending_id,
            created_at_secs,
            deadline_at_secs,
            protocol,
        } => Ok(format!(
            "pending created id={pending_id} protocol={protocol:?} \
             created_at_secs={created_at_secs} deadline_at_secs={deadline_at_secs}"
        )),
        ControlResponse::ImmediateVerdict { action, .. } => {
            Ok(format!("immediate verdict={action:?}"))
        }
        ControlResponse::PendingStillWaiting { pending_id } => {
            Ok(format!("pending still waiting id={pending_id}"))
        }
        ControlResponse::PendingResolved { action, .. } => {
            Ok(format!("pending resolved action={action:?}"))
        }
        ControlResponse::Health {
            ready,
            fail_close_active,
            pending_limit,
            default_timeout_secs,
            tcp_timeout_secs,
            udp_timeout_secs,
            quic_timeout_secs,
            other_timeout_secs,
            nfqueue_enabled,
            nfqueue_num,
        } => Ok(format!(
            "ready={ready} fail_close_active={fail_close_active} \
             pending_limit={pending_limit} default_timeout_secs={default_timeout_secs} \
             tcp={tcp_timeout_secs}s udp={udp_timeout_secs}s \
             quic={quic_timeout_secs}s other={other_timeout_secs}s \
             nfqueue={nfqueue_enabled} nfqueue_num={nfqueue_num:?}"
        )),
        ControlResponse::Unlocked => Ok("unlocked: nftables rules removed".to_string()),
        ControlResponse::Error(err) => Err(err),
        ControlResponse::SubscriptionAck => Ok("subscription confirmed".to_string()),
        ControlResponse::RoutedTcpReady { listen_addr } => {
            Ok(format!("routed tcp relay ready at {listen_addr}"))
        }
        ControlResponse::EgressList(egresses) => {
            if egresses.is_empty() {
                Ok("no egresses".to_string())
            } else {
                let body = egresses
                    .iter()
                    .map(|e| {
                        let dns = if e.dns_servers.is_empty() {
                            "(system DNS)".to_string()
                        } else {
                            e.dns_servers.join(", ")
                        };
                        format!(
                            "{} name={} default={} available={} targets={:?} dns={}",
                            e.id,
                            e.name,
                            e.is_system_default,
                            e.is_available,
                            e.targets,
                            dns,
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(body)
            }
        }
        ControlResponse::ProxyList(proxies) => {
            if proxies.is_empty() {
                Ok("no proxies".to_string())
            } else {
                let body = proxies
                    .iter()
                    .map(|p| {
                        format!(
                            "{} name={} proto={:?} {}:{} enabled={}",
                            p.id, p.name, p.protocol, p.host, p.port, p.enabled
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(body)
            }
        }
        ControlResponse::NfqueueStatus { enabled, queue_num } => {
            Ok(format!("nfqueue enabled={enabled} queue_num={queue_num:?}"))
        }
    }
}

fn send_request(socket_path: &str, request: &ControlRequest) -> Result<ControlResponse, String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("failed to connect to daemon at {socket_path}: {e}"))?;
    let payload = serde_json::to_string(request).map_err(|e| e.to_string())?;
    stream
        .write_all(format!("{payload}\n").as_bytes())
        .map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if line.trim().is_empty() {
        return Err("daemon returned empty response".to_string());
    }
    serde_json::from_str(line.trim_end()).map_err(|e| e.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (request, output_mode) = match parse_request(&args) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    let socket_path =
        std::env::var("LOGIGUARD_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
    let response = match send_request(&socket_path, &request) {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    match render_response(response, output_mode) {
        Ok(msg) => println!("{msg}"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_rule_domain_exact_default_action_duration() {
        let args = ["add-rule", "r1", "example.com"]
            .map(String::from)
            .to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        match req {
            ControlRequest::AddRule(rule) => {
                assert_eq!(rule.id, "r1");
                assert_eq!(rule.destination, DestinationMatcher::DomainExact("example.com".to_string()));
                assert_eq!(rule.action, RuleAction::Allow);
                assert_eq!(rule.duration, RuleDuration::UntilRestart);
                assert!(rule.process_name.is_none());
            }
            _ => panic!("expected AddRule"),
        }
    }

    #[test]
    fn add_rule_deny_permanent_with_process() {
        let args = [
            "add-rule", "r1", "ads.google.com",
            "--action", "deny",
            "--duration", "permanent",
            "--process", "firefox",
        ]
        .map(String::from)
        .to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        match req {
            ControlRequest::AddRule(rule) => {
                assert_eq!(rule.action, RuleAction::Deny);
                assert_eq!(rule.duration, RuleDuration::Permanent);
                assert_eq!(rule.process_name, Some("firefox".to_string()));
            }
            _ => panic!("expected AddRule"),
        }
    }

    #[test]
    fn add_rule_wildcard_destination_detected() {
        let args = ["add-rule", "r1", "*.example.com"].map(String::from).to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        match req {
            ControlRequest::AddRule(rule) => {
                assert_eq!(
                    rule.destination,
                    DestinationMatcher::DomainWildcard("example.com".to_string())
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn add_rule_cidr_destination_detected() {
        let args = ["add-rule", "r1", "10.0.0.0/8", "--action", "deny"]
            .map(String::from)
            .to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        match req {
            ControlRequest::AddRule(rule) => {
                assert_eq!(rule.destination, DestinationMatcher::Cidr("10.0.0.0/8".to_string()));
                assert_eq!(rule.action, RuleAction::Deny);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn add_rule_ip_exact_destination_detected() {
        let args = ["add-rule", "r1", "1.1.1.1"].map(String::from).to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        match req {
            ControlRequest::AddRule(rule) => {
                assert_eq!(rule.destination, DestinationMatcher::IpExact("1.1.1.1".to_string()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_list_flows_default_limit() {
        let args = ["list-flows"].map(String::from).to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        assert_eq!(req, ControlRequest::ListFlows { limit: DEFAULT_FLOW_LIST_LIMIT });
    }

    #[test]
    fn parses_list_flows_custom_limit() {
        let args = ["list-flows", "--limit", "10"].map(String::from).to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        assert_eq!(req, ControlRequest::ListFlows { limit: 10 });
    }

    #[test]
    fn parses_unlock_command() {
        let args = ["unlock"].map(String::from).to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        assert_eq!(req, ControlRequest::Unlock);
    }

    #[test]
    fn parses_delete_rule_request() {
        let args = ["delete-rule", "r1"].map(String::from).to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        assert_eq!(req, (ControlRequest::DeleteRule { id: "r1".to_string() }, OutputMode::Text).0);
    }

    #[test]
    fn parses_list_rules_request() {
        let args = ["list-rules"].map(String::from).to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        assert_eq!(req, ControlRequest::ListRules);
    }

    #[test]
    fn parses_list_pendings_request() {
        let args = ["list-pendings"].map(String::from).to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        assert_eq!(req, ControlRequest::ListPending);
    }

    #[test]
    fn rejects_unknown_command() {
        let args = ["what"].map(String::from).to_vec();
        let err = parse_request(&args).expect_err("must fail");
        assert_eq!(err, "unknown command");
    }

    #[test]
    fn parses_resolve_pending_request() {
        let args = ["resolve-pending", "pending-1", "deny"].map(String::from).to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        assert_eq!(
            req,
            ControlRequest::ResolvePending {
                pending_id: "pending-1".to_string(),
                action: RuleAction::Deny
            }
        );
    }

    #[test]
    fn parse_register_flow_supports_missing_domain() {
        let args = ["register-flow", "curl", "1.1.1.1", "-", "tcp", "100"]
            .map(String::from)
            .to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        match req {
            ControlRequest::RegisterUnknownFlow { flow, now_secs } => {
                assert_eq!(flow.destination_domain, None);
                assert_eq!(flow.protocol, TransportProtocol::Tcp);
                assert_eq!(now_secs, 100);
            }
            _ => panic!("expected register-flow"),
        }
    }

    #[test]
    fn parses_show_config_as_json_health_request() {
        let args = ["show-config"].map(String::from).to_vec();
        let (req, mode) = parse_request(&args).expect("must parse");
        assert_eq!(req, ControlRequest::Health);
        assert_eq!(mode, OutputMode::Json);
    }

    #[test]
    fn add_rule_route_action_with_egress() {
        let args = [
            "add-rule", "r1", "example.com",
            "--action", "route",
            "--egress", "eg-vpn",
            "--duration", "permanent",
        ]
        .map(String::from)
        .to_vec();
        let (req, _) = parse_request(&args).expect("must parse");
        match req {
            ControlRequest::AddRule(rule) => {
                assert_eq!(rule.action, RuleAction::Route);
                assert_eq!(rule.egress_id, Some("eg-vpn".to_string()));
                assert_eq!(rule.duration, RuleDuration::Permanent);
            }
            _ => panic!("expected AddRule"),
        }
    }

    #[test]
    fn parses_global_json_flag_for_other_commands() {
        let args = ["--json", "health"].map(String::from).to_vec();
        let (req, mode) = parse_request(&args).expect("must parse");
        assert_eq!(req, ControlRequest::Health);
        assert_eq!(mode, OutputMode::Json);
    }
}
