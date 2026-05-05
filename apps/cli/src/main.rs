use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use core_types::{DestinationMatcher, FlowContext, Rule, RuleAction, RuleDuration, TransportProtocol};
use control_api::{ControlRequest, ControlResponse};
use serde_json::json;

const DEFAULT_SOCKET_PATH: &str = "/tmp/logiguard.sock";

fn build_rule(id: &str, destination: &str) -> Rule {
    Rule {
        id: id.to_string(),
        enabled: true,
        action: RuleAction::Allow,
        duration: RuleDuration::UntilRestart,
        process_name: None,
        destination: DestinationMatcher::DomainExact(destination.to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Text,
    Json,
}

fn parse_request(args: &[String]) -> Result<(ControlRequest, OutputMode), String> {
    let (output_mode, cmd_args): (OutputMode, &[String]) =
        if args.first().map(|s| s.as_str()) == Some("--json") {
            (OutputMode::Json, &args[1..])
        } else {
            (OutputMode::Text, args)
        };

    if cmd_args.is_empty() {
        return Err("usage: add-rule <id> <domain> | list-rules | delete-rule <id> | register-flow <process> <ip> <domain|-> <tcp|udp|quic|other> <now-secs> | resolve-pending <id> <allow|deny|ask> | health | show-config".to_string());
    }

    match cmd_args[0].as_str() {
        "add-rule" => {
            if cmd_args.len() != 3 {
                return Err("usage: add-rule <id> <domain>".to_string());
            }
            Ok((
                ControlRequest::AddRule(build_rule(&cmd_args[1], &cmd_args[2])),
                output_mode,
            ))
        }
        "list-rules" => Ok((ControlRequest::ListRules, output_mode)),
        "delete-rule" => {
            if cmd_args.len() != 2 {
                return Err("usage: delete-rule <id>".to_string());
            }
            Ok((
                ControlRequest::DeleteRule {
                    id: cmd_args[1].clone(),
                },
                output_mode,
            ))
        }
        "register-flow" => {
            if cmd_args.len() != 6 {
                return Err("usage: register-flow <process> <ip> <domain|-> <tcp|udp|quic|other> <now-secs>".to_string());
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
            let domain = if cmd_args[3] == "-" {
                None
            } else {
                Some(cmd_args[3].clone())
            };
            Ok((
                ControlRequest::RegisterUnknownFlow {
                    flow: FlowContext {
                        process_name: Some(cmd_args[1].clone()),
                        destination_ip: cmd_args[2].clone(),
                        destination_domain: domain,
                        protocol,
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
                    .map(|r| format!("{} {:?}", r.id, r.destination))
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
            "pending created id={pending_id} protocol={protocol:?} created_at_secs={created_at_secs} deadline_at_secs={deadline_at_secs}"
        )),
        ControlResponse::ImmediateVerdict { action } => {
            Ok(format!("immediate verdict={action:?}"))
        }
        ControlResponse::PendingResolved { action } => Ok(format!("pending resolved action={action:?}")),
        ControlResponse::Health {
            ready,
            fail_close_active,
            pending_limit,
            default_timeout_secs,
            tcp_timeout_secs,
            udp_timeout_secs,
            quic_timeout_secs,
            other_timeout_secs,
        } => Ok(format!(
            "ready={ready} fail_close_active={fail_close_active} pending_limit={pending_limit} default_timeout_secs={default_timeout_secs} tcp_timeout_secs={tcp_timeout_secs} udp_timeout_secs={udp_timeout_secs} quic_timeout_secs={quic_timeout_secs} other_timeout_secs={other_timeout_secs}"
        )),
        ControlResponse::Error(err) => Err(err),
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
    fn parses_add_rule_request() {
        let args = vec![
            "add-rule".to_string(),
            "r1".to_string(),
            "example.com".to_string(),
        ];
        let req = parse_request(&args).expect("must parse");
        match req {
            (ControlRequest::AddRule(rule), OutputMode::Text) => {
                assert_eq!(rule.id, "r1");
                assert_eq!(
                    rule.destination,
                    DestinationMatcher::DomainExact("example.com".to_string())
                );
            }
            _ => panic!("expected add-rule"),
        }
    }

    #[test]
    fn parses_delete_rule_request() {
        let args = vec!["delete-rule".to_string(), "r1".to_string()];
        let req = parse_request(&args).expect("must parse");
        assert_eq!(
            req,
            (
                ControlRequest::DeleteRule { id: "r1".to_string() },
                OutputMode::Text
            )
        );
    }

    #[test]
    fn parses_list_rules_request() {
        let args = vec!["list-rules".to_string()];
        let req = parse_request(&args).expect("must parse");
        assert_eq!(req, (ControlRequest::ListRules, OutputMode::Text));
    }

    #[test]
    fn rejects_unknown_command() {
        let args = vec!["what".to_string()];
        let err = parse_request(&args).expect_err("must fail");
        assert_eq!(err, "unknown command");
    }

    #[test]
    fn parses_resolve_pending_request() {
        let args = vec![
            "resolve-pending".to_string(),
            "pending-1".to_string(),
            "deny".to_string(),
        ];
        let req = parse_request(&args).expect("must parse");
        assert_eq!(
            req,
            (
                ControlRequest::ResolvePending {
                    pending_id: "pending-1".to_string(),
                    action: RuleAction::Deny
                },
                OutputMode::Text
            )
        );
    }

    #[test]
    fn parse_register_flow_supports_missing_domain() {
        let args = vec![
            "register-flow".to_string(),
            "curl".to_string(),
            "1.1.1.1".to_string(),
            "-".to_string(),
            "tcp".to_string(),
            "100".to_string(),
        ];
        let req = parse_request(&args).expect("must parse");
        match req {
            (ControlRequest::RegisterUnknownFlow { flow, now_secs }, OutputMode::Text) => {
                assert_eq!(flow.destination_domain, None);
                assert_eq!(flow.protocol, TransportProtocol::Tcp);
                assert_eq!(now_secs, 100);
            }
            _ => panic!("expected register-flow"),
        }
    }

    #[test]
    fn parses_show_config_as_json_health_request() {
        let args = vec!["show-config".to_string()];
        let req = parse_request(&args).expect("must parse");
        assert_eq!(req, (ControlRequest::Health, OutputMode::Json));
    }

    #[test]
    fn parses_global_json_flag_for_other_commands() {
        let args = vec!["--json".to_string(), "health".to_string()];
        let req = parse_request(&args).expect("must parse");
        assert_eq!(req, (ControlRequest::Health, OutputMode::Json));
    }
}

