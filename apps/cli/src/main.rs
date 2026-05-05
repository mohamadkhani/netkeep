use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use core_types::{DestinationMatcher, FlowContext, Rule, RuleAction, RuleDuration};
use control_api::{ControlRequest, ControlResponse};

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

fn parse_request(args: &[String]) -> Result<ControlRequest, String> {
    if args.is_empty() {
        return Err("usage: add-rule <id> <domain> | list-rules | delete-rule <id> | register-flow <process> <ip> <domain|-] <now-secs> | resolve-pending <id> <allow|deny|ask> | health".to_string());
    }

    match args[0].as_str() {
        "add-rule" => {
            if args.len() != 3 {
                return Err("usage: add-rule <id> <domain>".to_string());
            }
            Ok(ControlRequest::AddRule(build_rule(&args[1], &args[2])))
        }
        "list-rules" => Ok(ControlRequest::ListRules),
        "delete-rule" => {
            if args.len() != 2 {
                return Err("usage: delete-rule <id>".to_string());
            }
            Ok(ControlRequest::DeleteRule {
                id: args[1].clone(),
            })
        }
        "register-flow" => {
            if args.len() != 5 {
                return Err("usage: register-flow <process> <ip> <domain|-> <now-secs>".to_string());
            }
            let now_secs = args[4]
                .parse::<u64>()
                .map_err(|_| "now-secs must be an unsigned integer".to_string())?;
            let domain = if args[3] == "-" {
                None
            } else {
                Some(args[3].clone())
            };
            Ok(ControlRequest::RegisterUnknownFlow {
                flow: FlowContext {
                    process_name: Some(args[1].clone()),
                    destination_ip: args[2].clone(),
                    destination_domain: domain,
                },
                now_secs,
            })
        }
        "resolve-pending" => {
            if args.len() != 3 {
                return Err("usage: resolve-pending <id> <allow|deny|ask>".to_string());
            }
            let action = match args[2].as_str() {
                "allow" => RuleAction::Allow,
                "deny" => RuleAction::Deny,
                "ask" => RuleAction::Ask,
                _ => return Err("action must be one of: allow, deny, ask".to_string()),
            };
            Ok(ControlRequest::ResolvePending {
                pending_id: args[1].clone(),
                action,
            })
        }
        "health" => Ok(ControlRequest::Health),
        _ => Err("unknown command".to_string()),
    }
}

fn render_response(response: ControlResponse) -> Result<String, String> {
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
            deadline_at_secs,
        } => Ok(format!(
            "pending created id={pending_id} deadline_at_secs={deadline_at_secs}"
        )),
        ControlResponse::ImmediateVerdict { action } => {
            Ok(format!("immediate verdict={action:?}"))
        }
        ControlResponse::PendingResolved { action } => Ok(format!("pending resolved action={action:?}")),
        ControlResponse::Health {
            ready,
            fail_close_active,
        } => Ok(format!(
            "ready={ready} fail_close_active={fail_close_active}"
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
    let request = match parse_request(&args) {
        Ok(req) => req,
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
    match render_response(response) {
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
            ControlRequest::AddRule(rule) => {
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
        assert_eq!(req, ControlRequest::DeleteRule { id: "r1".to_string() });
    }

    #[test]
    fn parses_list_rules_request() {
        let args = vec!["list-rules".to_string()];
        let req = parse_request(&args).expect("must parse");
        assert_eq!(req, ControlRequest::ListRules);
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
            ControlRequest::ResolvePending {
                pending_id: "pending-1".to_string(),
                action: RuleAction::Deny
            }
        );
    }

    #[test]
    fn parse_register_flow_supports_missing_domain() {
        let args = vec![
            "register-flow".to_string(),
            "curl".to_string(),
            "1.1.1.1".to_string(),
            "-".to_string(),
            "100".to_string(),
        ];
        let req = parse_request(&args).expect("must parse");
        match req {
            ControlRequest::RegisterUnknownFlow { flow, now_secs } => {
                assert_eq!(flow.destination_domain, None);
                assert_eq!(now_secs, 100);
            }
            _ => panic!("expected register-flow"),
        }
    }
}

