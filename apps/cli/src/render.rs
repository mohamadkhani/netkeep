use control_api::ControlResponse;

use crate::Format;

use core_types::{
    DestinationMatcher, Egress, FlowContext, FlowDirection, FlowEvent, FlowState, PendingDecision,
    ProxyAuth, ProxyConfig, ProxyProtocol, RouteTarget, Rule, RuleAction, RuleDuration,
    TransportProtocol,
};
use tabled::{settings::{Alignment, Padding, Style}, Table};

/// Apply a modern Unicode box style to a built table.
fn styled(mut table: Table) -> Table {
    table.with(Style::modern()).with(Padding::new(1, 1, 0, 0)).with(Alignment::left());
    table
}

/// Render a daemon response using the requested format.
pub fn render(response: &ControlResponse, format: Format) -> Result<String, String> {
    match format {
        Format::Json => serde_json::to_string_pretty(response).map_err(|e| e.to_string()),
        Format::Yaml => serde_yaml::to_string(response).map_err(|e| e.to_string()),
        Format::Table => render_table(response),
        Format::Text => render_text(response),
        Format::Md => render_md(response),
    }
}

// ---------- table ----------

fn render_table(response: &ControlResponse) -> Result<String, String> {
    match response {
        ControlResponse::RuleList(rules) => render_rules_table(rules),
        ControlResponse::PendingList(pendings) => render_pending_table(pendings),
        ControlResponse::FlowList(flows) => render_flows_table(flows),
        ControlResponse::EgressList(egresses) => render_egress_table(egresses),
        ControlResponse::ProxyList(proxies) => render_proxy_table(proxies),
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
        } => render_health_table(
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
        ),
        ControlResponse::NfqueueStatus { enabled, queue_num } => {
            render_nfqueue_status_table(enabled, queue_num)
        }
        ControlResponse::Ok => Ok("ok".to_string()),
        ControlResponse::PendingCreated { pending_id, .. } => {
            Ok(format!("pending created: {}", pending_id))
        }
        ControlResponse::ImmediateVerdict { action, .. } => Ok(format_verdict(action).to_string()),
        ControlResponse::PendingStillWaiting { pending_id } => {
            Ok(format!("pending {} still waiting", pending_id))
        }
        ControlResponse::PendingResolved { action, .. } => Ok(format_verdict(action).to_string()),
        ControlResponse::SubscriptionAck => {
            Ok("listening for pending decisions (push subscription active)".to_string())
        }
        ControlResponse::Unlocked => Ok("nftables rules removed (unlocked)".to_string()),
        ControlResponse::RoutedTcpReady { listen_addr } => {
            Ok(format!("routed TCP relay listening on {}", listen_addr))
        }
        ControlResponse::ProxyTestResult {
            success,
            latency_ms,
            error,
        } => {
            if let Some(err) = error {
                Err(format!("proxy test failed: {}", err))
            } else {
                Ok(format!(
                    "proxy test {} (latency: {}ms)",
                    if *success { "ok" } else { "failed" },
                    latency_ms
                ))
            }
        }
        ControlResponse::Error(msg) => Err(format!("daemon error: {}", msg)),
    }
}

fn render_rules_table(rules: &[Rule]) -> Result<String, String> {
    if rules.is_empty() {
        return Ok("no rules installed".to_string());
    }
    let mut builder = tabled::builder::Builder::new();
    builder.push_record(["id", "action", "process", "destination", "duration"]);
    for rule in rules {
        let destination = destination_str(&rule.destination);
        let cells: Vec<&str> = vec![
            rule.id.as_str(),
            format_action(&rule.action),
            rule.process_name.as_deref().unwrap_or("-"),
            destination.as_str(),
            format_duration(&rule.duration),
        ];
        builder.push_record(cells);
    }
    Ok(styled(builder.build()).to_string())
}

fn render_pending_table(pendings: &[PendingDecision]) -> Result<String, String> {
    if pendings.is_empty() {
        return Ok("no pending decisions".to_string());
    }
    let mut builder = tabled::builder::Builder::new();
    builder.push_record(["id", "process", "destination", "protocol"]);
    for p in pendings {
        let destination = destination_cell(&p.flow);
        let cells: Vec<&str> = vec![
            p.id.as_str(),
            p.flow.process_name.as_deref().unwrap_or("-"),
            destination.as_str(),
            transport_str(&p.flow.protocol),
        ];
        builder.push_record(cells);
    }
    Ok(styled(builder.build()).to_string())
}

fn render_flows_table(flows: &[FlowEvent]) -> Result<String, String> {
    if flows.is_empty() {
        return Ok("no flows".to_string());
    }
    let mut builder = tabled::builder::Builder::new();
    builder.push_record(["id", "process", "destination", "protocol", "state"]);
    for f in flows {
        let destination = destination_cell(f);
        let cells: Vec<&str> = vec![
            f.id.as_str(),
            f.process_name.as_deref().unwrap_or("-"),
            destination.as_str(),
            transport_str(&f.protocol),
            flow_state_str(&f.state),
        ];
        builder.push_record(cells);
    }
    Ok(styled(builder.build()).to_string())
}

fn render_egress_table(egresses: &[Egress]) -> Result<String, String> {
    if egresses.is_empty() {
        return Ok("no egresses".to_string());
    }
    let mut builder = tabled::builder::Builder::new();
    builder.push_record([
        "id",
        "name",
        "targets",
        "dns_servers",
        "system_default",
        "available",
        "color",
    ]);
    for e in egresses {
        let targets: Vec<String> = e
            .targets
            .iter()
            .map(|t| match t {
                RouteTarget::Tun(v) => format!("tun: {}", v),
                RouteTarget::Device(v) => format!("dev: {}", v),
                RouteTarget::Proxy(v) => format!("proxy: {}", v),
            })
            .collect();
        let dns: Vec<String> = e.dns_servers.iter().map(|s| s.clone()).collect();
        builder.push_record([
            e.id.as_str(),
            e.name.as_str(),
            targets.join(", ").as_str(),
            dns.join(", ").as_str(),
            if e.is_system_default { "yes" } else { "no" },
            if e.is_available { "yes" } else { "no" },
            e.color.as_str(),
        ]);
    }
    Ok(styled(builder.build()).to_string())
}

fn render_proxy_table(proxies: &[ProxyConfig]) -> Result<String, String> {
    if proxies.is_empty() {
        return Ok("no proxies".to_string());
    }
    let mut builder = tabled::builder::Builder::new();
    builder.push_record(["id", "name", "protocol", "host:port", "auth", "enabled"]);
    for p in proxies {
        let addr = format!("{}:{}", p.host, p.port);
        builder.push_record([
            p.id.as_str(),
            p.name.as_str(),
            format_proxy_protocol(&p.protocol),
            addr.as_str(),
            format_proxy_auth(&p.auth).as_str(),
            if p.enabled { "yes" } else { "no" },
        ]);
    }
    Ok(styled(builder.build()).to_string())
}

fn render_health_table(
    ready: &bool,
    fail_close_active: &bool,
    pending_limit: &usize,
    default_timeout_secs: &u64,
    tcp_timeout_secs: &u64,
    udp_timeout_secs: &u64,
    quic_timeout_secs: &u64,
    other_timeout_secs: &u64,
    nfqueue_enabled: &bool,
    nfqueue_num: &Option<u16>,
) -> Result<String, String> {
    let mut builder = tabled::builder::Builder::new();
    builder.push_record(["setting", "value"]);
    builder.push_record(["ready", if *ready { "yes" } else { "no" }]);
    builder.push_record([
        "fail_close_active",
        if *fail_close_active { "yes" } else { "no" },
    ]);
    builder.push_record(["pending_limit", &pending_limit.to_string()]);
    builder.push_record(["default_timeout_secs", &default_timeout_secs.to_string()]);
    builder.push_record(["tcp_timeout_secs", &tcp_timeout_secs.to_string()]);
    builder.push_record(["udp_timeout_secs", &udp_timeout_secs.to_string()]);
    builder.push_record(["quic_timeout_secs", &quic_timeout_secs.to_string()]);
    builder.push_record(["other_timeout_secs", &other_timeout_secs.to_string()]);
    builder.push_record([
        "nfqueue_enabled",
        if *nfqueue_enabled { "yes" } else { "no" },
    ]);
    builder.push_record([
        "nfqueue_num",
        &nfqueue_num.map_or("n/a".to_string(), |n| n.to_string()),
    ]);
    Ok(styled(builder.build()).to_string())
}

fn render_nfqueue_status_table(enabled: &bool, queue_num: &Option<u16>) -> Result<String, String> {
    let mut builder = tabled::builder::Builder::new();
    builder.push_record(["setting", "value"]);
    builder.push_record(["nfqueue enabled", if *enabled { "yes" } else { "no" }]);
    builder.push_record([
        "queue num",
        &queue_num.map_or("n/a".to_string(), |n| n.to_string()),
    ]);
    Ok(styled(builder.build()).to_string())
}  
  // ---------- text ----------

fn render_text(response: &ControlResponse) -> Result<String, String> {
    match response {
        ControlResponse::RuleList(rules) => {
            let mut out = String::new();
            if rules.is_empty() {
                return Ok("no rules installed".to_string());
            }
            for rule in rules {
                out.push_str(&format!(
                    "rule {} ({}) process={} destination={} duration={}\n",
                    rule.id,
                    format_action(&rule.action),
                    rule.process_name.as_deref().unwrap_or("-"),
                    destination_str(&rule.destination),
                    format_duration(&rule.duration),
                ));
            }
            Ok(out.trim_end().to_string())
        }
        ControlResponse::PendingList(pendings) => {
            let mut out = String::new();
            if pendings.is_empty() {
                return Ok("no pending decisions".to_string());
            }
            for p in pendings {
                out.push_str(&format!(
                    "pending {} process={} destination={} protocol={}\n",
                    p.id,
                    p.flow.process_name.as_deref().unwrap_or("-"),
                    destination_ip_domain(&p.flow),
                    transport_str(&p.flow.protocol),
                ));
            }
            Ok(out.trim_end().to_string())
        }
        ControlResponse::FlowList(flows) => {
            let mut out = String::new();
            if flows.is_empty() {
                return Ok("no flows".to_string());
            }
            for f in flows {
                out.push_str(&format!(
                    "flow {} process={} destination={} protocol={} state={}\n",
                    f.id,
                    f.process_name.as_deref().unwrap_or("-"),
                    destination_ip_domain(f),
                    transport_str(&f.protocol),
                    flow_state_str(&f.state),
                ));
            }
            Ok(out.trim_end().to_string())
        }
        ControlResponse::EgressList(egresses) => {
            let mut out = String::new();
            if egresses.is_empty() {
                return Ok("no egresses".to_string());
            }
            for e in egresses {
                out.push_str(&format!(
                    "egress {} name={} targets={} dns={}\n",
                    e.id,
                    e.name,
                    e.targets
                        .iter()
                        .map(|t| match t {
                            RouteTarget::Tun(v) => format!("tun:{}", v),
                            RouteTarget::Device(v) => format!("dev:{}", v),
                            RouteTarget::Proxy(v) => format!("proxy:{}", v),
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                    e.dns_servers.join(",")
                ));
            }
            Ok(out.trim_end().to_string())
        }
        ControlResponse::ProxyList(proxies) => {
            let mut out = String::new();
            if proxies.is_empty() {
                return Ok("no proxies".to_string());
            }
            for p in proxies {
                out.push_str(&format!(
                    "proxy {} name={} protocol={} addr={} auth={} enabled={}\n",
                    p.id,
                    p.name,
                    format_proxy_protocol(&p.protocol),
                    format!("{}:{}", p.host, p.port),
                    format_proxy_auth(&p.auth),
                    p.enabled,
                ));
            }
            Ok(out.trim_end().to_string())
        }
        ControlResponse::Health {
            ready,
            pending_limit,
            default_timeout_secs,
            tcp_timeout_secs,
            udp_timeout_secs,
            quic_timeout_secs,
            other_timeout_secs,
            nfqueue_enabled,
            nfqueue_num,
            ..
        } => {
            let mut out = String::new();
            out.push_str(&format!("ready={}\n", ready));
            out.push_str(&format!("pending_limit={}\n", pending_limit));
            out.push_str(&format!("default_timeout_secs={}\n", default_timeout_secs));
            out.push_str(&format!("tcp_timeout_secs={}\n", tcp_timeout_secs));
            out.push_str(&format!("udp_timeout_secs={}\n", udp_timeout_secs));
            out.push_str(&format!("quic_timeout_secs={}\n", quic_timeout_secs));
            out.push_str(&format!("other_timeout_secs={}\n", other_timeout_secs));
            out.push_str(&format!("nfqueue_enabled={}\n", nfqueue_enabled));
            out.push_str(&format!("nfqueue_num={:?}\n", nfqueue_num));
            Ok(out.trim_end().to_string())
        }
        ControlResponse::NfqueueStatus { enabled, queue_num } => Ok(format!(
            "nfqueue enabled={}\nqueue_num={:?}",
            enabled, queue_num
        )),
        ControlResponse::Ok => Ok("ok".to_string()),
        ControlResponse::PendingCreated { pending_id, .. } => {
            Ok(format!("pending created: {}", pending_id))
        }
        ControlResponse::ImmediateVerdict { action, .. } => Ok(format_verdict(action).to_string()),
        ControlResponse::PendingStillWaiting { pending_id } => {
            Ok(format!("pending {} still waiting", pending_id))
        }
        ControlResponse::PendingResolved { action, .. } => Ok(format_verdict(action).to_string()),
        ControlResponse::SubscriptionAck => {
            Ok("listening for pending decisions (push subscription active)".to_string())
        }
        ControlResponse::Unlocked => Ok("nftables rules removed (unlocked)".to_string()),
        ControlResponse::RoutedTcpReady { listen_addr } => {
            Ok(format!("routed TCP relay listening on {}", listen_addr))
        }
        ControlResponse::ProxyTestResult {
            success,
            latency_ms,
            error,
        } => {
            if let Some(err) = error {
                Err(format!("proxy test failed: {}", err))
            } else {
                Ok(format!(
                    "proxy test {} (latency: {}ms)",
                    if *success { "ok" } else { "failed" },
                    latency_ms
                ))
            }
        }
        ControlResponse::Error(msg) => Err(format!("daemon error: {}", msg)),
    }
}

// ---------- md ----------

fn render_md(response: &ControlResponse) -> Result<String, String> {
    match response {
        ControlResponse::RuleList(rules) => render_rules_table(rules),
        ControlResponse::PendingList(pendings) => render_pending_md(pendings),
        ControlResponse::FlowList(flows) => render_flows_md(flows),
        ControlResponse::EgressList(egresses) => render_egress_md(egresses),
        ControlResponse::ProxyList(proxies) => render_proxy_md(proxies),
        ControlResponse::Health {
            ready,
            pending_limit,
            default_timeout_secs,
            tcp_timeout_secs,
            udp_timeout_secs,
            quic_timeout_secs,
            other_timeout_secs,
            nfqueue_enabled,
            nfqueue_num,
            ..
        } => render_health_md(
            ready,
            pending_limit,
            default_timeout_secs,
            tcp_timeout_secs,
            udp_timeout_secs,
            quic_timeout_secs,
            other_timeout_secs,
            nfqueue_enabled,
            nfqueue_num,
        ),
        ControlResponse::NfqueueStatus { enabled, queue_num } => {
            render_nfqueue_status_md(enabled, queue_num)
        }
        ControlResponse::Ok
        | ControlResponse::PendingCreated { .. }
        | ControlResponse::ImmediateVerdict { .. }
        | ControlResponse::PendingStillWaiting { .. }
        | ControlResponse::PendingResolved { .. }
        | ControlResponse::SubscriptionAck
        | ControlResponse::Unlocked
        | ControlResponse::RoutedTcpReady { .. }
        | ControlResponse::ProxyTestResult { .. } => Ok(render_single(response)),
        ControlResponse::Error(msg) => Err(format!("daemon error: {}", msg)),
    }
}

fn render_single(response: &ControlResponse) -> String {
    match response {
        ControlResponse::Ok => "ok".to_string(),
        ControlResponse::PendingCreated { pending_id, .. } => {
            format!("pending created: {}", pending_id)
        }
        ControlResponse::ImmediateVerdict { action, .. } => format_verdict(action).to_string(),
        ControlResponse::PendingStillWaiting { pending_id } => {
            format!("pending {} still waiting", pending_id)
        }
        ControlResponse::PendingResolved { action, .. } => format_verdict(action).to_string(),
        ControlResponse::SubscriptionAck => {
            "listening for pending decisions (push subscription active)".to_string()
        }
        ControlResponse::Unlocked => "nftables rules removed (unlocked)".to_string(),
        ControlResponse::RoutedTcpReady { listen_addr } => {
            format!("routed TCP relay listening on {}", listen_addr)
        }
        ControlResponse::ProxyTestResult {
            success,
            latency_ms,
            error,
        } => {
            if let Some(err) = error {
                format!("proxy test failed: {}", err)
            } else {
                format!(
                    "proxy test {} (latency: {}ms)",
                    if *success { "ok" } else { "failed" },
                    latency_ms
                )
            }
        }
        _ => unreachable!(),
    }
}

fn render_rules_md(rules: &[Rule]) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("## Rules\n\n");
    if rules.is_empty() {
        return Ok(out.trim_end().to_string());
    }
    out.push_str("| id | action | process | destination | duration |\n");
    out.push_str("| --- | --- | --- | --- | --- |\n");
    for rule in rules {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            rule.id,
            format_action(&rule.action),
            rule.process_name.as_deref().unwrap_or("-"),
            destination_str(&rule.destination),
            format_duration(&rule.duration),
        ));
    }
    Ok(out.trim_end().to_string())
}

fn render_pending_md(pendings: &[PendingDecision]) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("## Pending\n\n");
    if pendings.is_empty() {
        return Ok(out.trim_end().to_string());
    }
    out.push_str("| id | process | destination | protocol |\n");
    out.push_str("| --- | --- | --- | --- |\n");
    for p in pendings {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            p.id,
            p.flow.process_name.as_deref().unwrap_or("-"),
            destination_ip_domain(&p.flow),
            transport_str(&p.flow.protocol),
        ));
    }
    Ok(out.trim_end().to_string())
}

fn render_flows_md(flows: &[FlowEvent]) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("## Flows\n\n");
    if flows.is_empty() {
        return Ok(out.trim_end().to_string());
    }
    out.push_str("| id | process | destination | protocol | state |\n");
    out.push_str("| --- | --- | --- | --- | --- |\n");
    for f in flows {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            f.id,
            f.process_name.as_deref().unwrap_or("-"),
            destination_ip_domain(f),
            transport_str(&f.protocol),
            flow_state_str(&f.state),
        ));
    }
    Ok(out.trim_end().to_string())
}

fn render_egress_md(egresses: &[Egress]) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("## Egresses\n\n");
    if egresses.is_empty() {
        return Ok(out.trim_end().to_string());
    }
    out.push_str("| id | name | targets | dns_servers | system_default | available | color |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for e in egresses {
        let targets: Vec<String> = e
            .targets
            .iter()
            .map(|t| match t {
                RouteTarget::Tun(v) => format!("tun:{}", v),
                RouteTarget::Device(v) => format!("dev:{}", v),
                RouteTarget::Proxy(v) => format!("proxy:{}", v),
            })
            .collect();
        let dns: Vec<String> = e.dns_servers.iter().map(|s| s.clone()).collect();
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            e.id,
            e.name,
            targets.join(","),
            dns.join(","),
            if e.is_system_default { "yes" } else { "no" },
            if e.is_available { "yes" } else { "no" },
            e.color,
        ));
    }
    Ok(out.trim_end().to_string())
}

fn render_proxy_md(proxies: &[ProxyConfig]) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("## Proxies\n\n");
    if proxies.is_empty() {
        return Ok(out.trim_end().to_string());
    }
    out.push_str("| id | name | protocol | host:port | auth | enabled |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for p in proxies {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            p.id,
            p.name,
            format_proxy_protocol(&p.protocol),
            format!("{}:{}", p.host, p.port),
            format_proxy_auth(&p.auth),
            if p.enabled { "yes" } else { "no" },
        ));
    }
    Ok(out.trim_end().to_string())
}

fn render_health_md(
    ready: &bool,
    pending_limit: &usize,
    default_timeout_secs: &u64,
    tcp_timeout_secs: &u64,
    udp_timeout_secs: &u64,
    quic_timeout_secs: &u64,
    other_timeout_secs: &u64,
    nfqueue_enabled: &bool,
    nfqueue_num: &Option<u16>,
) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("## Health\n\n");
    out.push_str("| setting | value |\n");
    out.push_str("| --- | --- |\n");
    out.push_str(&format!("| ready | {} |\n", ready));
    out.push_str(&format!("| pending_limit | {} |\n", pending_limit));
    out.push_str(&format!(
        "| default_timeout_secs | {} |\n",
        default_timeout_secs
    ));
    out.push_str(&format!("| tcp_timeout_secs | {} |\n", tcp_timeout_secs));
    out.push_str(&format!("| udp_timeout_secs | {} |\n", udp_timeout_secs));
    out.push_str(&format!("| quic_timeout_secs | {} |\n", quic_timeout_secs));
    out.push_str(&format!(
        "| other_timeout_secs | {} |\n",
        other_timeout_secs
    ));
    out.push_str(&format!("| nfqueue_enabled | {} |\n", nfqueue_enabled));
    out.push_str(&format!("| nfqueue_num | {:?} |\n", nfqueue_num));
    Ok(out.trim_end().to_string())
}

fn render_nfqueue_status_md(enabled: &bool, queue_num: &Option<u16>) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("## NFQUEUE Status\n\n");
    out.push_str("| setting | value |\n");
    out.push_str("| --- | --- |\n");
    out.push_str(&format!("| enabled | {} |\n", enabled));
    out.push_str(&format!("| queue num | {:?} |\n", queue_num));
    Ok(out.trim_end().to_string())
}

// ---------- helpers ----------

fn format_action(action: &RuleAction) -> &'static str {
    match action {
        RuleAction::Allow => "allow",
        RuleAction::Deny => "deny",
        RuleAction::Ask => "ask",
        RuleAction::Route => "route",
    }
}

fn format_duration(duration: &RuleDuration) -> &'static str {
    match duration {
        RuleDuration::UntilRestart => "until-restart",
        RuleDuration::Permanent => "permanent",
    }
}

fn format_verdict(action: &RuleAction) -> &'static str {
    match action {
        RuleAction::Allow => "verdict: allow",
        RuleAction::Deny => "verdict: deny",
        RuleAction::Ask => "verdict: ask",
        RuleAction::Route => "verdict: route",
    }
}

fn destination_str(d: &DestinationMatcher) -> String {
    match d {
        DestinationMatcher::IpExact(v)
        | DestinationMatcher::Cidr(v)
        | DestinationMatcher::DomainExact(v)
        | DestinationMatcher::DomainWildcard(v) => v,
        DestinationMatcher::Any => "any",
    }
    .to_string()
}

fn destination_cell<F: DestinationFlow>(flow: &F) -> String {
    // For table cells we only show the IP to keep columns narrow.
    flow.destination_ip_str()
}

fn transport_str(protocol: &TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
        TransportProtocol::Quic => "quic",
        TransportProtocol::Other => "other",
    }
}

fn flow_state_str(state: &FlowState) -> &'static str {
    match state {
        FlowState::Pending => "pending",
        FlowState::Allowed => "allowed",
        FlowState::Denied => "denied",
        FlowState::Expired => "expired",
    }
}

trait DestinationFlow {
    fn destination_ip_str(&self) -> String;
    fn destination_domain_str(&self) -> Option<String>;
}

impl DestinationFlow for FlowContext {
    fn destination_ip_str(&self) -> String {
        self.destination_ip.clone()
    }
    fn destination_domain_str(&self) -> Option<String> {
        self.destination_domain.clone()
    }
}

impl DestinationFlow for FlowEvent {
    fn destination_ip_str(&self) -> String {
        self.destination_ip.clone()
    }
    fn destination_domain_str(&self) -> Option<String> {
        self.destination_domain.clone()
    }
}

fn destination_ip_domain<F: DestinationFlow>(flow: &F) -> String {
    if let Some(domain) = flow.destination_domain_str() {
        format!("{} ({})", flow.destination_ip_str(), domain)
    } else {
        flow.destination_ip_str()
    }
}

fn format_proxy_protocol(protocol: &ProxyProtocol) -> &'static str {
    match protocol {
        ProxyProtocol::Http => "http",
        ProxyProtocol::Socks5 => "socks5",
        ProxyProtocol::Shadowsocks => "shadowsocks",
    }
}

fn format_proxy_auth(auth: &ProxyAuth) -> String {
    match auth {
        ProxyAuth::None => "none".to_string(),
        ProxyAuth::Basic { username, .. } => format!("basic:{}", username),
        ProxyAuth::Shadowsocks { method, .. } => format!("ss({})", method),
    }
}
