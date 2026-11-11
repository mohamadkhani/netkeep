use control_api::ControlResponse;

use crate::Format;

/// Rule list filters passed from the CLI.
pub struct RuleFilter {
    pub process: Option<String>,
    pub id: Option<String>,
    pub search: Option<String>,
    pub action: Option<String>,
    pub duration: Option<String>,
}

use core_types::{
    DestinationMatcher, Egress, FlowContext, FlowEvent, FlowState, PendingDecision, ProxyAuth,
    ProxyConfig, ProxyProtocol, RouteTarget, Rule, RuleAction, RuleDuration, TransportProtocol,
};
use tabled::{
    settings::{
        object::{Cell, Rows},
        Alignment, Color, Modify, Padding, Style,
    },
    Table,
};

/// Whether ANSI colors should be emitted on stdout.
fn colors_enabled() -> bool {
    use std::io::IsTerminal;

    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if let Some(force) = std::env::var_os("CLICOLOR_FORCE") {
        if force != "0" {
            return true;
        }
    }
    std::io::stdout().is_terminal()
}

/// Apply a standard box style (borders + padding + left alignment).
fn styled(mut table: Table) -> Table {
    table
        .with(Style::modern())
        .with(Padding::new(1, 2, 0, 0))
        .with(Alignment::left());
    if colors_enabled() {
        table.with(Modify::new(Rows::first()).with(Color::FG_YELLOW | Color::BOLD));
    }
    table
}

/// Pick a semantic color for common status values.
fn status_color(value: &str) -> Option<Color> {
    match value.to_ascii_lowercase().as_str() {
        "allow" | "yes" | "ok" | "ready" | "established" | "active" | "available" => {
            Some(Color::FG_GREEN)
        }
        "deny" | "no" | "failed" | "unavailable" | "blocked" | "closed" => Some(Color::FG_RED),
        "ask" | "pending" | "waiting" | "new" => Some(Color::FG_YELLOW),
        "route" => Some(Color::FG_CYAN),
        _ => None,
    }
}

/// Color a single table cell.
fn paint_cell(table: &mut Table, row: usize, col: usize, color: Color) {
    if colors_enabled() {
        table.with(Modify::new(Cell::new(row, col)).with(color | Color::BOLD));
    }
}

/// Color a single table cell when its value has a known status color.
fn paint_status(table: &mut Table, row: usize, col: usize, value: &str) {
    if let Some(color) = status_color(value) {
        paint_cell(table, row, col, color);
    }
}

/// Color for a rule's destination matcher type.
fn destination_color(destination: &DestinationMatcher) -> Color {
    match destination {
        DestinationMatcher::Any => Color::FG_MAGENTA,
        DestinationMatcher::IpExact(_) => Color::FG_BRIGHT_BLUE,
        DestinationMatcher::Cidr(_) => Color::FG_BRIGHT_CYAN,
        DestinationMatcher::DomainExact(_) => Color::FG_GREEN,
        DestinationMatcher::DomainWildcard(_) => Color::FG_YELLOW,
    }
}

/// Color for a destination rendered as text (flows have no matcher type).
fn destination_text_color(value: &str) -> Color {
    if value.eq_ignore_ascii_case("any") {
        Color::FG_MAGENTA
    } else if value.contains('/') {
        Color::FG_BRIGHT_CYAN
    } else if value.parse::<std::net::IpAddr>().is_ok() {
        Color::FG_BRIGHT_BLUE
    } else {
        Color::FG_GREEN
    }
}

/// Render a daemon response using the requested format.
pub fn render(
    response: &ControlResponse,
    format: Format,
    rule_filter: Option<&RuleFilter>,
) -> Result<String, String> {
    match format {
        Format::Json => serde_json::to_string_pretty(response).map_err(|e| e.to_string()),
        Format::Yaml => serde_yaml::to_string(response).map_err(|e| e.to_string()),
        Format::Table => render_table(response, rule_filter),
        Format::Ps => render_ps(response, rule_filter),
        Format::Flat => render_flat(response, rule_filter),
        Format::Text => render_text(response, rule_filter),
        Format::Md => render_md(response, rule_filter),
    }
}

// ---------- ps (docker ps style) ----------

/// Render a columnar, borderless listing with uppercase headers, like `docker ps`.
fn render_ps(response: &ControlResponse, filter: Option<&RuleFilter>) -> Result<String, String> {
    match response {
        ControlResponse::RuleList(rules) => ps_rules(rules, filter),
        ControlResponse::PendingList(pendings) => ps_pending(pendings),
        ControlResponse::FlowList(flows) => ps_flows(flows),
        ControlResponse::EgressList(egresses) => ps_egress(egresses),
        ControlResponse::ProxyList(proxies) => ps_proxy(proxies),
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
        } => ps_health(
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
        ControlResponse::NfqueueStatus { enabled, queue_num } => ps_nfqueue(enabled, queue_num),
        other => render_table(other, filter),
    }
}

fn ps_table(headers: &[&str], rows: Vec<Vec<String>>, destination_col: Option<usize>) -> String {
    let header_cells: Vec<String> = headers.iter().map(|h| h.to_uppercase()).collect();
    let mut widths: Vec<usize> = header_cells.iter().map(|h| h.chars().count()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }

    let mut out = String::new();
    out.push_str(&ps_line(&header_cells, &widths, destination_col, true));
    for row in &rows {
        out.push_str(&ps_line(row, &widths, destination_col, false));
    }
    out.trim_end().to_string()
}

fn ps_line(
    cells: &[String],
    widths: &[usize],
    destination_col: Option<usize>,
    header: bool,
) -> String {
    let mut line = String::new();
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            line.push_str("   ");
        }
        let color = if header {
            Some(Color::FG_YELLOW | Color::BOLD)
        } else if destination_col == Some(i) {
            Some(destination_text_color(cell))
        } else {
            status_color(cell)
        };
        if colors_enabled() {
            if let Some(color) = color {
                line.push_str(color.get_prefix());
                line.push_str(cell);
                line.push_str(color.get_suffix());
            } else {
                line.push_str(cell);
            }
        } else {
            line.push_str(cell);
        }
        let padding = widths[i].saturating_sub(cell.chars().count());
        line.extend(std::iter::repeat_n(' ', padding));
    }
    line.trim_end().to_string() + "\n"
}

fn ps_rules(rules: &[Rule], filter: Option<&RuleFilter>) -> Result<String, String> {
    let filtered = apply_rule_filter(rules, filter);
    if filtered.is_empty() {
        return Ok("no rules installed".to_string());
    }
    let rows = filtered
        .iter()
        .map(|rule| {
            vec![
                rule.id.clone(),
                format_action(&rule.action).to_string(),
                rule.process_name.clone().unwrap_or_else(|| "-".to_string()),
                destination_str(&rule.destination),
                format_duration(&rule.duration).to_string(),
            ]
        })
        .collect();
    Ok(ps_table(
        &["id", "action", "process", "destination", "duration"],
        rows,
        Some(3),
    ))
}

fn ps_pending(pendings: &[PendingDecision]) -> Result<String, String> {
    if pendings.is_empty() {
        return Ok("no pending decisions".to_string());
    }
    let rows = pendings
        .iter()
        .map(|pending| {
            vec![
                pending.id.clone(),
                pending
                    .flow
                    .process_name
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
                destination_cell(&pending.flow),
                transport_str(&pending.flow.protocol).to_string(),
            ]
        })
        .collect();
    Ok(ps_table(
        &["id", "process", "destination", "protocol"],
        rows,
        Some(2),
    ))
}

fn ps_flows(flows: &[FlowEvent]) -> Result<String, String> {
    if flows.is_empty() {
        return Ok("no flows".to_string());
    }
    let rows = flows
        .iter()
        .map(|flow| {
            vec![
                flow.id.clone(),
                flow.process_name.clone().unwrap_or_else(|| "-".to_string()),
                destination_cell(flow),
                transport_str(&flow.protocol).to_string(),
                flow_state_str(&flow.state).to_string(),
            ]
        })
        .collect();
    Ok(ps_table(
        &["id", "process", "destination", "protocol", "state"],
        rows,
        Some(2),
    ))
}

fn ps_egress(egresses: &[Egress]) -> Result<String, String> {
    if egresses.is_empty() {
        return Ok("no egresses".to_string());
    }
    let rows = egresses
        .iter()
        .map(|egress| {
            let targets = egress
                .targets
                .iter()
                .map(|target| match target {
                    RouteTarget::Tun(v) => format!("tun:{v}"),
                    RouteTarget::Device(v) => format!("dev:{v}"),
                    RouteTarget::Proxy(v) => format!("proxy:{v}"),
                })
                .collect::<Vec<_>>()
                .join(",");
            vec![
                egress.id.clone(),
                egress.name.clone(),
                targets,
                egress.dns_servers.join(","),
                if egress.is_system_default {
                    "yes"
                } else {
                    "no"
                }
                .to_string(),
                if egress.is_available { "yes" } else { "no" }.to_string(),
                egress.color.clone(),
            ]
        })
        .collect();
    Ok(ps_table(
        &[
            "id",
            "name",
            "targets",
            "dns_servers",
            "system_default",
            "available",
            "color",
        ],
        rows,
        None,
    ))
}

fn ps_proxy(proxies: &[ProxyConfig]) -> Result<String, String> {
    if proxies.is_empty() {
        return Ok("no proxies".to_string());
    }
    let rows = proxies
        .iter()
        .map(|proxy| {
            vec![
                proxy.id.clone(),
                proxy.name.clone(),
                format_proxy_protocol(&proxy.protocol).to_string(),
                format!("{}:{}", proxy.host, proxy.port),
                format_proxy_auth(&proxy.auth),
                if proxy.enabled { "yes" } else { "no" }.to_string(),
            ]
        })
        .collect();
    Ok(ps_table(
        &["id", "name", "protocol", "host:port", "auth", "enabled"],
        rows,
        None,
    ))
}

#[allow(clippy::too_many_arguments)]
fn ps_health(
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
    let rows = vec![
        vec!["ready".to_string(), yes_no(*ready)],
        vec!["fail_close_active".to_string(), yes_no(*fail_close_active)],
        vec!["pending_limit".to_string(), pending_limit.to_string()],
        vec![
            "default_timeout_secs".to_string(),
            default_timeout_secs.to_string(),
        ],
        vec!["tcp_timeout_secs".to_string(), tcp_timeout_secs.to_string()],
        vec!["udp_timeout_secs".to_string(), udp_timeout_secs.to_string()],
        vec![
            "quic_timeout_secs".to_string(),
            quic_timeout_secs.to_string(),
        ],
        vec![
            "other_timeout_secs".to_string(),
            other_timeout_secs.to_string(),
        ],
        vec!["nfqueue_enabled".to_string(), yes_no(*nfqueue_enabled)],
        vec![
            "nfqueue_num".to_string(),
            nfqueue_num.map_or("n/a".to_string(), |n| n.to_string()),
        ],
    ];
    Ok(ps_table(&["setting", "value"], rows, None))
}

fn ps_nfqueue(enabled: &bool, queue_num: &Option<u16>) -> Result<String, String> {
    let rows = vec![
        vec!["nfqueue enabled".to_string(), yes_no(*enabled)],
        vec![
            "queue num".to_string(),
            queue_num.map_or("n/a".to_string(), |n| n.to_string()),
        ],
    ];
    Ok(ps_table(&["setting", "value"], rows, None))
}

fn yes_no(value: bool) -> String {
    if value {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}

/// Format a flat-format header line, optionally colorized.
fn flat_header(header: &str) -> String {
    if colors_enabled() {
        format!("\x1b[1;33m{header}\x1b[0m\n")
    } else {
        format!("{header}\n")
    }
}

// ---------- table ----------

fn render_table(response: &ControlResponse, filter: Option<&RuleFilter>) -> Result<String, String> {
    match response {
        ControlResponse::RuleList(rules) => render_rules_table(rules, filter),
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

fn render_rules_table(rules: &[Rule], filter: Option<&RuleFilter>) -> Result<String, String> {
    let filtered = apply_rule_filter(rules, filter);
    if filtered.is_empty() {
        return Ok("no rules installed".to_string());
    }
    let mut builder = tabled::builder::Builder::new();
    builder.push_record(["id", "action", "process", "destination", "duration"]);
    for rule in &filtered {
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
    let mut table = styled(builder.build());
    for (i, rule) in filtered.iter().enumerate() {
        let row = i + 1;
        paint_status(&mut table, row, 1, format_action(&rule.action));
        paint_cell(&mut table, row, 3, destination_color(&rule.destination));
    }
    Ok(table.to_string())
}

fn render_pending_flat(pendings: &[PendingDecision]) -> Result<String, String> {
    if pendings.is_empty() {
        return Ok("no pending decisions".to_string());
    }
    let mut out = String::new();
    out.push_str(&flat_header("id  process   destination   protocol"));
    for p in pendings {
        out.push_str(&format!(
            "{}  {}  {}  {}\n",
            p.id,
            p.flow.process_name.as_deref().unwrap_or("-"),
            destination_cell(&p.flow),
            transport_str(&p.flow.protocol),
        ));
    }
    Ok(out)
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
    let mut table = styled(builder.build());
    for (i, pending) in pendings.iter().enumerate() {
        let destination = destination_cell(&pending.flow);
        paint_cell(&mut table, i + 1, 2, destination_text_color(&destination));
    }
    Ok(table.to_string())
}

fn render_flows_flat(flows: &[FlowEvent]) -> Result<String, String> {
    if flows.is_empty() {
        return Ok("no flows".to_string());
    }
    let mut out = String::new();
    out.push_str(&flat_header("id  process   destination   protocol   state"));
    for f in flows {
        out.push_str(&format!(
            "{}  {}  {}  {}  {}\n",
            f.id,
            f.process_name.as_deref().unwrap_or("-"),
            destination_cell(f),
            transport_str(&f.protocol),
            flow_state_str(&f.state),
        ));
    }
    Ok(out)
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
    let mut table = styled(builder.build());
    for (i, flow) in flows.iter().enumerate() {
        let row = i + 1;
        let destination = destination_cell(flow);
        paint_cell(&mut table, row, 2, destination_text_color(&destination));
        paint_status(&mut table, row, 4, flow_state_str(&flow.state));
    }
    Ok(table.to_string())
}

fn render_egress_flat(egresses: &[Egress]) -> Result<String, String> {
    if egresses.is_empty() {
        return Ok("no egresses".to_string());
    }
    let mut out = String::new();
    out.push_str(&flat_header(
        "id  name   targets   dns_servers   system_default   available   color",
    ));
    for e in egresses {
        let targets: String = e
            .targets
            .iter()
            .map(|t| match t {
                RouteTarget::Tun(v) => format!("tun:{v}"),
                RouteTarget::Device(v) => format!("dev:{v}"),
                RouteTarget::Proxy(v) => format!("proxy:{v}"),
            })
            .collect::<Vec<_>>()
            .join(",");
        let dns: String = e.dns_servers.join(",");
        out.push_str(&format!(
            "{}  {}  {}  {}  {}  {}  {}\n",
            e.id,
            e.name,
            targets,
            dns,
            if e.is_system_default { "yes" } else { "no" },
            if e.is_available { "yes" } else { "no" },
            e.color,
        ));
    }
    Ok(out)
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
        let dns: Vec<String> = e.dns_servers.clone();
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
    let mut table = styled(builder.build());
    for (i, egress) in egresses.iter().enumerate() {
        let row = i + 1;
        paint_status(
            &mut table,
            row,
            4,
            if egress.is_system_default {
                "yes"
            } else {
                "no"
            },
        );
        paint_status(
            &mut table,
            row,
            5,
            if egress.is_available { "yes" } else { "no" },
        );
    }
    Ok(table.to_string())
}

fn render_proxy_flat(proxies: &[ProxyConfig]) -> Result<String, String> {
    if proxies.is_empty() {
        return Ok("no proxies".to_string());
    }
    let mut out = String::new();
    out.push_str(&flat_header(
        "id  name   protocol   host:port   auth   enabled",
    ));
    for p in proxies {
        let addr = format!("{}:{}", p.host, p.port);
        out.push_str(&format!(
            "{}  {}  {}  {}  {}  {}\n",
            p.id,
            p.name,
            format_proxy_protocol(&p.protocol),
            addr,
            format_proxy_auth(&p.auth),
            if p.enabled { "yes" } else { "no" },
        ));
    }
    Ok(out)
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
    let mut table = styled(builder.build());
    for (i, proxy) in proxies.iter().enumerate() {
        paint_status(
            &mut table,
            i + 1,
            5,
            if proxy.enabled { "yes" } else { "no" },
        );
    }
    Ok(table.to_string())
}

fn render_nfqueue_status_flat(enabled: &bool, queue_num: &Option<u16>) -> Result<String, String> {
    let mut out = String::new();
    out.push_str(&flat_header("setting        value"));
    out.push_str(&format!(
        "nfqueue enabled  {}\n",
        if *enabled { "yes" } else { "no" }
    ));
    out.push_str(&format!(
        "queue num      {}\n",
        queue_num.map_or("n/a".to_string(), |n| n.to_string())
    ));
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
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
    let mut table = styled(builder.build());
    paint_status(&mut table, 1, 1, if *ready { "yes" } else { "no" });
    paint_status(
        &mut table,
        2,
        1,
        if *fail_close_active { "yes" } else { "no" },
    );
    paint_status(
        &mut table,
        9,
        1,
        if *nfqueue_enabled { "yes" } else { "no" },
    );
    Ok(table.to_string())
}

fn render_nfqueue_status_table(enabled: &bool, queue_num: &Option<u16>) -> Result<String, String> {
    let mut builder = tabled::builder::Builder::new();
    builder.push_record(["setting", "value"]);
    builder.push_record(["nfqueue enabled", if *enabled { "yes" } else { "no" }]);
    builder.push_record([
        "queue num",
        &queue_num.map_or("n/a".to_string(), |n| n.to_string()),
    ]);
    let mut table = styled(builder.build());
    paint_status(&mut table, 1, 1, if *enabled { "yes" } else { "no" });
    Ok(table.to_string())
}

fn render_flat(response: &ControlResponse, filter: Option<&RuleFilter>) -> Result<String, String> {
    match response {
        ControlResponse::RuleList(rules) => {
            let filtered = apply_rule_filter(rules, filter);
            let mut out = String::new();
            if filtered.is_empty() {
                return Ok("no rules installed".to_string());
            }
            out.push_str(&flat_header(
                "id  action   process   destination   duration",
            ));
            for rule in &filtered {
                out.push_str(&format!(
                    "{}  {}  {}  {}  {}\n",
                    rule.id,
                    format_action(&rule.action),
                    rule.process_name.as_deref().unwrap_or("-"),
                    destination_str(&rule.destination),
                    format_duration(&rule.duration)
                ));
            }
            Ok(out)
        }
        ControlResponse::PendingList(pendings) => render_pending_flat(pendings),
        ControlResponse::FlowList(flows) => render_flows_flat(flows),
        ControlResponse::EgressList(egresses) => render_egress_flat(egresses),
        ControlResponse::ProxyList(proxies) => render_proxy_flat(proxies),
        ControlResponse::NfqueueStatus { enabled, queue_num } => {
            render_nfqueue_status_flat(enabled, queue_num)
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
        } => {
            let mut out = String::new();
            out.push_str(&flat_header("setting                    value"));
            out.push_str(&format!(
                "ready                      {}\n",
                if *ready { "yes" } else { "no" }
            ));
            out.push_str(&format!(
                "fail_close_active          {}\n",
                if *fail_close_active { "yes" } else { "no" }
            ));
            out.push_str(&format!("pending_limit              {}\n", pending_limit));
            out.push_str(&format!(
                "default_timeout_secs       {}\n",
                default_timeout_secs
            ));
            out.push_str(&format!(
                "tcp_timeout_secs           {}\n",
                tcp_timeout_secs
            ));
            out.push_str(&format!(
                "udp_timeout_secs           {}\n",
                udp_timeout_secs
            ));
            out.push_str(&format!(
                "quic_timeout_secs          {}\n",
                quic_timeout_secs
            ));
            out.push_str(&format!(
                "other_timeout_secs         {}\n",
                other_timeout_secs
            ));
            out.push_str(&format!(
                "nfqueue_enabled            {}\n",
                if *nfqueue_enabled { "yes" } else { "no" }
            ));
            out.push_str(&format!(
                "nfqueue_num                {}\n",
                nfqueue_num.map_or("n/a".to_string(), |n| n.to_string())
            ));
            Ok(out)
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

fn apply_rule_filter<'a>(rules: &'a [Rule], filter: Option<&RuleFilter>) -> Vec<&'a Rule> {
    let mut result: Vec<&Rule> = rules.iter().collect();
    let filter = match filter {
        Some(f) => f,
        None => return result,
    };
    if let Some(p) = &filter.process {
        result.retain(|r| r.process_name.as_deref() == Some(p.as_str()));
    }
    if let Some(id) = &filter.id {
        result.retain(|r| &r.id == id);
    }
    if let Some(search) = &filter.search {
        let needle = search.to_ascii_lowercase();
        result.retain(|r| {
            let text = format!(
                "{} {} {} {} {}",
                r.id,
                format_action(&r.action),
                r.process_name.as_deref().unwrap_or("-"),
                destination_str(&r.destination),
                format_duration(&r.duration),
            )
            .to_ascii_lowercase();
            text.contains(&needle)
        });
    }
    if let Some(action) = &filter.action {
        let needle = action.to_ascii_lowercase();
        result.retain(|r| format_action(&r.action).contains(&needle));
    }
    if let Some(duration) = &filter.duration {
        let needle = duration.to_ascii_lowercase();
        result.retain(|r| format_duration(&r.duration).contains(&needle));
    }
    result
}

// ---------- text ----------

fn render_text(response: &ControlResponse, filter: Option<&RuleFilter>) -> Result<String, String> {
    match response {
        ControlResponse::RuleList(rules) => {
            let filtered = apply_rule_filter(rules, filter);
            let mut out = String::new();
            if filtered.is_empty() {
                return Ok("no rules installed".to_string());
            }
            for rule in &filtered {
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
                    "proxy {} name={} protocol={} addr={}:{} auth={} enabled={}\n",
                    p.id,
                    p.name,
                    format_proxy_protocol(&p.protocol),
                    p.host,
                    p.port,
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

fn render_md(response: &ControlResponse, filter: Option<&RuleFilter>) -> Result<String, String> {
    match response {
        ControlResponse::RuleList(rules) => render_rules_md(rules, filter),
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

fn render_rules_md(rules: &[Rule], filter: Option<&RuleFilter>) -> Result<String, String> {
    let filtered = apply_rule_filter(rules, filter);
    let mut out = String::new();
    out.push_str("## Rules\n\n");
    if filtered.is_empty() {
        return Ok(out.trim_end().to_string());
    }
    out.push_str("| id | action | process | destination | duration |\n");
    out.push_str("| --- | --- | --- | --- | --- |\n");
    for rule in &filtered {
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
        let dns: Vec<String> = e.dns_servers.clone();
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
            "| {} | {} | {} | {}:{} | {} | {} |\n",
            p.id,
            p.name,
            format_proxy_protocol(&p.protocol),
            p.host,
            p.port,
            format_proxy_auth(&p.auth),
            if p.enabled { "yes" } else { "no" },
        ));
    }
    Ok(out.trim_end().to_string())
}

#[allow(clippy::too_many_arguments)]
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
    out.push_str(&format!(
        "| nfqueue_num | {} |\n",
        nfqueue_num.map_or("n/a".to_string(), |n| n.to_string())
    ));
    Ok(out.trim_end().to_string())
}

fn render_nfqueue_status_md(enabled: &bool, queue_num: &Option<u16>) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("## NFQUEUE Status\n\n");
    out.push_str("| setting | value |\n");
    out.push_str("| --- | --- |\n");
    out.push_str(&format!("| enabled | {} |\n", enabled));
    out.push_str(&format!(
        "| queue num | {} |\n",
        queue_num.map_or("n/a".to_string(), |n| n.to_string())
    ));
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
