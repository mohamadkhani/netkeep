use std::collections::HashMap;

use core_types::{
    DestinationMatcher, Egress, FlowEvent, FlowState, PendingDecision, ProxyAuth, ProxyConfig, ProxyProtocol,
    RouteTarget, Rule, RuleAction, RuleDuration, TransportProtocol,
};
use rusqlite::{params, Connection};

// ---------------------------------------------------------------------------
// RuleRepository
// ---------------------------------------------------------------------------

pub trait RuleRepository {
    fn upsert_rule(&mut self, rule: Rule);
    fn get_rule(&self, id: &str) -> Option<Rule>;
    fn list_rules(&self) -> Vec<Rule>;
    fn delete_rule(&mut self, id: &str) -> bool;
    /// Remove all rules with `duration == UntilRestart`. Called at daemon startup.
    fn purge_session_rules(&mut self);
}

// ---------------------------------------------------------------------------
// FlowRepository
// ---------------------------------------------------------------------------

pub trait FlowRepository {
    fn append_event(&mut self, event: FlowEvent);
    /// Return the most-recent `limit` events, newest-first.
    fn list_events(&self, limit: usize) -> Vec<FlowEvent>;
}

// ---------------------------------------------------------------------------
// PendingRepository
// ---------------------------------------------------------------------------

pub trait PendingRepository {
    fn upsert_pending(&mut self, decision: &PendingDecision);
    fn delete_pending(&mut self, id: &str);
    /// Return all pending decisions whose deadline has not yet passed.
    fn list_live_pending(&self, now_secs: u64) -> Vec<PendingDecision>;
}

// ---------------------------------------------------------------------------
// EgressRepository
// ---------------------------------------------------------------------------

pub trait EgressRepository {
    fn upsert_egress(&mut self, egress: &Egress);
    fn list_egresses(&self) -> Vec<Egress>;
    fn delete_egress(&mut self, id: &str) -> bool;
    fn get_egress(&self, id: &str) -> Option<Egress>;
    /// Return the system-default egress (empty targets, standard routing).
    fn get_default_egress(&self) -> Option<Egress>;
}

// ---------------------------------------------------------------------------
// ProxyRepository
// ---------------------------------------------------------------------------

pub trait ProxyRepository {
    fn upsert_proxy(&mut self, proxy: &ProxyConfig);
    fn list_proxies(&self) -> Vec<ProxyConfig>;
    fn delete_proxy(&mut self, id: &str) -> bool;
    fn get_proxy(&self, id: &str) -> Option<ProxyConfig>;
}

// ---------------------------------------------------------------------------
// Combined supertrait used by ControlService
// ---------------------------------------------------------------------------

pub trait Repository: RuleRepository + FlowRepository + PendingRepository + EgressRepository + ProxyRepository {}
impl<T: RuleRepository + FlowRepository + PendingRepository + EgressRepository + ProxyRepository> Repository for T {}

// ---------------------------------------------------------------------------
// In-memory implementation (used in tests)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryRuleRepository {
    rules: HashMap<String, Rule>,
    events: Vec<FlowEvent>,
    pending: HashMap<String, PendingDecision>,
    egresses: HashMap<String, Egress>,
    proxies: HashMap<String, ProxyConfig>,
}

impl RuleRepository for InMemoryRuleRepository {
    fn upsert_rule(&mut self, rule: Rule) {
        self.rules.insert(rule.id.clone(), rule);
    }

    fn get_rule(&self, id: &str) -> Option<Rule> {
        self.rules.get(id).cloned()
    }

    fn list_rules(&self) -> Vec<Rule> {
        self.rules.values().cloned().collect()
    }

    fn delete_rule(&mut self, id: &str) -> bool {
        self.rules.remove(id).is_some()
    }

    fn purge_session_rules(&mut self) {
        self.rules.retain(|_, v| v.duration == RuleDuration::Permanent);
    }
}

impl FlowRepository for InMemoryRuleRepository {
    fn append_event(&mut self, event: FlowEvent) {
        self.events.push(event);
    }

    fn list_events(&self, limit: usize) -> Vec<FlowEvent> {
        self.events.iter().rev().take(limit).cloned().collect()
    }
}

impl PendingRepository for InMemoryRuleRepository {
    fn upsert_pending(&mut self, decision: &PendingDecision) {
        self.pending.insert(decision.id.clone(), decision.clone());
    }

    fn delete_pending(&mut self, id: &str) {
        self.pending.remove(id);
    }

    fn list_live_pending(&self, now_secs: u64) -> Vec<PendingDecision> {
        self.pending
            .values()
            .filter(|p| p.deadline_at_secs > now_secs)
            .cloned()
            .collect()
    }
}

impl EgressRepository for InMemoryRuleRepository {
    fn upsert_egress(&mut self, egress: &Egress) {
        self.egresses.insert(egress.id.clone(), egress.clone());
    }

    fn list_egresses(&self) -> Vec<Egress> {
        self.egresses.values().cloned().collect()
    }

    fn delete_egress(&mut self, id: &str) -> bool {
        self.egresses.remove(id).is_some()
    }

    fn get_egress(&self, id: &str) -> Option<Egress> {
        self.egresses.get(id).cloned()
    }

    fn get_default_egress(&self) -> Option<Egress> {
        self.egresses.values().find(|e| e.is_system_default).cloned()
    }
}

impl ProxyRepository for InMemoryRuleRepository {
    fn upsert_proxy(&mut self, proxy: &ProxyConfig) {
        self.proxies.insert(proxy.id.clone(), proxy.clone());
    }

    fn list_proxies(&self) -> Vec<ProxyConfig> {
        self.proxies.values().cloned().collect()
    }

    fn delete_proxy(&mut self, id: &str) -> bool {
        self.proxies.remove(id).is_some()
    }

    fn get_proxy(&self, id: &str) -> Option<ProxyConfig> {
        self.proxies.get(id).cloned()
    }
}

// ---------------------------------------------------------------------------
// SQLite implementation
// ---------------------------------------------------------------------------

pub struct SqliteRuleRepository {
    conn: Connection,
}

impl SqliteRuleRepository {
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS rules (
                 id TEXT PRIMARY KEY,
                 enabled INTEGER NOT NULL,
                 action INTEGER NOT NULL,
                 duration INTEGER NOT NULL,
                 process_name TEXT NULL,
                 destination_kind INTEGER NOT NULL,
                 destination_value TEXT NOT NULL,
                 route_target_kind INTEGER NULL,
                 route_target_value TEXT NULL
             );
             CREATE TABLE IF NOT EXISTS flow_events (
                 id TEXT PRIMARY KEY,
                 process_name TEXT NULL,
                 device_label TEXT NULL,
                 destination_ip TEXT NOT NULL,
                 destination_domain TEXT NULL,
                 protocol INTEGER NOT NULL,
                 state INTEGER NOT NULL,
                 timestamp_secs INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS pending_decisions (
                 id TEXT PRIMARY KEY,
                 created_at_secs INTEGER NOT NULL,
                 deadline_at_secs INTEGER NOT NULL,
                 flow_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS egresses (
                 id TEXT PRIMARY KEY,
                 name TEXT NOT NULL,
                 color TEXT NOT NULL,
                 is_system_default INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS egress_targets (
                 egress_id TEXT NOT NULL,
                 target_kind INTEGER NOT NULL,
                 target_value TEXT NOT NULL,
                 PRIMARY KEY (egress_id, target_kind, target_value),
                 FOREIGN KEY (egress_id) REFERENCES egresses(id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS egress_dns_servers (
                 egress_id TEXT NOT NULL,
                 dns_server TEXT NOT NULL,
                 PRIMARY KEY (egress_id, dns_server),
                 FOREIGN KEY (egress_id) REFERENCES egresses(id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS proxies (
                 id TEXT PRIMARY KEY,
                 name TEXT NOT NULL,
                 protocol INTEGER NOT NULL,
                 host TEXT NOT NULL,
                 port INTEGER NOT NULL,
                 auth_kind INTEGER NOT NULL DEFAULT 0,
                 auth_username TEXT NOT NULL DEFAULT '',
                 auth_password TEXT NOT NULL DEFAULT '',
                 auth_method TEXT NOT NULL DEFAULT '',
                 enabled INTEGER NOT NULL DEFAULT 1
             );",
        )
        .map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }
}

// --- encoding helpers ---

fn action_to_i64(action: &RuleAction) -> i64 {
    match action {
        RuleAction::Allow => 1,
        RuleAction::Deny => 2,
        RuleAction::Ask => 3,
        RuleAction::Route { .. } => 4,
    }
}

fn i64_to_action(v: i64, route_target: &Option<RouteTarget>) -> Option<RuleAction> {
    match v {
        1 => Some(RuleAction::Allow),
        2 => Some(RuleAction::Deny),
        3 => Some(RuleAction::Ask),
        4 => Some(RuleAction::Route { target: route_target.clone()? }),
        _ => None,
    }
}

fn route_target_to_parts(target: &RouteTarget) -> (i64, &str) {
    match target {
        RouteTarget::Tun(v) => (1, v.as_str()),
        RouteTarget::Device(v) => (2, v.as_str()),
        RouteTarget::Proxy(v) => (3, v.as_str()),
    }
}

fn parts_to_route_target(kind: i64, value: String) -> Option<RouteTarget> {
    match kind {
        1 => Some(RouteTarget::Tun(value)),
        2 => Some(RouteTarget::Device(value)),
        3 => Some(RouteTarget::Proxy(value)),
        _ => None,
    }
}

fn duration_to_i64(duration: RuleDuration) -> i64 {
    match duration {
        RuleDuration::UntilRestart => 1,
        RuleDuration::Permanent => 2,
    }
}

fn i64_to_duration(v: i64) -> Option<RuleDuration> {
    match v {
        1 => Some(RuleDuration::UntilRestart),
        2 => Some(RuleDuration::Permanent),
        _ => None,
    }
}

fn destination_to_parts(destination: &DestinationMatcher) -> (i64, &str) {
    match destination {
        DestinationMatcher::IpExact(v) => (1, v.as_str()),
        DestinationMatcher::Cidr(v) => (2, v.as_str()),
        DestinationMatcher::DomainExact(v) => (3, v.as_str()),
        DestinationMatcher::DomainWildcard(v) => (4, v.as_str()),
    }
}

fn parts_to_destination(kind: i64, value: String) -> Option<DestinationMatcher> {
    match kind {
        1 => Some(DestinationMatcher::IpExact(value)),
        2 => Some(DestinationMatcher::Cidr(value)),
        3 => Some(DestinationMatcher::DomainExact(value)),
        4 => Some(DestinationMatcher::DomainWildcard(value)),
        _ => None,
    }
}

fn protocol_to_i64(p: TransportProtocol) -> i64 {
    match p {
        TransportProtocol::Tcp => 1,
        TransportProtocol::Udp => 2,
        TransportProtocol::Quic => 3,
        TransportProtocol::Other => 4,
    }
}

fn i64_to_protocol(v: i64) -> Option<TransportProtocol> {
    match v {
        1 => Some(TransportProtocol::Tcp),
        2 => Some(TransportProtocol::Udp),
        3 => Some(TransportProtocol::Quic),
        4 => Some(TransportProtocol::Other),
        _ => None,
    }
}

fn state_to_i64(s: FlowState) -> i64 {
    match s {
        FlowState::Pending => 1,
        FlowState::Allowed => 2,
        FlowState::Denied => 3,
        FlowState::Expired => 4,
    }
}

fn i64_to_state(v: i64) -> Option<FlowState> {
    match v {
        1 => Some(FlowState::Pending),
        2 => Some(FlowState::Allowed),
        3 => Some(FlowState::Denied),
        4 => Some(FlowState::Expired),
        _ => None,
    }
}

// --- RuleRepository impl ---

impl RuleRepository for SqliteRuleRepository {
    fn upsert_rule(&mut self, rule: Rule) {
        let (destination_kind, destination_value) = destination_to_parts(&rule.destination);
        let (rt_kind, rt_value) = match &rule.route_target {
            Some(t) => {
                let (k, v) = route_target_to_parts(t);
                (Some(k), Some(v.to_string()))
            }
            None => (None, None),
        };
        let _ = self.conn.execute(
            "INSERT INTO rules (id, enabled, action, duration, process_name, destination_kind, destination_value, route_target_kind, route_target_value)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                 enabled=excluded.enabled,
                 action=excluded.action,
                 duration=excluded.duration,
                 process_name=excluded.process_name,
                 destination_kind=excluded.destination_kind,
                 destination_value=excluded.destination_value,
                 route_target_kind=excluded.route_target_kind,
                 route_target_value=excluded.route_target_value;",
            params![
                rule.id,
                if rule.enabled { 1i64 } else { 0i64 },
                action_to_i64(&rule.action),
                duration_to_i64(rule.duration),
                rule.process_name,
                destination_kind,
                destination_value,
                rt_kind,
                rt_value,
            ],
        );
    }

    fn get_rule(&self, id: &str) -> Option<Rule> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, enabled, action, duration, process_name, destination_kind, destination_value, route_target_kind, route_target_value
                 FROM rules WHERE id = ?1",
            )
            .ok()?;
        let mut rows = stmt.query(params![id]).ok()?;
        let row = rows.next().ok()??;
        let rt_kind: Option<i64> = row.get(7).ok()?;
        let rt_value: Option<String> = row.get(8).ok()?;
        let route_target = rt_kind.and_then(|k| rt_value.and_then(|v| parts_to_route_target(k, v)));
        let action = i64_to_action(row.get::<_, i64>(2).ok()?, &route_target)?;
        let duration = i64_to_duration(row.get::<_, i64>(3).ok()?)?;
        let destination =
            parts_to_destination(row.get::<_, i64>(5).ok()?, row.get::<_, String>(6).ok()?)?;
        Some(Rule {
            id: row.get(0).ok()?,
            enabled: row.get::<_, i64>(1).ok()? != 0,
            action,
            duration,
            process_name: row.get(4).ok()?,
            destination,
            route_target,
        })
    }

    fn list_rules(&self) -> Vec<Rule> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, enabled, action, duration, process_name, destination_kind, destination_value, route_target_kind, route_target_value FROM rules ORDER BY id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mapped = match stmt.query_map([], |row| {
            let rt_kind: Option<i64> = row.get(7)?;
            let rt_value: Option<String> = row.get(8)?;
            let route_target = rt_kind.and_then(|k| rt_value.and_then(|v| parts_to_route_target(k, v)));
            let action = i64_to_action(row.get::<_, i64>(2)?, &route_target)
                .ok_or(rusqlite::Error::InvalidColumnType(2, "action".to_string(), rusqlite::types::Type::Integer))?;
            let duration = i64_to_duration(row.get::<_, i64>(3)?)
                .ok_or(rusqlite::Error::InvalidColumnType(3, "duration".to_string(), rusqlite::types::Type::Integer))?;
            let destination = parts_to_destination(row.get::<_, i64>(5)?, row.get::<_, String>(6)?)
                .ok_or(rusqlite::Error::InvalidColumnType(5, "destination_kind".to_string(), rusqlite::types::Type::Integer))?;
            Ok(Rule {
                id: row.get(0)?,
                enabled: row.get::<_, i64>(1)? != 0,
                action,
                duration,
                process_name: row.get(4)?,
                destination,
                route_target,
            })
        }) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        mapped.filter_map(Result::ok).collect()
    }

    fn delete_rule(&mut self, id: &str) -> bool {
        self.conn
            .execute("DELETE FROM rules WHERE id = ?1", params![id])
            .map(|count| count > 0)
            .unwrap_or(false)
    }

    fn purge_session_rules(&mut self) {
        let _ = self.conn.execute(
            "DELETE FROM rules WHERE duration = ?1",
            params![duration_to_i64(RuleDuration::UntilRestart)],
        );
    }
}

// --- FlowRepository impl ---

impl FlowRepository for SqliteRuleRepository {
    fn append_event(&mut self, event: FlowEvent) {
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO flow_events
             (id, process_name, device_label, destination_ip, destination_domain, protocol, state, timestamp_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.id,
                event.process_name,
                event.device_label,
                event.destination_ip,
                event.destination_domain,
                protocol_to_i64(event.protocol),
                state_to_i64(event.state),
                event.timestamp_secs as i64,
            ],
        );
    }

    fn list_events(&self, limit: usize) -> Vec<FlowEvent> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, process_name, device_label, destination_ip, destination_domain,
                    protocol, state, timestamp_secs
             FROM flow_events ORDER BY timestamp_secs DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mapped = match stmt.query_map(params![limit as i64], |row| {
            let protocol = i64_to_protocol(row.get::<_, i64>(5)?)
                .ok_or(rusqlite::Error::InvalidColumnType(5, "protocol".to_string(), rusqlite::types::Type::Integer))?;
            let state = i64_to_state(row.get::<_, i64>(6)?)
                .ok_or(rusqlite::Error::InvalidColumnType(6, "state".to_string(), rusqlite::types::Type::Integer))?;
            Ok(FlowEvent {
                id: row.get(0)?,
                process_name: row.get(1)?,
                device_label: row.get(2)?,
                destination_ip: row.get(3)?,
                destination_domain: row.get(4)?,
                protocol,
                state,
                timestamp_secs: row.get::<_, i64>(7)? as u64,
            })
        }) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        mapped.filter_map(Result::ok).collect()
    }
}

// --- PendingRepository impl ---

impl PendingRepository for SqliteRuleRepository {
    fn upsert_pending(&mut self, decision: &PendingDecision) {
        let flow_json = serde_json::to_string(&decision.flow).unwrap_or_default();
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO pending_decisions (id, created_at_secs, deadline_at_secs, flow_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                decision.id,
                decision.created_at_secs as i64,
                decision.deadline_at_secs as i64,
                flow_json,
            ],
        );
    }

    fn delete_pending(&mut self, id: &str) {
        let _ = self.conn.execute(
            "DELETE FROM pending_decisions WHERE id = ?1",
            params![id],
        );
    }

    fn list_live_pending(&self, now_secs: u64) -> Vec<PendingDecision> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, created_at_secs, deadline_at_secs, flow_json
             FROM pending_decisions WHERE deadline_at_secs > ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mapped = match stmt.query_map(params![now_secs as i64], |row| {
            let flow_json: String = row.get(3)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
                flow_json,
            ))
        }) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        mapped
            .filter_map(|r| r.ok())
            .filter_map(|(id, created, deadline, flow_json)| {
                let flow = serde_json::from_str(&flow_json).ok()?;
                Some(PendingDecision {
                    id,
                    flow,
                    created_at_secs: created,
                    deadline_at_secs: deadline,
                })
            })
            .collect()
    }
}

// --- EgressRepository impl ---

impl EgressRepository for SqliteRuleRepository {
    fn upsert_egress(&mut self, egress: &Egress) {
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO egresses (id, name, color, is_system_default)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                egress.id,
                egress.name,
                egress.color,
                egress.is_system_default as i64,
            ],
        );
        // Delete old targets and re-insert
        let _ = self.conn.execute(
            "DELETE FROM egress_targets WHERE egress_id = ?1",
            params![egress.id],
        );
        let _ = self.conn.execute(
            "DELETE FROM egress_dns_servers WHERE egress_id = ?1",
            params![egress.id],
        );
        for target in &egress.targets {
            let (kind, value) = route_target_to_parts(target);
            let _ = self.conn.execute(
                "INSERT INTO egress_targets (egress_id, target_kind, target_value)
                 VALUES (?1, ?2, ?3)",
                params![egress.id, kind, value],
            );
        }
        for dns in &egress.dns_servers {
            let _ = self.conn.execute(
                "INSERT INTO egress_dns_servers (egress_id, dns_server)
                 VALUES (?1, ?2)",
                params![egress.id, dns],
            );
        }
    }

    fn list_egresses(&self) -> Vec<Egress> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, name, color, is_system_default FROM egresses",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mapped = match stmt.query_map([], |row| {
            Ok(Egress {
                id: row.get(0)?,
                name: row.get(1)?,
                color: row.get(2)?,
                is_system_default: row.get::<_, i64>(3)? != 0,
                targets: Vec::new(),
                dns_servers: Vec::new(),
                is_available: true,
            })
        }) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        let mut egresses: Vec<Egress> = mapped.filter_map(Result::ok).collect();
        // Populate targets for each egress
        for egress in &mut egresses {
            egress.targets = self.load_targets(&egress.id);
            egress.dns_servers = self.load_dns_servers(&egress.id);
        }
        egresses
    }

    fn delete_egress(&mut self, id: &str) -> bool {
        let _ = self.conn.execute(
            "DELETE FROM egress_targets WHERE egress_id = ?1",
            params![id],
        );
        self.conn
            .execute("DELETE FROM egresses WHERE id = ?1", params![id])
            .map(|count| count > 0)
            .unwrap_or(false)
    }

    fn get_egress(&self, id: &str) -> Option<Egress> {
        let mut stmt = self.conn
            .prepare("SELECT id, name, color, is_system_default FROM egresses WHERE id = ?1")
            .ok()?;
        let mut rows = stmt.query(params![id]).ok()?;
        let row = rows.next().ok()??;
        Some(Egress {
            id: row.get(0).ok()?,
            name: row.get(1).ok()?,
            color: row.get(2).ok()?,
            is_system_default: row.get::<_, i64>(3).ok()? != 0,
            targets: self.load_targets(id),
            dns_servers: self.load_dns_servers(id),
            is_available: true,
        })
    }

    fn get_default_egress(&self) -> Option<Egress> {
        let mut stmt = self.conn
            .prepare("SELECT id, name, color, is_system_default FROM egresses WHERE is_system_default = 1")
            .ok()?;
        let mut rows = stmt.query([]).ok()?;
        let row = rows.next().ok()??;
        let id: String = row.get(0).ok()?;
        Some(Egress {
            id: id.clone(),
            name: row.get(1).ok()?,
            color: row.get(2).ok()?,
            is_system_default: true,
            targets: self.load_targets(&id),
            dns_servers: self.load_dns_servers(&id),
            is_available: true,
        })
    }
}

impl SqliteRuleRepository {
    fn load_targets(&self, egress_id: &str) -> Vec<RouteTarget> {
        let mut stmt = match self.conn.prepare(
            "SELECT target_kind, target_value FROM egress_targets WHERE egress_id = ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mapped = match stmt.query_map(params![egress_id], |row| {
            let kind: i64 = row.get(0)?;
            let value: String = row.get(1)?;
            Ok(parts_to_route_target(kind, value))
        }) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        mapped.filter_map(Result::ok).flatten().collect()
    }

    fn load_dns_servers(&self, egress_id: &str) -> Vec<String> {
        let mut stmt = match self
            .conn
            .prepare("SELECT dns_server FROM egress_dns_servers WHERE egress_id = ?1 ORDER BY dns_server")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mapped = match stmt.query_map(params![egress_id], |row| row.get::<_, String>(0)) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        mapped.filter_map(Result::ok).collect()
    }
}

// --- proxy encoding helpers ---

fn proxy_protocol_to_i64(p: &ProxyProtocol) -> i64 {
    match p {
        ProxyProtocol::Socks5 => 1,
        ProxyProtocol::Http => 2,
        ProxyProtocol::Shadowsocks => 3,
    }
}

fn i64_to_proxy_protocol(v: i64) -> Option<ProxyProtocol> {
    match v {
        1 => Some(ProxyProtocol::Socks5),
        2 => Some(ProxyProtocol::Http),
        3 => Some(ProxyProtocol::Shadowsocks),
        _ => None,
    }
}

/// Encode ProxyAuth into (kind, username, password, method).
fn auth_to_parts(auth: &ProxyAuth) -> (i64, &str, &str, &str) {
    match auth {
        ProxyAuth::None => (0, "", "", ""),
        ProxyAuth::Basic { username, password } => (1, username.as_str(), password.as_str(), ""),
        ProxyAuth::Shadowsocks { method, password } => (2, "", password.as_str(), method.as_str()),
    }
}

fn parts_to_auth(kind: i64, username: String, password: String, method: String) -> ProxyAuth {
    match kind {
        1 => ProxyAuth::Basic { username, password },
        2 => ProxyAuth::Shadowsocks { method, password },
        _ => ProxyAuth::None,
    }
}

impl ProxyRepository for SqliteRuleRepository {
    fn upsert_proxy(&mut self, proxy: &ProxyConfig) {
        let (auth_kind, auth_user, auth_pass, auth_method) = auth_to_parts(&proxy.auth);
        self.conn
            .execute(
                "INSERT OR REPLACE INTO proxies (id, name, protocol, host, port, auth_kind, auth_username, auth_password, auth_method, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    proxy.id,
                    proxy.name,
                    proxy_protocol_to_i64(&proxy.protocol),
                    proxy.host,
                    proxy.port as i64,
                    auth_kind,
                    auth_user,
                    auth_pass,
                    auth_method,
                    proxy.enabled as i64,
                ],
            )
            .ok();
    }

    fn list_proxies(&self) -> Vec<ProxyConfig> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, name, protocol, host, port, auth_kind, auth_username, auth_password, auth_method, enabled FROM proxies ORDER BY id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mapped = match stmt.query_map([], |row| {
            let protocol = i64_to_proxy_protocol(row.get::<_, i64>(2)?).unwrap_or(ProxyProtocol::Socks5);
            let auth = parts_to_auth(
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            );
            Ok(ProxyConfig {
                id: row.get::<_, String>(0)?,
                name: row.get::<_, String>(1)?,
                protocol,
                host: row.get::<_, String>(3)?,
                port: row.get::<_, i64>(4)? as u16,
                auth,
                enabled: row.get::<_, i64>(9)? != 0,
            })
        }) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        mapped.filter_map(Result::ok).collect()
    }

    fn delete_proxy(&mut self, id: &str) -> bool {
        self.conn
            .execute("DELETE FROM proxies WHERE id = ?1", params![id])
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    fn get_proxy(&self, id: &str) -> Option<ProxyConfig> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, name, protocol, host, port, auth_kind, auth_username, auth_password, auth_method, enabled FROM proxies WHERE id = ?1",
            )
            .ok()?;
        let mut rows = stmt.query(params![id]).ok()?;
        let row = rows.next().ok()??;
        let protocol = i64_to_proxy_protocol(row.get::<_, i64>(2).ok()?).unwrap_or(ProxyProtocol::Socks5);
        let auth = parts_to_auth(
            row.get::<_, i64>(5).ok()?,
            row.get::<_, String>(6).ok()?,
            row.get::<_, String>(7).ok()?,
            row.get::<_, String>(8).ok()?,
        );
        Some(ProxyConfig {
            id: row.get::<_, String>(0).ok()?,
            name: row.get::<_, String>(1).ok()?,
            protocol,
            host: row.get::<_, String>(3).ok()?,
            port: row.get::<_, i64>(4).ok()? as u16,
            auth,
            enabled: row.get::<_, i64>(9).ok()? != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{DestinationMatcher, Egress, FlowContext, FlowDirection, FlowState, RouteTarget, RuleAction, RuleDuration, TransportProtocol};
    use tempfile::NamedTempFile;

    fn mk_rule(id: &str) -> Rule {
        Rule {
            id: id.to_string(),
            enabled: true,
            action: RuleAction::Allow,
            duration: RuleDuration::UntilRestart,
            process_name: Some("curl".to_string()),
            destination: DestinationMatcher::DomainExact("example.com".to_string()),
            route_target: None,
        }
    }

    fn mk_flow_event(id: &str) -> FlowEvent {
        FlowEvent {
            id: id.to_string(),
            process_name: Some("curl".to_string()),
            device_label: None,
            destination_ip: "1.1.1.1".to_string(),
            destination_domain: Some("example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            state: FlowState::Allowed,
            timestamp_secs: 1000,
        }
    }

    fn mk_pending(id: &str) -> PendingDecision {
        PendingDecision {
            id: id.to_string(),
            flow: FlowContext {
                process_name: Some("curl".to_string()),
                destination_ip: "1.1.1.1".to_string(),
                destination_port: 443,
                destination_domain: Some("example.com".to_string()),
                protocol: TransportProtocol::Tcp,
                direction: FlowDirection::Outbound,
                device_label: None,
            },
            created_at_secs: 100,
            deadline_at_secs: 200,
        }
    }

    // --- InMemory ---

    #[test]
    fn insert_and_get_rule() {
        let mut repo = InMemoryRuleRepository::default();
        let rule = mk_rule("r1");
        repo.upsert_rule(rule.clone());
        assert_eq!(repo.get_rule("r1"), Some(rule));
    }

    #[test]
    fn update_existing_rule() {
        let mut repo = InMemoryRuleRepository::default();
        let mut rule = mk_rule("r1");
        repo.upsert_rule(rule.clone());
        rule.enabled = false;
        repo.upsert_rule(rule.clone());
        assert_eq!(repo.get_rule("r1"), Some(rule));
    }

    #[test]
    fn delete_rule_returns_expected_status() {
        let mut repo = InMemoryRuleRepository::default();
        repo.upsert_rule(mk_rule("r1"));
        assert!(repo.delete_rule("r1"));
        assert!(!repo.delete_rule("r1"));
    }

    #[test]
    fn purge_session_rules_removes_until_restart_only() {
        let mut repo = InMemoryRuleRepository::default();
        let mut permanent = mk_rule("perm");
        permanent.duration = RuleDuration::Permanent;
        repo.upsert_rule(mk_rule("temp"));
        repo.upsert_rule(permanent);
        repo.purge_session_rules();
        assert_eq!(repo.list_rules().len(), 1);
        assert_eq!(repo.list_rules()[0].id, "perm");
    }

    #[test]
    fn flow_events_append_and_list() {
        let mut repo = InMemoryRuleRepository::default();
        repo.append_event(mk_flow_event("e1"));
        repo.append_event(mk_flow_event("e2"));
        let events = repo.list_events(10);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, "e2");
    }

    #[test]
    fn pending_upsert_delete_and_list_live() {
        let mut repo = InMemoryRuleRepository::default();
        repo.upsert_pending(&mk_pending("p1"));
        assert_eq!(repo.list_live_pending(150).len(), 1);
        assert_eq!(repo.list_live_pending(200).len(), 0);
        repo.delete_pending("p1");
        assert_eq!(repo.list_live_pending(150).len(), 0);
    }

    // --- SQLite ---

    #[test]
    fn sqlite_insert_get_and_delete() {
        let file = NamedTempFile::new().expect("must create temp file");
        let path = file.path().to_string_lossy().to_string();
        let mut repo = SqliteRuleRepository::open(&path).expect("sqlite open");
        let rule = mk_rule("r1");
        repo.upsert_rule(rule.clone());
        assert_eq!(repo.get_rule("r1"), Some(rule));
        assert!(repo.delete_rule("r1"));
        assert_eq!(repo.get_rule("r1"), None);
    }

    #[test]
    fn sqlite_persists_between_reopens() {
        let file = NamedTempFile::new().expect("must create temp file");
        let path = file.path().to_string_lossy().to_string();
        {
            let mut repo = SqliteRuleRepository::open(&path).expect("sqlite open");
            repo.upsert_rule(mk_rule("persisted"));
        }
        let repo = SqliteRuleRepository::open(&path).expect("sqlite reopen");
        let rules = repo.list_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "persisted");
    }

    #[test]
    fn sqlite_purge_session_rules() {
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_string_lossy().to_string();
        let mut repo = SqliteRuleRepository::open(&path).expect("sqlite open");
        let mut perm = mk_rule("perm");
        perm.duration = RuleDuration::Permanent;
        repo.upsert_rule(mk_rule("temp"));
        repo.upsert_rule(perm);
        repo.purge_session_rules();
        let rules = repo.list_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "perm");
    }

    #[test]
    fn sqlite_flow_events_persist() {
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_string_lossy().to_string();
        let mut repo = SqliteRuleRepository::open(&path).expect("sqlite open");
        repo.append_event(mk_flow_event("e1"));
        repo.append_event(mk_flow_event("e2"));
        let events = repo.list_events(10);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn sqlite_pending_decisions_persist_and_expire() {
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_string_lossy().to_string();
        let mut repo = SqliteRuleRepository::open(&path).expect("sqlite open");
        repo.upsert_pending(&mk_pending("p1"));
        assert_eq!(repo.list_live_pending(150).len(), 1);
        assert_eq!(repo.list_live_pending(200).len(), 0);
        repo.delete_pending("p1");
        assert_eq!(repo.list_live_pending(150).len(), 0);
    }

    // --- Egress tests ---

    fn mk_egress(id: &str, name: &str, color: &str, targets: Vec<RouteTarget>, is_default: bool) -> Egress {
        Egress {
            id: id.to_string(),
            name: name.to_string(),
            color: color.to_string(),
            targets,
            dns_servers: vec![],
            is_system_default: is_default,
            is_available: true,
        }
    }

    #[test]
    fn in_memory_egress_crud() {
        let mut repo = InMemoryRuleRepository::default();
        let eg = mk_egress("eg-vpn", "VPN", "#22c55e", vec![RouteTarget::Tun("tun0".into())], false);
        repo.upsert_egress(&eg);
        assert_eq!(repo.list_egresses().len(), 1);
        assert_eq!(repo.get_egress("eg-vpn").unwrap().name, "VPN");
        assert!(repo.delete_egress("eg-vpn"));
        assert_eq!(repo.list_egresses().len(), 0);
    }

    #[test]
    fn in_memory_default_egress() {
        let mut repo = InMemoryRuleRepository::default();
        repo.upsert_egress(&mk_egress("eg-def", "Default Route", "#6b7280", vec![], true));
        repo.upsert_egress(&mk_egress("eg-vpn", "VPN", "#22c55e", vec![], false));
        let default = repo.get_default_egress().expect("should exist");
        assert_eq!(default.id, "eg-def");
        assert!(default.is_system_default);
    }

    #[test]
    fn sqlite_egress_crud() {
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_string_lossy().to_string();
        let mut repo = SqliteRuleRepository::open(&path).expect("sqlite open");
        let eg = mk_egress(
            "eg-wlan",
            "Wi-Fi",
            "#3b82f6",
            vec![RouteTarget::Device("wlan0".into())],
            false,
        );
        repo.upsert_egress(&eg);
        let loaded = repo.get_egress("eg-wlan").expect("should exist");
        assert_eq!(loaded.name, "Wi-Fi");
        assert_eq!(loaded.targets.len(), 1);
        assert_eq!(loaded.targets[0], RouteTarget::Device("wlan0".into()));
        assert_eq!(repo.list_egresses().len(), 1);
        assert!(repo.delete_egress("eg-wlan"));
        assert!(repo.get_egress("eg-wlan").is_none());
    }

    #[test]
    fn sqlite_egress_with_multiple_targets() {
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_string_lossy().to_string();
        let mut repo = SqliteRuleRepository::open(&path).expect("sqlite open");
        let eg = mk_egress(
            "eg-multi",
            "Bonded",
            "#f59e0b",
            vec![
                RouteTarget::Tun("tun0".into()),
                RouteTarget::Device("eth1".into()),
            ],
            false,
        );
        repo.upsert_egress(&eg);
        let loaded = repo.get_egress("eg-multi").expect("should exist");
        assert_eq!(loaded.targets.len(), 2);
    }

    #[test]
    fn sqlite_egress_dns_servers_roundtrip() {
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_string_lossy().to_string();
        let mut repo = SqliteRuleRepository::open(&path).expect("sqlite open");
        let mut eg = mk_egress(
            "eg-dns",
            "DNS Egress",
            "#22c55e",
            vec![RouteTarget::Device("wlp0s20f3".into())],
            false,
        );
        eg.dns_servers = vec!["1.1.1.1".into(), "8.8.8.8".into()];
        repo.upsert_egress(&eg);
        let loaded = repo.get_egress("eg-dns").expect("should exist");
        assert_eq!(loaded.dns_servers, vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
    }

    #[test]
    fn sqlite_default_egress() {
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_string_lossy().to_string();
        let mut repo = SqliteRuleRepository::open(&path).expect("sqlite open");
        repo.upsert_egress(&mk_egress("eg-def", "Default Route", "#6b7280", vec![], true));
        repo.upsert_egress(&mk_egress("eg-vpn", "VPN", "#22c55e", vec![], false));
        let default = repo.get_default_egress().expect("should exist");
        assert_eq!(default.id, "eg-def");
    }
}
