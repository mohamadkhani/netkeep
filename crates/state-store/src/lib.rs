use std::collections::HashMap;

use core_types::{DestinationMatcher, Rule, RuleAction, RuleDuration};
use rusqlite::{params, Connection};

pub trait RuleRepository {
    fn upsert_rule(&mut self, rule: Rule);
    fn get_rule(&self, id: &str) -> Option<Rule>;
    fn list_rules(&self) -> Vec<Rule>;
    fn delete_rule(&mut self, id: &str) -> bool;
}

#[derive(Default)]
pub struct InMemoryRuleRepository {
    rules: HashMap<String, Rule>,
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
}

pub struct SqliteRuleRepository {
    conn: Connection,
}

impl SqliteRuleRepository {
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL,
                action INTEGER NOT NULL,
                duration INTEGER NOT NULL,
                process_name TEXT NULL,
                destination_kind INTEGER NOT NULL,
                destination_value TEXT NOT NULL
            );",
        )
        .map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }
}

fn action_to_i64(action: RuleAction) -> i64 {
    match action {
        RuleAction::Allow => 1,
        RuleAction::Deny => 2,
        RuleAction::Ask => 3,
    }
}

fn i64_to_action(v: i64) -> Option<RuleAction> {
    match v {
        1 => Some(RuleAction::Allow),
        2 => Some(RuleAction::Deny),
        3 => Some(RuleAction::Ask),
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

impl RuleRepository for SqliteRuleRepository {
    fn upsert_rule(&mut self, rule: Rule) {
        let (destination_kind, destination_value) = destination_to_parts(&rule.destination);
        let _ = self.conn.execute(
            "INSERT INTO rules (id, enabled, action, duration, process_name, destination_kind, destination_value)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                 enabled=excluded.enabled,
                 action=excluded.action,
                 duration=excluded.duration,
                 process_name=excluded.process_name,
                 destination_kind=excluded.destination_kind,
                 destination_value=excluded.destination_value;",
            params![
                rule.id,
                if rule.enabled { 1 } else { 0 },
                action_to_i64(rule.action),
                duration_to_i64(rule.duration),
                rule.process_name,
                destination_kind,
                destination_value
            ],
        );
    }

    fn get_rule(&self, id: &str) -> Option<Rule> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, enabled, action, duration, process_name, destination_kind, destination_value
                 FROM rules WHERE id = ?1",
            )
            .ok()?;
        let mut rows = stmt.query(params![id]).ok()?;
        let row = rows.next().ok()??;
        let action = i64_to_action(row.get::<_, i64>(2).ok()?)?;
        let duration = i64_to_duration(row.get::<_, i64>(3).ok()?)?;
        let destination = parts_to_destination(row.get::<_, i64>(5).ok()?, row.get::<_, String>(6).ok()?)?;
        Some(Rule {
            id: row.get(0).ok()?,
            enabled: row.get::<_, i64>(1).ok()? != 0,
            action,
            duration,
            process_name: row.get(4).ok()?,
            destination,
        })
    }

    fn list_rules(&self) -> Vec<Rule> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, enabled, action, duration, process_name, destination_kind, destination_value FROM rules",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mapped = match stmt.query_map([], |row| {
            let action = i64_to_action(row.get::<_, i64>(2)?)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{DestinationMatcher, RuleAction, RuleDuration};
    use tempfile::NamedTempFile;

    fn mk_rule(id: &str) -> Rule {
        Rule {
            id: id.to_string(),
            enabled: true,
            action: RuleAction::Allow,
            duration: RuleDuration::UntilRestart,
            process_name: Some("curl".to_string()),
            destination: DestinationMatcher::DomainExact("example.com".to_string()),
        }
    }

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
}

