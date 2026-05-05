use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDuration {
    UntilRestart,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestinationMatcher {
    IpExact(String),
    Cidr(String),
    DomainExact(String),
    DomainWildcard(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub action: RuleAction,
    pub duration: RuleDuration,
    pub process_name: Option<String>,
    pub destination: DestinationMatcher,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowContext {
    pub process_name: Option<String>,
    pub destination_ip: String,
    pub destination_domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDecision {
    pub id: String,
    pub flow: FlowContext,
    pub created_at_secs: u64,
    pub deadline_at_secs: u64,
}

