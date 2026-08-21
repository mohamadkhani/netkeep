use core_types::{DestinationMatcher, FlowContext, Rule, RuleAction};
use metrics::{counter, histogram};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRule {
    pub rule_id: String,
    pub action: RuleAction,
    /// Populated when `action == Route`; references the egress the matched
    /// rule is bound to. Control-service resolves the concrete `RouteTarget`
    /// from this id at enforcement time.
    pub egress_id: Option<String>,
}

/// Wildcard match for `DomainWildcard(pattern)` against a flow's `destination_domain`.
///
/// The stored pattern is the apex (e.g. `"example.com"`) — the GPUI decision
/// dialog and the CLI both strip the `*.` prefix before persisting. However
/// rules created via the settings form, the JSON-RPC, or imported from a
/// previous schema may still carry the `*.` prefix. This function is
/// intentionally lenient and accepts both `"foo.com"` and `"*.foo.com"` so we
/// don't silently fail to match real rules.
///
/// Semantics: matches *proper* subdomains only. `"example.com"` matches
/// `"api.example.com"` and `"a.b.example.com"` but **not** `"example.com"`
/// itself (the apex). Allowing the apex requires a separate `DomainExact`
/// rule — this matches the documented contract in `docs/decision-dialog-ux.md`.
fn wildcard_matches(pattern: &str, host: &str) -> bool {
    let apex = pattern.strip_prefix("*.").unwrap_or(pattern);
    if apex.is_empty() {
        return false;
    }
    host.ends_with(&format!(".{apex}"))
}

fn destination_matches(rule: &Rule, flow: &FlowContext) -> bool {
    match &rule.destination {
        DestinationMatcher::Any => true,
        DestinationMatcher::IpExact(ip) => flow.destination_ip == *ip,
        DestinationMatcher::Cidr(prefix) => cidr_contains(prefix, &flow.destination_ip),
        DestinationMatcher::DomainExact(domain) => flow.destination_domain.as_ref() == Some(domain),
        DestinationMatcher::DomainWildcard(pattern) => flow
            .destination_domain
            .as_ref()
            .map(|h| wildcard_matches(pattern, h))
            .unwrap_or(false),
    }
}

/// True when `ip` falls inside the network described by `prefix`.
///
/// Accepts real CIDR notation (`"10.0.0.0/8"` — the form the GPUI dialog,
/// settings form, and CLI all persist). Falls back to a literal string
/// prefix (`"10.0.0."`) for rules stored by older versions or imported
/// from foreign schemas. Unparsable prefixes match nothing rather than
/// everything.
fn cidr_contains(prefix: &str, ip: &str) -> bool {
    if let Some((net_str, len_str)) = prefix.split_once('/') {
        let (Ok(net), Ok(len), Ok(addr)) = (
            net_str.parse::<std::net::Ipv4Addr>(),
            len_str.parse::<u32>(),
            ip.parse::<std::net::Ipv4Addr>(),
        ) else {
            return false;
        };
        if len > 32 {
            return false;
        }
        let mask: u32 = if len == 0 {
            0
        } else {
            u32::MAX << (32 - len)
        };
        (u32::from(net) & mask) == (u32::from(addr) & mask)
    } else {
        ip.starts_with(prefix)
    }
}

fn process_matches(rule: &Rule, flow: &FlowContext) -> bool {
    // Prefer exe-path comparison when both sides have it — more unique than
    // basename alone and immune to comm-name truncation.
    if let (Some(rule_exe), Some(flow_exe)) = (&rule.process_exe, &flow.process_exe) {
        return rule_exe == flow_exe;
    }
    match (&rule.process_name, &flow.process_name) {
        (None, _) => true,
        (Some(rp), Some(fp)) => rp == fp,
        // Flow process attribution failed (proc_resolver lost the
        // /proc/net/tcp race). When the rule pins a *specific* destination
        // we trust the destination: re-prompting the user for the same
        // host they already approved is worse UX than letting the rule
        // apply. Broad destinations (Any / Cidr / Wildcard) still require
        // an exact process match so a global "allow process X" rule can't
        // be silently piggy-backed on by a different unattributed process.
        (Some(_), None) => matches!(
            rule.destination,
            DestinationMatcher::IpExact(_) | DestinationMatcher::DomainExact(_)
        ),
    }
}

/// Insertion comparator — the default placement ladder for new rules.
/// Higher rank = inserted higher in the rule list (evaluated earlier).
/// This is ONLY used when seeding a new rule's `position` alongside
/// existing rules; evaluation itself is purely first-match-wins over the
/// stored position order.
///
/// Ladder (top to bottom):
///   process + ip > process + domain > process + wildcard > process + cidr
///   > ip > domain > wildcard > cidr > process + any > any
pub fn priority_rank(rule: &Rule) -> u8 {
    match (&rule.process_name, &rule.destination) {
        (Some(_), DestinationMatcher::IpExact(_)) => 9,
        (Some(_), DestinationMatcher::DomainExact(_)) => 8,
        (Some(_), DestinationMatcher::DomainWildcard(_)) => 7,
        (Some(_), DestinationMatcher::Cidr(_)) => 6,
        (None, DestinationMatcher::IpExact(_)) => 5,
        (None, DestinationMatcher::DomainExact(_)) => 4,
        (None, DestinationMatcher::DomainWildcard(_)) => 3,
        (None, DestinationMatcher::Cidr(_)) => 2,
        (Some(_), DestinationMatcher::Any) => 1,
        (None, DestinationMatcher::Any) => 0,
    }
}

/// Compute the position a new rule should occupy within `existing`
/// (position-sorted): below all rules of higher-or-equal rank, at the
/// bottom of its own rank's block.
pub fn seed_position(new_rule: &Rule, existing: &[Rule]) -> u32 {
    let new_rank = priority_rank(new_rule);
    // Count rules that should sit above the new rule.
    let above = existing
        .iter()
        .filter(|r| priority_rank(r) > new_rank)
        .count();
    above as u32
}

pub fn resolve_action(rules: &[Rule], flow: &FlowContext) -> Option<ResolvedRule> {
    let start = std::time::Instant::now();
    counter!("logiguard.policy.evaluations").increment(1);

    // First-match-wins over position order. Callers pass rules sorted by
    // position (state-store returns them ordered); as a safety net we also
    // tolerate unsorted input by sorting a copy.
    let mut sorted: Vec<&Rule> = rules.iter().filter(|r| r.enabled).collect();
    sorted.sort_by_key(|r| r.position);

    let result = sorted
        .into_iter()
        .find(|r| process_matches(r, flow) && destination_matches(r, flow))
        .map(|r| ResolvedRule {
            rule_id: r.id.clone(),
            action: r.action.clone(),
            egress_id: r.egress_id.clone(),
        });

    histogram!("logiguard.policy.evaluation.duration").record(start.elapsed().as_secs_f64());

    match &result {
        Some(r) => {
            let action_str = match r.action {
                RuleAction::Allow => "allow",
                RuleAction::Deny => "deny",
                RuleAction::Ask => "ask",
                RuleAction::Route => "route",
            };
            counter!("logiguard.policy.resolved", "action" => action_str).increment(1);
        }
        None => {
            counter!("logiguard.policy.no_match").increment(1);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{FlowDirection, Rule, RuleDuration, TransportProtocol};

    fn mk_rule(
        id: &str,
        action: RuleAction,
        process_name: Option<&str>,
        destination: DestinationMatcher,
    ) -> Rule {
        Rule {
            id: id.to_string(),
            enabled: true,
            action,
            duration: RuleDuration::UntilRestart,
            process_name: process_name.map(str::to_string),
            process_exe: None,
            destination,
            egress_id: None,
            position: 0,
        }
    }

    #[test]
    fn wildcard_matches_subdomain_but_not_apex() {
        let flow_sub = FlowContext {
            process_name: None,
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: Some("api.example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        };
        let flow_apex = FlowContext {
            process_name: None,
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: Some("example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        };
        let rule = mk_rule(
            "r1",
            RuleAction::Allow,
            None,
            DestinationMatcher::DomainWildcard("*.example.com".to_string()),
        );
        assert_eq!(
            resolve_action(&[rule.clone()], &flow_sub).map(|r| r.action),
            Some(RuleAction::Allow)
        );
        assert_eq!(resolve_action(&[rule], &flow_apex), None);
    }

    /// Production storage form: the GPUI decision dialog and the CLI both
    /// strip the `*.` prefix before persisting (see
    /// `apps/gpui/src/components/action_footer.rs::build_dest_matcher` and
    /// `apps/cli/src/main.rs::parse_destination`). Before the lenient
    /// matcher, `wildcard_matches` returned `false` for these rules and
    /// every dialog-installed wildcard silently failed.
    #[test]
    fn wildcard_matches_with_apex_only_storage_form() {
        let flow_sub = FlowContext {
            process_name: None,
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: Some("api.example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        };
        let flow_deep = FlowContext {
            destination_domain: Some("a.b.c.example.com".to_string()),
            ..flow_sub.clone()
        };
        let flow_apex = FlowContext {
            destination_domain: Some("example.com".to_string()),
            ..flow_sub.clone()
        };
        let flow_unrelated = FlowContext {
            destination_domain: Some("notexample.com".to_string()),
            ..flow_sub.clone()
        };
        let rule = mk_rule(
            "wildcard-apex-form",
            RuleAction::Allow,
            None,
            // No `*.` prefix — what the decision dialog actually writes.
            DestinationMatcher::DomainWildcard("example.com".to_string()),
        );
        assert_eq!(
            resolve_action(&[rule.clone()], &flow_sub).map(|r| r.action),
            Some(RuleAction::Allow),
            "subdomain must match apex-only wildcard storage"
        );
        assert_eq!(
            resolve_action(&[rule.clone()], &flow_deep).map(|r| r.action),
            Some(RuleAction::Allow),
            "deep subdomain must match apex-only wildcard storage"
        );
        assert_eq!(
            resolve_action(&[rule.clone()], &flow_apex),
            None,
            "apex must still NOT match wildcard (separate rule required)"
        );
        assert_eq!(
            resolve_action(&[rule], &flow_unrelated),
            None,
            "wildcard must not be substring-fooled by `notexample.com`"
        );
    }

    /// Both storage forms — `"example.com"` and `"*.example.com"` — must be
    /// accepted by the matcher so rules created via the GPUI dialog (no
    /// prefix) and via the legacy settings form (with prefix) behave
    /// identically.
    #[test]
    fn wildcard_matches_both_storage_forms_identically() {
        let flow = FlowContext {
            process_name: None,
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: Some("api.example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        };
        let with_prefix = mk_rule(
            "p",
            RuleAction::Allow,
            None,
            DestinationMatcher::DomainWildcard("*.example.com".to_string()),
        );
        let without_prefix = mk_rule(
            "n",
            RuleAction::Allow,
            None,
            DestinationMatcher::DomainWildcard("example.com".to_string()),
        );
        assert_eq!(
            resolve_action(&[with_prefix], &flow).map(|r| r.action),
            Some(RuleAction::Allow)
        );
        assert_eq!(
            resolve_action(&[without_prefix], &flow).map(|r| r.action),
            Some(RuleAction::Allow)
        );
    }

    /// Empty pattern (defensive): must never match anything, otherwise a
    /// malformed import or empty form field could turn into an
    /// allow-everything rule.
    #[test]
    fn wildcard_empty_pattern_matches_nothing() {
        let flow = FlowContext {
            process_name: None,
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: Some("api.example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        };
        for pat in ["", "*.", "*."] {
            let rule = mk_rule(
                "empty",
                RuleAction::Allow,
                None,
                DestinationMatcher::DomainWildcard(pat.to_string()),
            );
            assert!(
                resolve_action(&[rule], &flow).is_none(),
                "empty pattern `{pat}` must not match anything"
            );
        }
    }

    #[test]
    fn specific_process_rule_beats_general_rule() {
        let flow = FlowContext {
            process_name: Some("firefox".to_string()),
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "9.9.9.9".to_string(),
            destination_port: 443,
            destination_domain: Some("api.example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        };
        let general = mk_rule(
            "general",
            RuleAction::Allow,
            None,
            DestinationMatcher::DomainWildcard("*.example.com".to_string()),
        );
        let mut specific = mk_rule(
            "specific",
            RuleAction::Deny,
            Some("firefox"),
            DestinationMatcher::DomainWildcard("*.example.com".to_string()),
        );
        let mut rules = vec![general];
        let idx = seed_position(&specific, &rules) as usize;
        rules.insert(idx, specific);
        for (ix, r) in rules.iter_mut().enumerate() {
            r.position = ix as u32;
        }
        let resolved = resolve_action(&rules, &flow).expect("must resolve");
        assert_eq!(resolved.rule_id, "specific");
        assert_eq!(resolved.action, RuleAction::Deny);
    }

    #[test]
    fn deny_beats_allow_at_same_specificity() {
        let flow = FlowContext {
            process_name: None,
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "8.8.8.8".to_string(),
            destination_port: 443,
            destination_domain: Some("example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        };
        let mut allow = mk_rule(
            "allow",
            RuleAction::Allow,
            None,
            DestinationMatcher::DomainExact("example.com".to_string()),
        );
        // Seeded order puts a Deny above an Allow of equal rank only via
        // explicit position; here we place deny first deliberately.
        let mut deny = mk_rule(
            "deny",
            RuleAction::Deny,
            None,
            DestinationMatcher::DomainExact("example.com".to_string()),
        );
        allow.position = 1;
        deny.position = 0;
        let resolved = resolve_action(&[allow, deny], &flow).expect("must resolve");
        assert_eq!(resolved.rule_id, "deny");
    }

    fn flow_unknown_proc(domain: Option<&str>, ip: &str) -> FlowContext {
        FlowContext {
            process_name: None,
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: ip.to_string(),
            destination_port: 443,
            destination_domain: domain.map(str::to_string),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        }
    }

    #[test]
    fn unknown_process_matches_specific_destination_rule() {
        // proc_resolver lost the race on this packet; the user has already
        // approved curl → example.com. The rule must still apply, otherwise
        // we'd reprompt for an already-trusted destination.
        let rule = mk_rule(
            "allow-curl-example",
            RuleAction::Allow,
            Some("curl"),
            DestinationMatcher::DomainExact("example.com".to_string()),
        );
        let flow = flow_unknown_proc(Some("example.com"), "93.184.216.34");
        let resolved = resolve_action(&[rule], &flow).expect("rule must match");
        assert_eq!(resolved.rule_id, "allow-curl-example");
        assert_eq!(resolved.action, RuleAction::Allow);
    }

    #[test]
    fn unknown_process_matches_specific_ip_rule() {
        let rule = mk_rule(
            "allow-curl-ip",
            RuleAction::Allow,
            Some("curl"),
            DestinationMatcher::IpExact("1.1.1.1".to_string()),
        );
        let flow = flow_unknown_proc(None, "1.1.1.1");
        let resolved = resolve_action(&[rule], &flow).expect("rule must match");
        assert_eq!(resolved.action, RuleAction::Allow);
    }

    #[test]
    fn unknown_process_does_not_piggyback_on_wildcard_rule() {
        // Broad destination + unknown process must NOT silently apply.
        // Otherwise a wildcard "allow curl → *.example.com" rule could
        // permit any unattributed traffic to that wildcard.
        let rule = mk_rule(
            "allow-curl-wildcard",
            RuleAction::Allow,
            Some("curl"),
            DestinationMatcher::DomainWildcard("*.example.com".to_string()),
        );
        let flow = flow_unknown_proc(Some("api.example.com"), "1.2.3.4");
        assert!(resolve_action(&[rule], &flow).is_none());
    }

    #[test]
    fn unknown_process_does_not_piggyback_on_any_rule() {
        let rule = mk_rule(
            "allow-curl-any",
            RuleAction::Allow,
            Some("curl"),
            DestinationMatcher::Any,
        );
        let flow = flow_unknown_proc(None, "9.9.9.9");
        assert!(resolve_action(&[rule], &flow).is_none());
    }

    #[test]
    fn unknown_process_does_not_piggyback_on_cidr_rule() {
        let rule = mk_rule(
            "allow-curl-cidr",
            RuleAction::Allow,
            Some("curl"),
            DestinationMatcher::Cidr("10.0.0.".to_string()),
        );
        let flow = flow_unknown_proc(None, "10.0.0.5");
        assert!(resolve_action(&[rule], &flow).is_none());
    }

    #[test]
    fn known_process_mismatch_still_blocks_specific_rule() {
        // If proc_resolver succeeded but with a different name, the rule
        // must still NOT match — the unknown-process fallback only kicks
        // in when attribution failed entirely.
        let rule = mk_rule(
            "allow-curl-example",
            RuleAction::Allow,
            Some("curl"),
            DestinationMatcher::DomainExact("example.com".to_string()),
        );
        let mut flow = flow_unknown_proc(Some("example.com"), "93.184.216.34");
        flow.process_name = Some("evil".to_string());
        assert!(resolve_action(&[rule], &flow).is_none());
    }

    #[test]
    fn tie_break_equal_route_rules_prefers_lexicographically_greater_id() {
        let flow = FlowContext {
            process_name: Some("socks-client".to_string()),
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "0.0.0.0".to_string(),
            destination_port: 443,
            destination_domain: Some("www.digikala.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        };
        let mut tun = mk_rule(
            "demo-digikala-tun",
            RuleAction::Route,
            Some("socks-client"),
            DestinationMatcher::DomainExact("www.digikala.com".to_string()),
        );
        tun.egress_id = Some("eg-tun-wg0".into());
        let mut wifi = mk_rule(
            "demo-digikala-wifi",
            RuleAction::Route,
            Some("socks-client"),
            DestinationMatcher::DomainExact("www.digikala.com".to_string()),
        );
        wifi.egress_id = Some("eg-wifi-wlp0".into());
        // Equal rank: wifi was created later, so it seeds below tun — but the
        // user dragged it above. Position order decides.
        wifi.position = 0;
        tun.position = 1;
        let resolved = resolve_action(&[tun, wifi], &flow).expect("must resolve");
        assert_eq!(resolved.rule_id, "demo-digikala-wifi");
        assert_eq!(resolved.egress_id, Some("eg-wifi-wlp0".into()));
    }

    /// The user-reported regression: a CIDR rule without a process must not
    /// be shadowed by a process-only rule. With seeded positions the CIDR
    /// rule (rank 2) sits above the process+any rule (rank 1).
    #[test]
    fn cidr_rule_beats_process_only_rule_when_seeded() {
        // Simulate state-store insertion: cidr first, then chrome seeded
        // against the existing list.
        let cidr = mk_rule(
            "lan-cidr",
            RuleAction::Deny,
            None,
            DestinationMatcher::Cidr("10.0.0.0/8".to_string()),
        );
        let chrome = mk_rule(
            "chrome-allow",
            RuleAction::Allow,
            Some("chrome"),
            DestinationMatcher::Any,
        );
        let mut rules: Vec<Rule> = vec![cidr];
        let idx = seed_position(&chrome, &rules) as usize;
        rules.insert(idx, chrome);
        for (ix, r) in rules.iter_mut().enumerate() {
            r.position = ix as u32;
        }
        assert!(rules[0].id == "lan-cidr");

        let flow = FlowContext {
            process_name: Some("chrome".to_string()),
            process_exe: None,
            app_name: None,
            source_ip: "192.168.1.2".to_string(),
            source_port: 54321,
            destination_ip: "10.2.3.4".to_string(),
            destination_port: 443,
            destination_domain: None,
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        };
        let resolved =
            resolve_action(&rules, &flow).expect("must resolve");
        assert_eq!(resolved.rule_id, "lan-cidr");
        assert_eq!(resolved.action, RuleAction::Deny);
    }

    /// WYSIWYG: the first matching rule in position order wins, even if a
    /// later rule is "more specific". User reorder is authoritative.
    #[test]
    fn user_reordered_allow_above_deny_wins() {
        let mut allow = mk_rule(
            "allow-any",
            RuleAction::Allow,
            None,
            DestinationMatcher::Any,
        );
        allow.position = 0;
        let mut deny = mk_rule(
            "deny-firefox",
            RuleAction::Deny,
            Some("firefox"),
            DestinationMatcher::DomainExact("evil.example.com".to_string()),
        );
        deny.position = 1;
        let flow = FlowContext {
            process_name: Some("firefox".to_string()),
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 54321,
            destination_ip: "9.9.9.9".to_string(),
            destination_port: 443,
            destination_domain: Some("evil.example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
        };
        let resolved = resolve_action(&[allow, deny], &flow).expect("must resolve");
        assert_eq!(resolved.rule_id, "allow-any");
    }

    #[test]
    fn seed_position_orders_by_rank() {
        // Insert in "worst-first" creation order; the ladder must reorder them.
        let ip = mk_rule(
            "r-ip",
            RuleAction::Allow,
            None,
            DestinationMatcher::IpExact("1.2.3.4".to_string()),
        );
        let proc_any = mk_rule(
            "r-proc",
            RuleAction::Allow,
            Some("chrome"),
            DestinationMatcher::Any,
        );
        let cidr = mk_rule(
            "r-cidr",
            RuleAction::Allow,
            None,
            DestinationMatcher::Cidr("10.0.0.0/8".to_string()),
        );
        let proc_dom = mk_rule(
            "r-pdom",
            RuleAction::Allow,
            Some("curl"),
            DestinationMatcher::DomainExact("example.com".to_string()),
        );

        let mut rules: Vec<Rule> = Vec::new();
        for rule in [ip, proc_any, cidr, proc_dom] {
            let idx = seed_position(&rule, &rules) as usize;
            rules.insert(idx, rule);
        }

        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["r-pdom", "r-ip", "r-cidr", "r-proc"]);
    }
}
