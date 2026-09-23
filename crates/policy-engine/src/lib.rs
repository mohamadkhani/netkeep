use core_types::{DestinationMatcher, FlowContext, ProcessPriority, Rule, RuleAction};
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
/// Semantics: matches the apex itself **and** any depth of proper subdomains.
/// `"example.com"` matches `"example.com"`, `"api.example.com"` and
/// `"a.b.example.com"` but not `"notexample.com"`. This deviates from the
/// original subdomains-only contract: re-prompting the user for the very
/// host they just wildcarded felt like a broken rule (see
/// `docs/decision-dialog-ux.md`).
fn wildcard_matches(pattern: &str, host: &str) -> bool {
    let apex = pattern.strip_prefix("*.").unwrap_or(pattern);
    if apex.is_empty() {
        return false;
    }
    host == apex || host.ends_with(&format!(".{apex}"))
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
        let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        (u32::from(net) & mask) == (u32::from(addr) & mask)
    } else {
        ip.starts_with(prefix)
    }
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

/// Built-in restriction ladder — default priority *bases* for new rules.
/// See the priority ladder. Higher base = more restricted combo = higher precedence.
/// Deliberate orderings: wildcard > cidr on both axes (a domain wildcard
/// constrains intent more tightly than a CIDR range); ip > domain (IP match
/// is deterministic, domain match depends on resolution).
///
/// `process + Any` has no destination specificity to rank by, so it splits
/// into two creator-chosen slots: `High` (7) or `Low` (2). There is no
/// default tier — plain `AddRule` seeds `High`.
pub fn priority_base(rule: &Rule, process_priority: ProcessPriority) -> f64 {
    let has_proc = rule.process_name.is_some() || rule.process_exe.is_some();
    match (&rule.destination, has_proc) {
        (DestinationMatcher::IpExact(_), true) => 12.0,
        (DestinationMatcher::DomainExact(_), true) => 11.0,
        (DestinationMatcher::DomainWildcard(_), true) => 10.0,
        (DestinationMatcher::Cidr(_), true) => 9.0,
        (DestinationMatcher::Any, true) => match process_priority {
            ProcessPriority::High => 7.0,
            ProcessPriority::Low => 2.0,
        },
        (DestinationMatcher::IpExact(_), false) => 6.0,
        (DestinationMatcher::DomainExact(_), false) => 5.0,
        (DestinationMatcher::DomainWildcard(_), false) => 4.0,
        (DestinationMatcher::Cidr(_), false) => 3.0,
        (DestinationMatcher::Any, false) => 1.0,
    }
}

/// Seed a new rule's priority: `base + recency fraction`.
///
/// `creation_seq` is a monotonically increasing creation counter (SQLite
/// `rowid` works). The fraction stays strictly inside `(base, base + 1)` so
/// it can never leak into a neighboring combo's range, and newer rules in
/// the same combo class rank above older ones (newest intent wins). The
/// `% 999` wrap reorders after 999 same-combo rules — accepted per the priority ladder.
pub fn seed_priority(rule: &Rule, creation_seq: i64, process_priority: ProcessPriority) -> f64 {
    priority_base(rule, process_priority) + (creation_seq.rem_euclid(999) as f64) / 1000.0
}

fn action_rank(action: &RuleAction) -> u8 {
    match action {
        RuleAction::Deny => 3,
        RuleAction::Allow | RuleAction::Route => 2,
        RuleAction::Ask => 1,
    }
}

pub fn resolve_action(rules: &[Rule], flow: &FlowContext) -> Option<ResolvedRule> {
    let start = std::time::Instant::now();
    counter!("netkeep.policy.evaluations").increment(1);

    let result = rules
        .iter()
        .filter(|r| r.enabled)
        .filter(|r| process_matches(r, flow) && destination_matches(r, flow))
        .max_by(|a, b| {
            a.priority
                .partial_cmp(&b.priority)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| (action_rank(&a.action), &a.id).cmp(&(action_rank(&b.action), &b.id)))
        })
        .map(|r| ResolvedRule {
            rule_id: r.id.clone(),
            action: r.action.clone(),
            egress_id: r.egress_id.clone(),
        });

    histogram!("netkeep.policy.evaluation.duration").record(start.elapsed().as_secs_f64());

    match &result {
        Some(r) => {
            let action_str = match r.action {
                RuleAction::Allow => "allow",
                RuleAction::Deny => "deny",
                RuleAction::Ask => "ask",
                RuleAction::Route => "route",
            };
            counter!("netkeep.policy.resolved", "action" => action_str).increment(1);
        }
        None => {
            counter!("netkeep.policy.no_match").increment(1);
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
        mk_rule_at(id, action, process_name, destination, 5.0)
    }

    fn mk_rule_at(
        id: &str,
        action: RuleAction,
        process_name: Option<&str>,
        destination: DestinationMatcher,
        priority: f64,
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
            priority,
        }
    }

    #[test]
    fn wildcard_matches_apex_and_subdomains() {
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
            tcp_syn: false,
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
            tcp_syn: false,
        };
        let rule = mk_rule(
            "r1",
            RuleAction::Allow,
            None,
            DestinationMatcher::DomainWildcard("*.example.com".to_string()),
        );
        assert_eq!(
            resolve_action(std::slice::from_ref(&rule), &flow_sub).map(|r| r.action),
            Some(RuleAction::Allow)
        );
        assert_eq!(
            resolve_action(&[rule], &flow_apex).map(|r| r.action),
            Some(RuleAction::Allow),
            "apex must match too — re-prompting for the wildcarded host reads as a broken rule"
        );
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
            tcp_syn: false,
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
            resolve_action(std::slice::from_ref(&rule), &flow_sub).map(|r| r.action),
            Some(RuleAction::Allow),
            "subdomain must match apex-only wildcard storage"
        );
        assert_eq!(
            resolve_action(std::slice::from_ref(&rule), &flow_deep).map(|r| r.action),
            Some(RuleAction::Allow),
            "deep subdomain must match apex-only wildcard storage"
        );
        assert_eq!(
            resolve_action(std::slice::from_ref(&rule), &flow_apex).map(|r| r.action),
            Some(RuleAction::Allow),
            "apex must match too (apex + subdomains wildcard semantics)"
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
            tcp_syn: false,
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
            tcp_syn: false,
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
            tcp_syn: false,
        };
        let general = mk_rule(
            "general",
            RuleAction::Allow,
            None,
            DestinationMatcher::DomainWildcard("*.example.com".to_string()),
        );
        let specific = mk_rule(
            "specific",
            RuleAction::Deny,
            Some("firefox"),
            DestinationMatcher::DomainWildcard("*.example.com".to_string()),
        );
        let resolved = resolve_action(&[general, specific], &flow).expect("must resolve");
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
            tcp_syn: false,
        };
        let allow = mk_rule(
            "allow",
            RuleAction::Allow,
            None,
            DestinationMatcher::DomainExact("example.com".to_string()),
        );
        let deny = mk_rule(
            "deny",
            RuleAction::Deny,
            None,
            DestinationMatcher::DomainExact("example.com".to_string()),
        );
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
            tcp_syn: false,
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

    /// Exactly the form `build_dest_matcher`, `parse_destination`, and the
    /// settings form persist (`"a.b.c.d/N"`). Before `cidr_contains` this
    /// rule NEVER matched: the matcher ran `"10.0.0.5".starts_with("10.0.0.0/24")`.
    #[test]
    fn cidr_matches_dialog_cidr_notation() {
        let rule = mk_rule(
            "cidr-24",
            RuleAction::Allow,
            None,
            DestinationMatcher::Cidr("10.0.0.0/24".into()),
        );
        let inside = flow_unknown_proc(None, "10.0.0.5");
        let outside = flow_unknown_proc(None, "10.0.1.5");
        assert_eq!(
            resolve_action(std::slice::from_ref(&rule), &inside).map(|r| r.action),
            Some(RuleAction::Allow)
        );
        assert_eq!(resolve_action(&[rule], &outside), None);
    }

    #[test]
    fn cidr_mask_covers_whole_network() {
        let rule = mk_rule(
            "cidr-8",
            RuleAction::Deny,
            None,
            DestinationMatcher::Cidr("10.0.0.0/8".into()),
        );
        for ip in ["10.0.0.1", "10.9.9.9", "10.255.255.254"] {
            let flow = flow_unknown_proc(None, ip);
            assert_eq!(
                resolve_action(std::slice::from_ref(&rule), &flow).map(|r| r.action),
                Some(RuleAction::Deny),
                "/8 must cover {ip}"
            );
        }
        let outside = flow_unknown_proc(None, "11.0.0.1");
        assert_eq!(resolve_action(&[rule], &outside), None);
    }

    /// Legacy dotted-prefix storage (`"10.0.0."`, no `/N`) keeps working.
    #[test]
    fn cidr_legacy_dotted_prefix_still_matches() {
        let rule = mk_rule(
            "cidr-legacy",
            RuleAction::Allow,
            None,
            DestinationMatcher::Cidr("10.0.0.".into()),
        );
        let flow = flow_unknown_proc(None, "10.0.0.77");
        assert_eq!(
            resolve_action(&[rule], &flow).map(|r| r.action),
            Some(RuleAction::Allow)
        );
    }

    /// A malformed prefix must fail closed — match nothing, not everything.
    #[test]
    fn cidr_unparsable_prefix_matches_nothing() {
        let rule = mk_rule(
            "cidr-bad",
            RuleAction::Allow,
            None,
            DestinationMatcher::Cidr("not-an-ip/24".into()),
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
            tcp_syn: false,
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
        let resolved = resolve_action(&[tun, wifi], &flow).expect("must resolve");
        assert_eq!(resolved.rule_id, "demo-digikala-wifi");
        assert_eq!(resolved.egress_id, Some("eg-wifi-wlp0".into()));
    }

    #[test]
    fn priority_base_ranks_every_combo_by_restriction() {
        // the priority ladder ladder. Asserts the full ordering, including the two
        // deliberate inversions: wildcard > cidr on both axes, and ip > domain.
        let cases = [
            (
                Some("firefox"),
                DestinationMatcher::IpExact("1.1.1.1".into()),
                12.0,
            ),
            (
                Some("firefox"),
                DestinationMatcher::DomainExact("a.com".into()),
                11.0,
            ),
            (
                Some("firefox"),
                DestinationMatcher::DomainWildcard("*.a.com".into()),
                10.0,
            ),
            (
                Some("firefox"),
                DestinationMatcher::Cidr("10.0.0.0/8".into()),
                9.0,
            ),
            (None, DestinationMatcher::IpExact("1.1.1.1".into()), 6.0),
            (None, DestinationMatcher::DomainExact("a.com".into()), 5.0),
            (
                None,
                DestinationMatcher::DomainWildcard("*.a.com".into()),
                4.0,
            ),
            (None, DestinationMatcher::Cidr("10.0.0.0/8".into()), 3.0),
            (None, DestinationMatcher::Any, 1.0),
        ];
        for (proc_name, dest, expected) in cases {
            let rule = mk_rule("x", RuleAction::Allow, proc_name, dest.clone());
            let got = priority_base(&rule, ProcessPriority::High);
            assert_eq!(got, expected, "base for ({proc_name:?}, {dest:?})");
        }

        // process + Any is the only combo whose base depends on the tier.
        let any = mk_rule(
            "x",
            RuleAction::Allow,
            Some("firefox"),
            DestinationMatcher::Any,
        );
        assert_eq!(priority_base(&any, ProcessPriority::High), 7.0);
        assert_eq!(priority_base(&any, ProcessPriority::Low), 2.0);
    }

    #[test]
    fn seed_priority_fraction_stays_inside_its_own_combo_band() {
        // The recency fraction must never leak into a neighboring combo's
        // range, or a broad rule could outrank a more restricted one.
        let rule = mk_rule(
            "x",
            RuleAction::Allow,
            Some("firefox"),
            DestinationMatcher::DomainExact("a.com".into()),
        );
        let base = priority_base(&rule, ProcessPriority::High);

        for seq in [0_i64, 1, 42, 998, 999, 1000, 123_456] {
            let p = seed_priority(&rule, seq, ProcessPriority::High);
            assert!(
                p >= base && p < base + 1.0,
                "seq {seq} produced {p}, outside [{base}, {})",
                base + 1.0
            );
        }

        // Newer rules (higher seq) outrank older ones within a combo class.
        let older = seed_priority(&rule, 10, ProcessPriority::High);
        let newer = seed_priority(&rule, 11, ProcessPriority::High);
        assert!(
            newer > older,
            "newer rule must outrank older: {newer} vs {older}"
        );
    }

    #[test]
    fn process_any_high_beats_low_and_below_process_destination() {
        // Two process+Any rules: High (base 7) must outrank Low (base 2).
        let mut high = mk_rule(
            "proc-high",
            RuleAction::Allow,
            Some("firefox"),
            DestinationMatcher::Any,
        );
        high.priority = seed_priority(&high, 1, ProcessPriority::High);
        let mut low = mk_rule(
            "proc-low",
            RuleAction::Deny,
            Some("firefox"),
            DestinationMatcher::Any,
        );
        low.priority = seed_priority(&low, 2, ProcessPriority::Low);

        let flow = FlowContext {
            process_name: Some("firefox".to_string()),
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 1,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: None,
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
            tcp_syn: false,
        };
        // Low has the higher action_rank (Deny), but priority dominates.
        let resolved = resolve_action(&[low, high], &flow).expect("must resolve");
        assert_eq!(resolved.rule_id, "proc-high");
    }

    #[test]
    fn process_destination_beats_process_any_high() {
        // A destination-only rule (ip, base 6) outranks process+Any High (7)?
        // No — base 7 > base 6, so process+Any High wins. This pins the
        // ladder ordering: process+Any High sits above ip/domain-only rules.
        let mut proc_any = mk_rule(
            "proc-any",
            RuleAction::Allow,
            Some("firefox"),
            DestinationMatcher::Any,
        );
        proc_any.priority = seed_priority(&proc_any, 1, ProcessPriority::High);
        let mut ip_only = mk_rule(
            "ip-only",
            RuleAction::Deny,
            None,
            DestinationMatcher::IpExact("1.1.1.1".to_string()),
        );
        ip_only.priority = seed_priority(&ip_only, 2, ProcessPriority::High);

        let flow = FlowContext {
            process_name: Some("firefox".to_string()),
            process_exe: None,
            app_name: None,
            source_ip: "10.0.0.1".to_string(),
            source_port: 1,
            destination_ip: "1.1.1.1".to_string(),
            destination_port: 443,
            destination_domain: None,
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
            tcp_syn: false,
        };
        let resolved = resolve_action(&[ip_only, proc_any], &flow).expect("must resolve");
        assert_eq!(resolved.rule_id, "proc-any");
    }
}
