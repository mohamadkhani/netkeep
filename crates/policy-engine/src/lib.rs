use core_types::{DestinationMatcher, FlowContext, Rule, RuleAction};

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
        DestinationMatcher::Cidr(prefix) => flow.destination_ip.starts_with(prefix),
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

fn specificity(rule: &Rule) -> u8 {
    let base = match rule.destination {
        DestinationMatcher::Any => 1,
        DestinationMatcher::IpExact(_) | DestinationMatcher::DomainExact(_) => 3,
        DestinationMatcher::Cidr(_) | DestinationMatcher::DomainWildcard(_) => 2,
    };
    if rule.process_name.is_some() {
        base + 2
    } else {
        base
    }
}

fn action_rank(action: &RuleAction) -> u8 {
    match action {
        RuleAction::Deny => 3,
        RuleAction::Allow | RuleAction::Route => 2,
        RuleAction::Ask => 1,
    }
}

pub fn resolve_action(rules: &[Rule], flow: &FlowContext) -> Option<ResolvedRule> {
    rules
        .iter()
        .filter(|r| r.enabled)
        .filter(|r| process_matches(r, flow) && destination_matches(r, flow))
        .max_by(|a, b| {
            (specificity(a), action_rank(&a.action), &a.id).cmp(&(
                specificity(b),
                action_rank(&b.action),
                &b.id,
            ))
        })
        .map(|r| ResolvedRule {
            rule_id: r.id.clone(),
            action: r.action.clone(),
            egress_id: r.egress_id.clone(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{FlowDirection, RuleDuration, Rule, TransportProtocol};

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
        }
    }

    #[test]
    fn wildcard_matches_subdomain_but_not_apex() {
        let flow_sub = FlowContext {
            process_name: None,
            process_exe: None,
            app_name: None,
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
        assert_eq!(resolve_action(&[rule.clone()], &flow_sub).map(|r| r.action), Some(RuleAction::Allow));
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
            resolve_action(&[rule.clone()], &flow_apex), None,
            "apex must still NOT match wildcard (separate rule required)"
        );
        assert_eq!(
            resolve_action(&[rule], &flow_unrelated), None,
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
            destination_ip: "8.8.8.8".to_string(),
            destination_port: 443,
            destination_domain: Some("example.com".to_string()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
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
        let resolved = resolve_action(&[tun, wifi], &flow).expect("must resolve");
        assert_eq!(resolved.rule_id, "demo-digikala-wifi");
        assert_eq!(resolved.egress_id, Some("eg-wifi-wlp0".into()));
    }
}

