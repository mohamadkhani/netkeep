use std::collections::HashMap;

/// Live proxy redirects, shared by route selection and nftables recovery.
pub(crate) struct ProxyRoutes {
    routes: HashMap<String, (u32, u16)>,
    next_mark: u32,
}

impl ProxyRoutes {
    pub(crate) fn new(routes: HashMap<String, (u32, u16)>) -> Self {
        let next_mark = routes
            .values()
            .map(|(mark, _)| *mark)
            .min()
            .unwrap_or(enforcer::DAEMON_BYPASS_MARK)
            .saturating_sub(1);
        Self { routes, next_mark }
    }

    pub(crate) fn redirects(&self) -> Vec<(u32, u16)> {
        self.routes.values().copied().collect()
    }

    /// Prepare a listener and install its redirect before publishing the mark.
    /// The caller starts the returned listener after this succeeds.
    pub(crate) fn ensure<T>(
        &mut self,
        id: &str,
        prepare: impl FnOnce() -> Result<(u16, T), String>,
        install: impl FnOnce(u32, u16) -> Result<(), String>,
    ) -> Result<(u32, Option<T>), String> {
        if let Some((mark, _)) = self.routes.get(id) {
            return Ok((*mark, None));
        }
        let mark = self.next_mark;
        if mark == 0 {
            return Err("proxy routing marks exhausted".into());
        }
        let (port, listener) = prepare()?;
        install(mark, port)?;
        self.routes.insert(id.to_string(), (mark, port));
        self.next_mark -= 1;
        Ok((mark, Some(listener)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switching_to_proxy_added_after_startup_installs_its_own_redirect() {
        let old_mark = enforcer::DAEMON_BYPASS_MARK - 1;
        let mut routes = ProxyRoutes::new(HashMap::from([("old".into(), (old_mark, 10001))]));
        let (mark, listener) = routes
            .ensure(
                "replacement",
                || Ok((10002, "replacement listener")),
                |mark, port| {
                    assert_eq!((mark, port), (old_mark - 1, 10002));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(mark, old_mark - 1);
        assert_eq!(listener, Some("replacement listener"));
        assert!(routes.redirects().contains(&(mark, 10002)));
        assert!(routes.redirects().contains(&(old_mark, 10001)));
        let (reused, listener) = routes
            .ensure::<()>(
                "replacement",
                || panic!("must reuse listener"),
                |_, _| panic!("must reuse redirect"),
            )
            .unwrap();
        assert_eq!(reused, mark);
        assert!(listener.is_none());
    }

    #[test]
    fn failed_redirect_installation_is_not_published_and_can_retry() {
        let mut routes = ProxyRoutes::new(HashMap::new());
        assert!(routes
            .ensure("new", || Ok((10002, ())), |_, _| Err("nft failed".into()))
            .is_err());
        assert!(routes.redirects().is_empty());
        let (mark, _) = routes
            .ensure("new", || Ok((10003, ())), |_, _| Ok(()))
            .unwrap();
        assert_eq!(routes.redirects(), vec![(mark, 10003)]);
    }

    #[test]
    fn failed_listener_preparation_does_not_install_or_publish_a_redirect() {
        let mut routes = ProxyRoutes::new(HashMap::new());
        assert!(routes
            .ensure::<()>(
                "new",
                || Err("listener failed".into()),
                |_, _| panic!("must not redirect to a missing listener"),
            )
            .is_err());
        assert!(routes.redirects().is_empty());
    }

    #[test]
    fn egress_edit_selects_replacement_proxy_without_changing_the_rule() {
        use control_api::{ControlRequest, ControlResponse};
        use core_types::{
            DestinationMatcher, Egress, FlowContext, FlowDirection, ProxyAuth, ProxyConfig,
            ProxyProtocol, RouteTarget, Rule, RuleAction, RuleDuration, TransportProtocol,
        };
        use enforcer::{FlowDecision, FlowRegistrar};
        use std::sync::{Arc, Mutex};

        let mut service =
            control_service::ControlService::new(state_store::InMemoryRuleRepository::default());
        for id in ["old", "replacement"] {
            assert_eq!(
                service.handle(ControlRequest::UpsertProxy(ProxyConfig {
                    id: id.into(),
                    name: id.into(),
                    protocol: ProxyProtocol::Socks5,
                    host: "127.0.0.1".into(),
                    port: 1080,
                    auth: ProxyAuth::None,
                    enabled: true,
                })),
                ControlResponse::Ok
            );
        }
        let old_mark = enforcer::DAEMON_BYPASS_MARK - 1;
        let routes = Arc::new(Mutex::new(ProxyRoutes::new(HashMap::from([(
            "old".into(),
            (old_mark, 10001),
        )]))));
        let live_routes = Arc::clone(&routes);
        service.set_route_mark_fn(move |target| {
            let RouteTarget::Proxy(id) = target else {
                panic!("expected proxy")
            };
            live_routes
                .lock()
                .unwrap()
                .ensure(id, || Ok((10002, ())), |_, _| Ok(()))
                .ok()
                .map(|(mark, _)| mark)
        });
        assert_eq!(
            service.handle(ControlRequest::AddRule(Rule {
                id: "rule".into(),
                enabled: true,
                action: RuleAction::Route,
                duration: RuleDuration::Permanent,
                process_name: Some("curl".into()),
                process_exe: None,
                destination: DestinationMatcher::Any,
                egress_id: Some("egress".into()),
                priority: 500.0,
            })),
            ControlResponse::Ok
        );
        let flow = FlowContext {
            process_name: Some("curl".into()),
            process_exe: None,
            app_name: None,
            source_ip: "192.0.2.1".into(),
            source_port: 12345,
            destination_ip: "198.51.100.1".into(),
            destination_port: 443,
            destination_domain: Some("example.com".into()),
            protocol: TransportProtocol::Tcp,
            direction: FlowDirection::Outbound,
            device_label: None,
            tcp_syn: true,
        };
        for (id, expected_mark) in [
            ("old", old_mark),
            ("replacement", old_mark - 1),
            ("old", old_mark),
        ] {
            let target = RouteTarget::Proxy(id.into());
            let previous_revision = service.routing_revision();
            assert_eq!(
                service.handle(ControlRequest::UpsertEgress(Egress {
                    id: "egress".into(),
                    name: "egress".into(),
                    color: "#123456".into(),
                    targets: vec![target.clone()],
                    dns_servers: vec![],
                    is_system_default: false,
                    is_available: true,
                })),
                ControlResponse::Ok
            );
            assert_ne!(service.routing_revision(), previous_revision);
            assert_eq!(
                service.register(flow.clone(), 1000),
                FlowDecision::Immediate(RuleAction::Route, Some(target.clone()))
            );
            assert_eq!(service.route_mark(&target), Some(expected_mark));
        }
        assert_eq!(routes.lock().unwrap().redirects().len(), 2);
    }
}
