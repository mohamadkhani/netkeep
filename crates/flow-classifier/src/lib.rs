pub mod proc_resolver;

use core_types::{FlowContext, FlowDirection, TransportProtocol};

/// Raw packet information from the network layer before classification.
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
    /// TLS SNI value extracted from ClientHello, if available.
    pub sni_hint: Option<String>,
    /// Network interface the packet arrived on (populated for gateway/routed traffic).
    pub ingress_interface: Option<String>,
    /// True when this is a TCP control packet (SYN/ACK/FIN) with no application payload.
    /// These must be accepted immediately so the handshake completes before classification.
    pub tcp_payload_empty: bool,
}

/// Resolves the local process name from a socket endpoint.
pub trait ProcessResolver {
    fn resolve(&self, src_ip: &str, src_port: u16, protocol: TransportProtocol) -> Option<String>;
}

/// Resolves a domain name from the DNS cache for a given destination IP.
pub trait DnsResolver {
    fn resolve_dns(&self, dst_ip: &str) -> Option<String>;
}

/// Maps a network interface + source IP to a human-readable device label.
pub trait DeviceLabelResolver {
    fn resolve(&self, ingress_interface: &str, src_ip: &str) -> Option<String>;
}

pub struct FlowClassifier<P, D, L> {
    process_resolver: P,
    dns_resolver: D,
    device_label_resolver: L,
}

impl<P, D, L> FlowClassifier<P, D, L>
where
    P: ProcessResolver,
    D: DnsResolver,
    L: DeviceLabelResolver,
{
    pub fn new(process_resolver: P, dns_resolver: D, device_label_resolver: L) -> Self {
        Self { process_resolver, dns_resolver, device_label_resolver }
    }

    pub fn classify(&self, packet: &RawPacket) -> FlowContext {
        let process_name = self.process_resolver.resolve(
            &packet.src_ip,
            packet.src_port,
            packet.protocol,
        );

        let destination_domain = self.resolve_domain(packet);

        let device_label = if process_name.is_none() {
            packet.ingress_interface.as_deref().and_then(|iface| {
                self.device_label_resolver.resolve(iface, &packet.src_ip)
            })
        } else {
            None
        };

        FlowContext {
            process_name,
            destination_ip: packet.dst_ip.clone(),
            destination_port: packet.dst_port,
            destination_domain,
            protocol: packet.protocol,
            direction: FlowDirection::Outbound,
            device_label,
        }
    }

    fn resolve_domain(&self, packet: &RawPacket) -> Option<String> {
        let dns_domain = self.dns_resolver.resolve_dns(&packet.dst_ip);
        let sni_domain = packet.sni_hint.clone();

        match (dns_domain, sni_domain) {
            // QUIC: SNI is unreliable; use DNS-only, fall back to None.
            (dns, _) if packet.protocol == TransportProtocol::Quic => dns,
            // Both present and agree → use it.
            (Some(dns), Some(sni)) if dns == sni => Some(dns),
            // Both present but differ → conflict, treat as IP-only.
            (Some(_), Some(_)) => None,
            // Only one source → use whichever is available.
            (Some(dns), None) => Some(dns),
            (None, Some(sni)) => Some(sni),
            (None, None) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Test fakes
// ---------------------------------------------------------------------------

pub struct FakeProcessResolver {
    pub result: Option<String>,
}

impl ProcessResolver for FakeProcessResolver {
    fn resolve(&self, _src_ip: &str, _src_port: u16, _protocol: TransportProtocol) -> Option<String> {
        self.result.clone()
    }
}

pub struct FakeDnsResolver {
    pub result: Option<String>,
}

impl DnsResolver for FakeDnsResolver {
    fn resolve_dns(&self, _dst_ip: &str) -> Option<String> {
        self.result.clone()
    }
}

pub struct FakeDeviceLabelResolver {
    pub result: Option<String>,
}

impl DeviceLabelResolver for FakeDeviceLabelResolver {
    fn resolve(&self, _iface: &str, _src_ip: &str) -> Option<String> {
        self.result.clone()
    }
}

/// Trait for classifying a raw packet into a `FlowContext`.
/// Implemented by `FlowClassifier` and test fakes.
pub trait Classifier {
    fn classify(&self, packet: &RawPacket) -> FlowContext;
}

impl<P, D, L> Classifier for FlowClassifier<P, D, L>
where
    P: ProcessResolver,
    D: DnsResolver,
    L: DeviceLabelResolver,
{
    fn classify(&self, packet: &RawPacket) -> FlowContext {
        self.classify(packet)
    }
}

/// Test fake that returns a fixed `FlowContext` regardless of the packet.
pub struct FakeClassifier {
    pub result: FlowContext,
}

impl Classifier for FakeClassifier {
    fn classify(&self, _packet: &RawPacket) -> FlowContext {
        self.result.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier(
        process: Option<&str>,
        dns: Option<&str>,
        device_label: Option<&str>,
    ) -> FlowClassifier<FakeProcessResolver, FakeDnsResolver, FakeDeviceLabelResolver> {
        FlowClassifier::new(
            FakeProcessResolver { result: process.map(str::to_string) },
            FakeDnsResolver { result: dns.map(str::to_string) },
            FakeDeviceLabelResolver { result: device_label.map(str::to_string) },
        )
    }

    fn packet(protocol: TransportProtocol, sni: Option<&str>, iface: Option<&str>) -> RawPacket {
        RawPacket {
            src_ip: "192.168.1.5".to_string(),
            src_port: 54321,
            dst_ip: "1.1.1.1".to_string(),
            dst_port: 443,
            protocol,
            sni_hint: sni.map(str::to_string),
            ingress_interface: iface.map(str::to_string),
            tcp_payload_empty: false,
        }
    }

    #[test]
    fn process_attribution_success() {
        let c = classifier(Some("curl"), None, None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, None, None));
        assert_eq!(ctx.process_name.as_deref(), Some("curl"));
    }

    #[test]
    fn process_attribution_missing_falls_back_to_none() {
        let c = classifier(None, None, None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, None, None));
        assert_eq!(ctx.process_name, None);
    }

    #[test]
    fn dns_derived_domain_association() {
        let c = classifier(Some("curl"), Some("example.com"), None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, None, None));
        assert_eq!(ctx.destination_domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn sni_derived_domain_association() {
        let c = classifier(Some("curl"), None, None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, Some("example.com"), None));
        assert_eq!(ctx.destination_domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn dns_sni_conflict_yields_ip_only() {
        let c = classifier(Some("curl"), Some("example.com"), None);
        let ctx = c.classify(&packet(TransportProtocol::Tcp, Some("other.com"), None));
        assert_eq!(ctx.destination_domain, None);
    }

    #[test]
    fn quic_falls_back_to_dns_ignores_sni() {
        // QUIC with both sources: SNI is ignored, DNS is used.
        let c = classifier(Some("app"), Some("quic-cdn.com"), None);
        let ctx = c.classify(&packet(TransportProtocol::Quic, Some("different.com"), None));
        assert_eq!(ctx.destination_domain.as_deref(), Some("quic-cdn.com"));

        // QUIC with no DNS: domain is None regardless of SNI.
        let c2 = classifier(Some("app"), None, None);
        let ctx2 = c2.classify(&packet(TransportProtocol::Quic, Some("different.com"), None));
        assert_eq!(ctx2.destination_domain, None);
    }

    #[test]
    fn gateway_flow_device_label_attached() {
        // No local process → device label resolver is consulted.
        let c = classifier(None, None, Some("home-laptop"));
        let ctx = c.classify(&packet(TransportProtocol::Tcp, None, Some("eth0")));
        assert_eq!(ctx.process_name, None);
        assert_eq!(ctx.device_label.as_deref(), Some("home-laptop"));
    }
}
