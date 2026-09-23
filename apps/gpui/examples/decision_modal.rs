//! Standalone preview of the connection decision dialog — no daemon needed.
//!
//! The example recompiles the dialog's source modules via `#[path]`
//! includes, so it always exercises the exact production UI code.
//!
//! Run:
//!
//! ```text
//! cargo run -p netkeep-gpui --example decision_modal -- [flags]
//! ```
//!
//! Flags override every condition of the synthetic pending decision:
//!
//! ```text
//! --process curl   --exe /usr/bin/curl   --app "cURL"
//! --ip 93.184.216.34   --port 443   --domain example.com
//! --proto tcp|udp|quic|other   --device wlan0   --timeout 30
//! ```
//!
//! Pass `none` to `--process`/`--exe`/`--app`/`--domain`/`--device` to drop
//! that field — e.g. `--domain none` exercises the IP-only rule scopes,
//! `--process none --domain none` exercises the unknown-connection warning.
//! Allow/Deny just exits without talking to a daemon.

// The included modules carry items used by the rest of the production
// binary (settings, tray) but not by this example; that is expected here.
#![allow(unused_imports, dead_code)]

#[path = "../src/app.rs"]
mod app;
#[path = "../src/colors.rs"]
mod colors;
#[path = "../src/components/mod.rs"]
mod components;
#[path = "../src/daemon.rs"]
mod daemon;
#[path = "../src/decision_dialog.rs"]
mod decision_dialog;
#[path = "../src/fonts.rs"]
mod fonts;
#[path = "../src/state.rs"]
mod state;

use core_types::{
    Egress, FlowContext, FlowDirection, PendingDecision, RouteTarget, TransportProtocol,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let flag = |name: &str| -> Option<&str> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
    };
    // `Some(None)` = flag given as `none` (drop the field),
    // `None` = flag absent (use the default).
    let specified = |name: &str| -> Option<Option<String>> {
        flag(name).map(|v| {
            if v.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(v.to_string())
            }
        })
    };
    let field = |name: &str, default: &str| -> Option<String> {
        specified(name).unwrap_or_else(|| Some(default.to_string()))
    };

    let proto = match flag("--proto").unwrap_or("tcp") {
        "tcp" => TransportProtocol::Tcp,
        "udp" => TransportProtocol::Udp,
        "quic" => TransportProtocol::Quic,
        "other" => TransportProtocol::Other,
        other => {
            eprintln!("--proto must be one of: tcp, udp, quic, other (got '{other}')");
            std::process::exit(2);
        }
    };
    let port: u16 = match flag("--port") {
        Some(v) => v.parse().unwrap_or_else(|_| {
            eprintln!("--port must be 0-65535 (got '{v}')");
            std::process::exit(2);
        }),
        None => 443,
    };
    let timeout: u64 = match flag("--timeout") {
        Some(v) => v.parse().unwrap_or_else(|_| {
            eprintln!("--timeout must be seconds (got '{v}')");
            std::process::exit(2);
        }),
        None => 30,
    };

    let now = daemon::unix_now();
    let item = PendingDecision {
        id: "test-decision".to_string(),
        flow: FlowContext {
            process_name: field("--process", "curl"),
            process_exe: field("--exe", "/usr/bin/curl"),
            app_name: field("--app", "cURL"),
            source_ip: flag("--source-ip").unwrap_or("192.168.1.10").to_string(),
            source_port: flag("--source-port")
                .and_then(|v| v.parse().ok())
                .unwrap_or(52344),
            destination_ip: flag("--ip").unwrap_or("93.184.216.34").to_string(),
            destination_port: port,
            destination_domain: field("--domain", "example.com"),
            protocol: proto,
            direction: FlowDirection::Outbound,
            device_label: specified("--device").unwrap_or(None),
            tcp_syn: false,
        },
        created_at_secs: now,
        deadline_at_secs: now + timeout,
    };

    // Synthetic egress list: default route, an available TUN, an available
    // Wi-Fi, and an unavailable LAN — covers every chip state in the
    // "Route via" selector deterministically, regardless of real interfaces.
    let egresses = vec![
        Egress {
            id: "eg-default".to_string(),
            name: "Default Route".to_string(),
            color: "#6b7280".to_string(),
            targets: vec![],
            dns_servers: vec![],
            is_system_default: true,
            is_available: true,
        },
        Egress {
            id: "eg-test-tun".to_string(),
            name: "TUN: test0".to_string(),
            color: "#22c55e".to_string(),
            targets: vec![RouteTarget::Tun("test0".to_string())],
            dns_servers: vec!["1.1.1.1".to_string()],
            is_system_default: false,
            is_available: true,
        },
        Egress {
            id: "eg-test-wifi".to_string(),
            name: "Wi-Fi: wlan0".to_string(),
            color: "#3b82f6".to_string(),
            targets: vec![RouteTarget::Device("wlan0".to_string())],
            dns_servers: vec![],
            is_system_default: false,
            is_available: true,
        },
        Egress {
            id: "eg-test-dead".to_string(),
            name: "LAN: eth9".to_string(),
            color: "#ef4444".to_string(),
            targets: vec![RouteTarget::Device("eth9".to_string())],
            dns_servers: vec![],
            is_system_default: false,
            is_available: false,
        },
    ];

    decision_dialog::show_decision_dialog(item, egresses);
}
