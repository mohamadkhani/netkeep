use std::net::SocketAddr;

use metrics_exporter_prometheus::PrometheusBuilder;

const DEFAULT_METRICS_PORT: u16 = 9090;
const METRICS_PORT_ENV: &str = "NETKEEP_METRICS_PORT";

pub fn start_metrics_server() {
    let port: u16 = std::env::var(METRICS_PORT_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_METRICS_PORT);

    if port == 0 {
        eprintln!("prometheus metrics disabled (port=0)");
        return;
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    if let Err(e) = PrometheusBuilder::new()
        .with_http_listener(addr)
        .with_recommended_naming(true)
        .install()
    {
        eprintln!("failed to start prometheus metrics on :{port}: {e}");
        return;
    }

    println!("prometheus metrics listening on :{port}");
}
