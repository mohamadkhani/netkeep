use std::io::{copy, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use control_api::{ControlRequest, ControlResponse};
use core_types::{FlowContext, FlowDirection, RouteTarget, RuleAction, TransportProtocol};

pub fn send_control_request(socket_path: &str, request: &ControlRequest) -> Result<ControlResponse, String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("failed to connect to daemon socket {socket_path}: {e}"))?;
    let payload = serde_json::to_string(request).map_err(|e| e.to_string())?;
    stream
        .write_all(format!("{payload}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(line.trim_end()).map_err(|e| e.to_string())
}

pub fn parse_socks5_target(stream: &mut TcpStream) -> Result<(String, u16), String> {
    let mut hello = [0u8; 2];
    stream.read_exact(&mut hello).map_err(|e| e.to_string())?;
    if hello[0] != 0x05 {
        return Err("not a SOCKS5 client".to_string());
    }
    let n_methods = hello[1] as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).map_err(|e| e.to_string())?;
    let no_auth = methods.contains(&0x00);
    if !no_auth {
        stream.write_all(&[0x05, 0xFF]).map_err(|e| e.to_string())?;
        return Err("client does not support no-auth SOCKS5".to_string());
    }
    stream.write_all(&[0x05, 0x00]).map_err(|e| e.to_string())?;

    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).map_err(|e| e.to_string())?;
    if req_header[0] != 0x05 || req_header[1] != 0x01 {
        return Err("only SOCKS5 CONNECT is supported".to_string());
    }
    let atyp = req_header[3];
    let host = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).map_err(|e| e.to_string())?;
            IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_string()
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
            let len = len_buf[0] as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).map_err(|e| e.to_string())?;
            String::from_utf8(domain).map_err(|e| e.to_string())?
        }
        0x04 => {
            let mut ip6 = [0u8; 16];
            stream.read_exact(&mut ip6).map_err(|e| e.to_string())?;
            std::net::Ipv6Addr::from(ip6).to_string()
        }
        _ => return Err("unsupported address type".to_string()),
    };
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).map_err(|e| e.to_string())?;
    let port = u16::from_be_bytes(port_buf);
    Ok((host, port))
}

pub fn deny_reply(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|e| e.to_string())
}

pub fn success_reply(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|e| e.to_string())
}

/// SOCKS5 reply with a generic connection failure (reply code 0x05 = connection refused).
pub fn fail_reply(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|e| e.to_string())
}

pub fn relay_bidirectional(client: TcpStream, upstream: TcpStream) -> Result<(), String> {
    let mut c_read = client.try_clone().map_err(|e| e.to_string())?;
    let mut c_write = client;
    let mut u_read = upstream.try_clone().map_err(|e| e.to_string())?;
    let mut u_write = upstream;

    let t1 = thread::spawn(move || copy(&mut c_read, &mut u_write).map_err(|e| e.to_string()));
    let t2 = thread::spawn(move || copy(&mut u_read, &mut c_write).map_err(|e| e.to_string()));

    let _ = t1.join().map_err(|_| "relay thread join failed".to_string())??;
    let _ = t2.join().map_err(|_| "relay thread join failed".to_string())??;
    Ok(())
}

/// Emulator is intentionally unprivileged. It does not apply socket-level
/// routing options (`SO_MARK` / `SO_BINDTODEVICE`) and always opens a normal
/// upstream TCP connection.
///
/// Route decisions are still registered with daemon (RuleAction::Route), but
/// actual privileged enforcement belongs to daemon/enforcer path.
fn connect_upstream(
    host: &str,
    port: u16,
    route_target: Option<&RouteTarget>,
    socket_path: &str,
) -> Result<TcpStream, String> {
    match route_target {
        Some(target) => {
            let response = send_control_request(
                socket_path,
                &ControlRequest::OpenRoutedTcp {
                    host: host.to_string(),
                    port,
                    target: target.clone(),
                },
            )?;
            match response {
                ControlResponse::RoutedTcpReady { listen_addr } => TcpStream::connect(&listen_addr)
                    .map_err(|e| format!("failed to connect routed relay {listen_addr}: {e}")),
                ControlResponse::Error(e) => Err(format!("daemon routed connect failed: {e}")),
                other => Err(format!("unexpected OpenRoutedTcp response: {other:?}")),
            }
        }
        None => {
            let addr = format!("{host}:{port}");
            TcpStream::connect(&addr).map_err(|e| format!("upstream connect to {addr} failed: {e}"))
        }
    }
}

pub fn handle_client(mut stream: TcpStream, socket_path: &str) -> Result<(), String> {
    let (host, port) = parse_socks5_target(&mut stream)?;
    let parsed_ip = host.parse::<IpAddr>().ok();
    let flow = FlowContext {
        process_name: Some("socks-client".to_string()),
        destination_ip: parsed_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string()),
        destination_port: port,
        destination_domain: if parsed_ip.is_none() { Some(host.clone()) } else { None },
        protocol: TransportProtocol::Tcp,
        direction: FlowDirection::Outbound,
        device_label: None,
    };
    let response = send_control_request(
        socket_path,
        &ControlRequest::RegisterUnknownFlow {
            flow,
            now_secs: current_unix_secs(),
        },
    )
    .map_err(|e| {
        let _ = fail_reply(&mut stream);
        e
    })?;
    match response {
        ControlResponse::ImmediateVerdict {
            action: RuleAction::Allow,
        } => {
            let upstream = connect_upstream(&host, port, None, socket_path).map_err(|e| {
                let _ = fail_reply(&mut stream);
                e
            })?;
            success_reply(&mut stream)?;
            relay_bidirectional(stream, upstream)
        }
        ControlResponse::ImmediateVerdict {
            action: RuleAction::Route { target },
        } => {
            let upstream = connect_upstream(&host, port, Some(&target), socket_path).map_err(|e| {
                let _ = fail_reply(&mut stream);
                e
            })?;
            success_reply(&mut stream)?;
            relay_bidirectional(stream, upstream)
        }
        ControlResponse::PendingCreated { pending_id, deadline_at_secs, .. } => {
            wait_for_pending_and_continue(stream, socket_path, &pending_id, deadline_at_secs, host, port)
        }
        _ => {
            deny_reply(&mut stream)?;
            Ok(())
        }
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn wait_for_pending_and_continue(
    mut stream: TcpStream,
    socket_path: &str,
    pending_id: &str,
    deadline_at_secs: u64,
    host: String,
    port: u16,
) -> Result<(), String> {
    loop {
        if current_unix_secs() > deadline_at_secs {
            deny_reply(&mut stream)?;
            return Ok(());
        }
        let poll = send_control_request(
            socket_path,
            &ControlRequest::AwaitPendingDecision {
                pending_id: pending_id.to_string(),
            },
        )
        .map_err(|e| {
            let _ = fail_reply(&mut stream);
            e
        })?;
        match poll {
            ControlResponse::PendingStillWaiting { .. } => {
                thread::sleep(Duration::from_millis(200));
            }
            ControlResponse::PendingResolved {
                action: RuleAction::Allow,
            }
            | ControlResponse::ImmediateVerdict {
                action: RuleAction::Allow,
            } => {
                let upstream = connect_upstream(&host, port, None, socket_path).map_err(|e| {
                    let _ = fail_reply(&mut stream);
                    e
                })?;
                success_reply(&mut stream)?;
                return relay_bidirectional(stream, upstream);
            }
            ControlResponse::PendingResolved {
                action: RuleAction::Route { target },
            }
            | ControlResponse::ImmediateVerdict {
                action: RuleAction::Route { target },
            } => {
                let upstream = connect_upstream(&host, port, Some(&target), socket_path).map_err(|e| {
                    let _ = fail_reply(&mut stream);
                    e
                })?;
                success_reply(&mut stream)?;
                return relay_bidirectional(stream, upstream);
            }
            _ => {
                deny_reply(&mut stream)?;
                return Ok(());
            }
        }
    }
}

