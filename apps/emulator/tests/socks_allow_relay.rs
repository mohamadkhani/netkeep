use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::thread;
use std::time::Duration;

use control_api::ControlResponse;
use core_types::RuleAction;
use netkeep_emulator::handle_client;
use tempfile::TempDir;

fn start_mock_daemon(socket_path: String) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind unix");
        let (mut stream, _) = listener.accept().expect("accept unix");
        let mut line = String::new();
        {
            let mut reader = BufReader::new(&stream);
            reader.read_line(&mut line).expect("read request");
        }
        assert!(line.contains("\"RegisterUnknownFlow\""));
        let response = serde_json::to_string(&ControlResponse::ImmediateVerdict {
            action: RuleAction::Allow,
            route_target: None,
        })
        .expect("serialize response");
        stream
            .write_all(format!("{response}\n").as_bytes())
            .expect("write response");
    })
}

#[test]
fn socks_connect_allow_relay_passes_upstream_response() {
    let temp = TempDir::new().expect("tempdir");
    let socket_path = temp
        .path()
        .join("daemon.sock")
        .to_string_lossy()
        .to_string();

    let daemon_thread = start_mock_daemon(socket_path.clone());

    let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_thread = thread::spawn(move || {
        let (mut conn, _) = upstream_listener.accept().expect("accept upstream");
        let mut req_buf = [0u8; 512];
        let _ = conn.read(&mut req_buf).expect("read upstream request");
        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .expect("write upstream response");
    });

    let emulator_listener = TcpListener::bind("127.0.0.1:0").expect("bind emulator");
    let emulator_addr = emulator_listener.local_addr().expect("emulator addr");
    let emulator_socket_path = socket_path.clone();
    let emulator_thread = thread::spawn(move || {
        let (stream, _) = emulator_listener.accept().expect("accept emulator");
        handle_client(stream, &emulator_socket_path).expect("handle client");
    });

    let mut client = TcpStream::connect(emulator_addr).expect("connect emulator");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).expect("read auth reply");
    assert_eq!(auth_reply, [0x05, 0x00]);

    let host = "127.0.0.1".as_bytes();
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    connect_req.extend_from_slice(host);
    connect_req.extend_from_slice(&upstream_addr.port().to_be_bytes());
    client
        .write_all(&connect_req)
        .expect("write connect request");

    let mut connect_reply = [0u8; 10];
    client
        .read_exact(&mut connect_reply)
        .expect("read connect reply");
    assert_eq!(connect_reply[0], 0x05);
    assert_eq!(connect_reply[1], 0x00);

    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .expect("write proxied request");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown client write");
    let mut resp_buf = [0u8; 128];
    let n = client.read(&mut resp_buf).expect("read proxied response");
    let text = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(text.contains("200 OK"));
    assert!(text.contains("\r\n\r\nOK"));

    emulator_thread.join().expect("join emulator");
    upstream_thread.join().expect("join upstream");
    daemon_thread.join().expect("join daemon");
}

#[test]
fn socks_pending_keeps_connection_open_until_allow_then_relays() {
    let temp = TempDir::new().expect("tempdir");
    let socket_path = temp
        .path()
        .join("daemon.sock")
        .to_string_lossy()
        .to_string();

    let daemon_thread = thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind unix");
            let mut await_count = 0usize;
            loop {
                let (mut stream, _) = listener.accept().expect("accept unix");
                let mut line = String::new();
                {
                    let mut reader = BufReader::new(&stream);
                    reader.read_line(&mut line).expect("read request");
                }
                let response = if line.contains("\"RegisterUnknownFlow\"") {
                    ControlResponse::PendingCreated {
                        pending_id: "pending-1".to_string(),
                        created_at_secs: 1,
                        deadline_at_secs: 99_999_999_999,
                        protocol: core_types::TransportProtocol::Tcp,
                    }
                } else if line.contains("\"AwaitPendingDecision\"") {
                    await_count += 1;
                    if await_count < 5 {
                        ControlResponse::PendingStillWaiting {
                            pending_id: "pending-1".to_string(),
                        }
                    } else {
                        ControlResponse::PendingResolved {
                            action: RuleAction::Allow,
                            route_target: None,
                        }
                    }
                } else {
                    ControlResponse::Error("unexpected request".to_string())
                };
                let payload = serde_json::to_string(&response).expect("serialize response");
                stream
                    .write_all(format!("{payload}\n").as_bytes())
                    .expect("write response");
                if matches!(response, ControlResponse::PendingResolved { .. }) {
                    break;
                }
            }
        }
    });

    let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_thread = thread::spawn(move || {
        let (mut conn, _) = upstream_listener.accept().expect("accept upstream");
        let mut req_buf = [0u8; 512];
        let _ = conn.read(&mut req_buf).expect("read upstream request");
        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .expect("write upstream response");
    });

    let emulator_listener = TcpListener::bind("127.0.0.1:0").expect("bind emulator");
    let emulator_addr = emulator_listener.local_addr().expect("emulator addr");
    let emulator_socket_path = socket_path.clone();
    let emulator_thread = thread::spawn(move || {
        let (stream, _) = emulator_listener.accept().expect("accept emulator");
        handle_client(stream, &emulator_socket_path).expect("handle client");
    });

    let mut client = TcpStream::connect(emulator_addr).expect("connect emulator");
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set short read timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).expect("read auth reply");
    assert_eq!(auth_reply, [0x05, 0x00]);

    let host = "127.0.0.1".as_bytes();
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    connect_req.extend_from_slice(host);
    connect_req.extend_from_slice(&upstream_addr.port().to_be_bytes());
    client
        .write_all(&connect_req)
        .expect("write connect request");

    let mut connect_reply = [0u8; 10];
    let pending_err = client
        .read_exact(&mut connect_reply)
        .expect_err("connect reply should not be immediate while pending");
    assert!(
        matches!(
            pending_err.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ),
        "unexpected error kind while waiting pending: {pending_err:?}"
    );

    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set long read timeout");
    client
        .read_exact(&mut connect_reply)
        .expect("read eventual connect reply");
    assert_eq!(connect_reply[0], 0x05);
    assert_eq!(connect_reply[1], 0x00);

    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .expect("write proxied request");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown client write");
    let mut resp_buf = [0u8; 128];
    let n = client.read(&mut resp_buf).expect("read proxied response");
    let text = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(text.contains("200 OK"));
    assert!(text.contains("\r\n\r\nOK"));

    emulator_thread.join().expect("join emulator");
    upstream_thread.join().expect("join upstream");
    daemon_thread.join().expect("join daemon");
}
