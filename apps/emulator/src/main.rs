use std::net::TcpListener;
use std::thread;

use netkeep_emulator::handle_client;

const DEFAULT_SOCKS_ADDR: &str = "127.0.0.1:1080";
const DEFAULT_SOCKET_PATH: &str = "/tmp/netkeep.sock";

fn main() {
    let socks_addr =
        std::env::var("NETKEEP_EMULATOR_ADDR").unwrap_or_else(|_| DEFAULT_SOCKS_ADDR.to_string());
    let socket_path =
        std::env::var("NETKEEP_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    let listener = TcpListener::bind(&socks_addr)
        .unwrap_or_else(|e| panic!("failed to bind SOCKS emulator at {socks_addr}: {e}"));
    println!("socks emulator listening on {socks_addr} -> daemon socket {socket_path}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let socket_path = socket_path.clone();
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream, &socket_path) {
                        eprintln!("emulator client error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("emulator incoming error: {err}"),
        }
    }
}
