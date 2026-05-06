# Unix Domain Sockets in Rust

Unix domain sockets provide fast local inter-process communication (IPC) on Unix-like systems.

## Basic Client (UnixStream)

### Connect and Send/Receive

```rust
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::os::unix::net::UnixStream;

fn send_request(path: &str, req: &ControlRequest) -> Result<ControlResponse, String> {
    // Connect to socket
    let mut stream = UnixStream::connect(path)
        .map_err(|e| format!("connect failed: {e}"))?;
    
    // Serialize request to JSON
    let payload = serde_json::to_string(req)
        .map_err(|e| e.to_string())?;
    
    // Send request (with newline delimiter for line-based protocol)
    stream
        .write_all(format!("{payload}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    
    // Create buffered reader
    let mut reader = BufReader::new(stream);
    
    // Read response line
    let mut line = String::new();
    reader.read_line(&mut line)
        .map_err(|e| e.to_string())?;
    
    if line.trim().is_empty() {
        return Err("empty response from daemon".into());
    }
    
    // Deserialize response from JSON
    serde_json::from_str(line.trim_end())
        .map_err(|e| e.to_string())
}
```

Key steps:
1. `UnixStream::connect(path)` — connect to socket at path (e.g., `/tmp/logiguard.sock`)
2. Serialize request to JSON string
3. `write_all()` — send full message (include newline for line-based protocol)
4. `BufReader::new(stream)` — wrap stream for line-based reading
5. `read_line()` — read until newline
6. Deserialize JSON response

### Error Handling

All I/O operations return `Result`. Use:
- `map_err()` to convert to your error type
- `?` operator to propagate errors
- Pattern matching for recovery

## Line-Based Protocol

For simplicity, use newline-delimited JSON (JSONL):

**Client sends:**
```
{"variant":"AddRule","contents":{...}}\n
```

**Daemon responds:**
```
{"variant":"Ok"}\n
```

Benefits:
- Delimiters prevent partial message handling
- Easy to debug (inspect with `cat`/`nc`)
- Works with `BufReader::read_line()`

## Basic Server (UnixListener)

```rust
use std::os::unix::net::UnixListener;

fn bind_socket(path: &str) -> Result<UnixListener, Box<dyn std::error::Error>> {
    // Remove old socket if it exists
    let _ = std::fs::remove_file(path);
    
    let listener = UnixListener::bind(path)?;
    Ok(listener)
}

fn accept_and_handle(listener: UnixListener) -> Result<(), Box<dyn std::error::Error>> {
    for stream_result in listener.incoming() {
        let stream = stream_result?;
        
        // Handle client (blocking operation)
        handle_client(stream)?;
    }
    Ok(())
}

fn handle_client(stream: UnixStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(&stream);
    let mut writer = stream;
    
    let mut line = String::new();
    reader.read_line(&mut line)?;
    
    // Parse request
    let req: ControlRequest = serde_json::from_str(line.trim_end())?;
    
    // Process request
    let resp = process_request(req)?;
    
    // Send response
    let payload = serde_json::to_string(&resp)?;
    writer.write_all(format!("{payload}\n").as_bytes())?;
    
    Ok(())
}
```

Key points:
- `UnixListener::bind(path)` — bind to socket path
- Remove old socket file with `std::fs::remove_file()` before binding (avoids "address in use" errors)
- `.incoming()` — returns iterator over accepted connections
- Each connection must be handled (typically in a thread or async task)

## Async Server (Tokio)

For real applications, use async I/O:

```rust
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{BufReader, AsyncBufReadExt, AsyncWriteExt};

async fn accept_and_handle(listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(async move {
                    let _ = handle_client(stream).await;
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}

async fn handle_client(stream: UnixStream) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    
    let req: ControlRequest = serde_json::from_str(line.trim_end())?;
    let resp = process_request(req)?;
    
    let payload = serde_json::to_string(&resp)?;
    writer.write_all(format!("{payload}\n").as_bytes()).await?;
    
    Ok(())
}
```

Benefits:
- Non-blocking: handle many clients concurrently
- Use `.into_split()` to separate reader and writer if needed
- `tokio::spawn()` handles each client in a task

## Permissions and Security

### File Permissions

Socket file inherits umask permissions:

```rust
// Create socket with mode 0o660 (rw-rw----)
// Useful for daemon-user communication
std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
```

### Peer Credential Checks

```rust
use std::os::unix::net::UnixStream;
use rustix::net::{getsockopt, sockopt};

fn get_peer_uid(stream: &UnixStream) -> Result<u32, Box<dyn std::error::Error>> {
    let fd = stream.as_raw_fd();
    
    // Get peer credentials via SO_PEERCRED
    let cred = rustix::net::getsockopt(fd, rustix::net::sockopt::SO_PEERCRED)?;
    
    Ok(cred.uid)
}
```

Alternatively, use `libc` crate:

```rust
use libc::{getsockopt, ucred, SO_PEERCRED, SOL_SOCKET};

fn get_peer_cred(stream: &UnixStream) -> Result<libc::ucred, std::io::Error> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut cred_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    
    unsafe {
        if getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut cred_len,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    
    Ok(cred)
}
```

### Console Access Check

For daemon recovery commands (e.g., physical-console-only unlock):

```rust
use std::os::unix::io::AsRawFd;
use rustix::fs::major;

fn is_console(fd: i32) -> bool {
    // Check if fd 0 (stdin) is a console device (major 5, minor 0-3)
    match rustix::fs::fstat(fd) {
        Ok(stat) => {
            let dev_major = major(stat.st_rdev);
            dev_major == 5  // TTY device major number
        }
        Err(_) => false,
    }
}

fn check_console_access(stream: &UnixStream) -> Result<(), String> {
    let cred = get_peer_cred(stream)?;
    
    // Get client's fd 0 (stdin) by reading /proc/<pid>/fd/0
    let proc_fd_path = format!("/proc/{}/fd/0", cred.pid);
    let link = std::fs::read_link(&proc_fd_path)
        .map_err(|e| format!("cannot read {}: {e}", proc_fd_path))?;
    
    if link.to_string_lossy().starts_with("/dev/tty") || link.to_string_lossy() == "/dev/console" {
        Ok(())
    } else {
        Err("not running from console".into())
    }
}
```

## Common Patterns

### Duplex Communication

One stream for request/response:

```rust
// Client sends request, receives response on same connection
stream.write_all(request.as_bytes())?;
let mut response = String::new();
reader.read_line(&mut response)?;
```

Or use separate connections:
- Client: send on connection 1, receive on connection 2
- More complex but allows true concurrency

### Timeout Handling

For clients (with std library):

```rust
stream.set_read_timeout(Some(Duration::from_secs(5)))?;
stream.set_write_timeout(Some(Duration::from_secs(5)))?;
```

For async (Tokio):

```rust
tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await?
```

### Graceful Shutdown

```rust
// Shutdown write side (signals EOF to reader)
stream.shutdown(std::net::Shutdown::Write)?;

// Shutdown both sides
stream.shutdown(std::net::Shutdown::Both)?;
```

## Dependencies

```toml
[dependencies]
serde_json = "1"
serde = { version = "1", features = ["derive"] }

# For async
tokio = { version = "1", features = ["net", "io-util"] }

# For credential checking
libc = "0.2"
# Or use rustix for safer APIs
rustix = { version = "0.37", features = ["net", "fs"] }
```

## Debugging

### Test with netcat

```bash
# Terminal 1: Start daemon listening on socket
# (daemon binds to /tmp/logiguard.sock)

# Terminal 2: Send request
echo '{"variant":"Health"}' | nc -U /tmp/logiguard.sock
```

### Inspect Socket

```bash
ls -la /tmp/logiguard.sock
stat /tmp/logiguard.sock  # See permissions, inode
```

### Monitor with strace

```bash
strace -e openat,connect,read,write -f ./daemon
```

## Platform Notes

- **Linux**: Fully supported (SOCK_STREAM, credentials, console detection)
- **macOS**: Supported (SOCK_STREAM, some credential APIs differ)
- **BSD**: Supported (SOCK_STREAM, credential APIs differ)

Use feature-gated code for platform-specific behavior (e.g., console detection):

```rust
#[cfg(target_os = "linux")]
fn is_console(fd: i32) -> bool { /* ... */ }

#[cfg(not(target_os = "linux"))]
fn is_console(fd: i32) -> bool { false }
```
