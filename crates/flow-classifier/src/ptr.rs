//! Reverse-DNS names for destinations, as a *display hint* only.
//!
//! A name learned from a PTR record says what the network says about an
//! address. It is not proof of anything: the owner of the reverse zone can
//! claim any name, and a rule that matched on it could be steered by whoever
//! controls that zone. So this never reaches policy matching — it is stored
//! next to the flow so the dialog can show `lb-140-82-121-4-fra.github.com`
//! instead of a bare address, and nothing else.
//!
//! Lookups run on a worker thread with a cache: the packet path only reads the
//! cache, so a slow or unresponsive resolver cannot delay a decision.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A missing record is retried after this long: reverse zones do change, but
/// not often.
const MISSING_TTL: Duration = Duration::from_secs(10 * 60);
/// A found name is kept this long.
const NAME_TTL: Duration = Duration::from_secs(60 * 60);
/// While a lookup is in flight, do not queue the same address again.
const PENDING_TTL: Duration = Duration::from_secs(5);

enum Entry {
    Pending(Instant),
    Name { name: String, at: Instant },
    Missing(Instant),
}

/// Cache of reverse-DNS names, filled by a background worker.
pub struct PtrCache {
    entries: Mutex<HashMap<IpAddr, Entry>>,
    queue: Sender<IpAddr>,
}

impl PtrCache {
    /// Start the worker thread. One lookup at a time is enough: a new address
    /// appears at most a few times per second, and nothing waits on the answer.
    pub fn spawn() -> Arc<Self> {
        let (tx, rx) = mpsc::channel::<IpAddr>();
        let cache = Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            queue: tx,
        });

        let worker = Arc::clone(&cache);
        std::thread::Builder::new()
            .name("netkeep-ptr".into())
            .spawn(move || {
                while let Ok(ip) = rx.recv() {
                    let name = resolve_ptr(ip);
                    if let Ok(mut entries) = worker.entries.lock() {
                        entries.insert(
                            ip,
                            match name {
                                Some(name) => Entry::Name {
                                    name,
                                    at: Instant::now(),
                                },
                                None => Entry::Missing(Instant::now()),
                            },
                        );
                    }
                }
            })
            .ok();

        cache
    }

    /// The cached name for `ip`, queueing a lookup if the answer is stale.
    ///
    /// Returns immediately in every case.
    pub fn lookup(&self, ip: &str) -> Option<String> {
        let Ok(addr) = ip.parse::<IpAddr>() else {
            return None;
        };
        // Loopback reverse zones are noise.
        if addr.is_loopback() || addr.is_unspecified() {
            return None;
        }

        let mut entries = self.entries.lock().ok()?;
        let now = Instant::now();
        match entries.get(&addr) {
            Some(Entry::Name { name, at }) if now.duration_since(*at) < NAME_TTL => {
                return Some(name.clone())
            }
            Some(Entry::Pending(at)) if now.duration_since(*at) < PENDING_TTL => return None,
            Some(Entry::Missing(at)) if now.duration_since(*at) < MISSING_TTL => return None,
            _ => {}
        }

        entries.insert(addr, Entry::Pending(now));
        drop(entries);
        let _ = self.queue.send(addr);
        None
    }
}

/// Ask the system resolver for the PTR name.
///
/// `getent hosts <ip>` performs the reverse lookup through NSS, so it honours
/// `/etc/nsswitch.conf` and any local resolver. It is wrapped in `timeout` so a
/// resolver that never answers cannot wedge the worker.
fn resolve_ptr(ip: IpAddr) -> Option<String> {
    let output = std::process::Command::new("timeout")
        .args(["3", "getent", "hosts", &ip.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let name = text.split_whitespace().nth(1)?.trim_end_matches('.');
    if name.is_empty() || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_not_reverse_resolved() {
        let cache = PtrCache {
            entries: Mutex::new(HashMap::new()),
            queue: mpsc::channel().0,
        };
        assert_eq!(cache.lookup("127.0.0.1"), None);
    }

    /// A cached name is served without touching the resolver, and an
    /// unanswerable address is not queued twice within the pending window.
    #[test]
    fn lookup_reads_the_cache_and_queues_once() {
        let (tx, rx) = mpsc::channel();
        let cache = PtrCache {
            entries: Mutex::new(HashMap::new()),
            queue: tx,
        };

        assert_eq!(cache.lookup("140.82.121.4"), None);
        assert_eq!(cache.lookup("140.82.121.4"), None, "second call is pending");
        assert_eq!(rx.try_recv().ok(), Some("140.82.121.4".parse().unwrap()));
        assert!(rx.try_recv().is_err(), "queued exactly once");

        cache.entries.lock().unwrap().insert(
            "140.82.121.4".parse().unwrap(),
            Entry::Name {
                name: "lb-140-82-121-4-fra.github.com".into(),
                at: Instant::now(),
            },
        );
        assert_eq!(
            cache.lookup("140.82.121.4").as_deref(),
            Some("lb-140-82-121-4-fra.github.com")
        );
    }
}
