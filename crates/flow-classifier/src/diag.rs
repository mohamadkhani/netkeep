//! Diagnostics instrumentation for the process-attribution path.
//!
//! Set `NETKEEP_DIAG=1` in the daemon's environment to print one structured
//! line per classification stage to stderr (visible via `journalctl -u
//! netkeepd`). The lines are designed so an incorrectly attributed packet
//! can be traced to the FIRST stage that produced a wrong value:
//!
//! ```text
//! diag: pkt  tcp 10.0.0.1:54321 -> 1.1.1.1:443
//! diag: ebpf tcp 10.0.0.1:54321 miss
//! diag: rslv tcp 10.0.0.1:54321 cache=miss
//! diag: diag tcp 10.0.0.1:54321 inode=99001 uid=1000
//! diag: fdpid tcp 10.0.0.1:54321 pid=4242
//! diag: name pid=4242 exe=/usr/bin/curl name=curl
//! diag: layer0 1.1.1.1:443 restored name=curl cache=ip
//! ```

use std::sync::OnceLock;

/// Whether diagnostics are enabled (`NETKEEP_DIAG=1`, checked once).
pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("NETKEEP_DIAG").ok().as_deref() == Some("1"))
}

/// Emit a diagnostics line when `NETKEEP_DIAG=1`.
#[macro_export]
macro_rules! diag {
    ($($arg:tt)*) => {
        if $crate::diag::enabled() {
            eprintln!("diag: {}", format_args!($($arg)*));
        }
    };
}
