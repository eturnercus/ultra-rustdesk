//! Ultra RustDesk: a live connection journal. Every step of a direct connection (which address,
//! which transport, how long it took, why it failed) and of the listening side (ports, UPnP,
//! incoming attempts) is recorded here, so the user can see where a connection gets stuck.
//! The UI shows it in the "Connection log" window.

use std::{collections::VecDeque, sync::Mutex, time::Instant};

const MAX_LINES: usize = 400;

static LINES: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Records one step. `area` is a short tag such as "QUIC", "TCP", "CODE", "LAN", "LISTEN".
pub fn note(area: &str, msg: impl AsRef<str>) {
    let msg = msg.as_ref();
    hbb_common::log::info!("[ultra {}] {}", area, msg);
    let line = format!(
        "{} {:<6} {}",
        hbb_common::chrono::Local::now().format("%H:%M:%S%.3f"),
        area,
        msg
    );
    let mut lines = LINES.lock().unwrap_or_else(|e| e.into_inner());
    if lines.len() >= MAX_LINES {
        lines.pop_front();
    }
    lines.push_back(line);
}

/// Milliseconds since `t`, for "took N ms" in notes.
pub fn ms(t: Instant) -> u128 {
    t.elapsed().as_millis()
}

/// The journal of this process, oldest line first.
pub fn dump() -> String {
    let lines = LINES.lock().unwrap_or_else(|e| e.into_inner());
    lines.iter().cloned().collect::<Vec<_>>().join("\n")
}

pub fn clear() {
    LINES.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// What the UI shows: this device's listening side (from the service process on desktop) and
/// this process's outgoing connections.
pub fn full_journal() -> String {
    let mut out = String::new();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let service = crate::ipc::get_config("ultra_diag")
            .ok()
            .flatten()
            .unwrap_or_default();
        out.push_str("=== This device (service: listening, UPnP, incoming) ===\n");
        if service.is_empty() {
            out.push_str("(the service is not running or has nothing to report yet)\n");
        } else {
            out.push_str(&service);
            out.push('\n');
        }
        out.push_str("\n=== Outgoing connections (this window) ===\n");
    }
    let own = dump();
    if own.is_empty() {
        out.push_str("(no connection attempts yet)");
    } else {
        out.push_str(&own);
    }
    out
}

/// Clears the journal here and, on desktop, in the service.
pub fn clear_all() {
    clear();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _ = crate::ipc::set_config("ultra_diag_clear", "".to_owned());
    }
}
