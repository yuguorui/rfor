//! Session statistics and periodic logging module.
//!
//! This module provides global statistics tracking for TCP and UDP sessions,
//! including active/total session counts and bytes transferred.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use once_cell::sync::Lazy;
use tracing::info;

/// Global statistics for sessions (TCP or UDP)
pub struct SessionStats {
    /// Number of currently active sessions
    pub active_sessions: AtomicUsize,
    /// Total number of sessions since startup
    pub total_sessions: AtomicU64,
    /// Total bytes transferred (upload + download)
    pub total_bytes: AtomicU64,
}

impl SessionStats {
    /// Create a new SessionStats instance with all counters at zero
    pub const fn new() -> Self {
        Self {
            active_sessions: AtomicUsize::new(0),
            total_sessions: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
        }
    }

    /// Record a new session starting
    pub fn session_start(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
        self.total_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a session ending with the number of bytes transferred
    pub fn session_end(&self, bytes: u64) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add bytes to the transfer counter (for ongoing sessions)
    pub fn add_bytes(&self, bytes: u64) {
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get current active session count
    pub fn get_active(&self) -> usize {
        self.active_sessions.load(Ordering::Relaxed)
    }

    /// Get total session count
    pub fn get_total(&self) -> u64 {
        self.total_sessions.load(Ordering::Relaxed)
    }

    /// Get total bytes transferred
    pub fn get_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }
}

/// Global TCP session statistics instance
pub static TCP_STATS: Lazy<SessionStats> = Lazy::new(SessionStats::new);

/// Global UDP session statistics instance
pub static UDP_STATS: Lazy<SessionStats> = Lazy::new(SessionStats::new);

/// Format bytes into human-readable string (KB, MB, GB, etc.)
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Default interval for periodic stats logging (60 seconds)
const STATS_LOG_INTERVAL_SECS: u64 = 60;

/// Start the periodic stats logging task.
/// This function spawns a background task that logs TCP and UDP session statistics
/// at regular intervals.
pub async fn stats_logger_worker() -> anyhow::Result<()> {
    let interval = Duration::from_secs(STATS_LOG_INTERVAL_SECS);

    loop {
        tokio::time::sleep(interval).await;

        let tcp_active = TCP_STATS.get_active();
        let tcp_total = TCP_STATS.get_total();
        let tcp_bytes = TCP_STATS.get_bytes();

        let udp_active = UDP_STATS.get_active();
        let udp_total = UDP_STATS.get_total();
        let udp_bytes = UDP_STATS.get_bytes();

        info!(
            "Session stats: TCP(active={}, total={}, transferred={}), UDP(active={}, total={}, transferred={})",
            tcp_active,
            tcp_total,
            format_bytes(tcp_bytes),
            udp_active,
            udp_total,
            format_bytes(udp_bytes)
        );
    }
}
