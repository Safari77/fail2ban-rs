//! `journalctl` child-process bookkeeping for the journal watcher.
//!
//! Captures a bounded prefix of the child's stderr and its exit status so the
//! supervisor ([`supervise`](crate::detect::journal::supervise)) can tell a
//! cursor `journalctl` rejected (drop it, or every restart fails) apart from
//! a quiet session that merely ended (keep it, or entries are lost).

use std::process::ExitStatus;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr};
use tokio::task::JoinHandle;
use tracing::debug;

/// Most stderr bytes kept per session (the rest is read and discarded so the
/// child never blocks on a full pipe).
pub(crate) const STDERR_CAP: usize = 4096;

/// A session that exits non-zero this soon without producing an entry is
/// treated as `journalctl` rejecting its arguments (typically the cursor).
pub(crate) const FAST_FAIL_WINDOW: Duration = Duration::from_secs(2);

/// How long to wait for an ended child's exit status and stderr.
const EXIT_WAIT: Duration = Duration::from_millis(500);

/// Background reader of a child's stderr.
pub(crate) struct StderrCapture(Option<JoinHandle<String>>);

impl StderrCapture {
    /// Start draining `child`'s stderr (if piped) on a background task.
    pub(crate) fn spawn(child: &mut Child) -> Self {
        Self(child.stderr.take().map(|s| tokio::spawn(read_bounded(s))))
    }

    /// The captured stderr text; empty if unavailable within [`EXIT_WAIT`].
    pub(crate) async fn collect(self) -> String {
        let Some(handle) = self.0 else {
            return String::new();
        };
        let abort = handle.abort_handle();
        match tokio::time::timeout(EXIT_WAIT, handle).await {
            Ok(Ok(text)) => text,
            Ok(Err(e)) => {
                debug!(error = %e, "journalctl stderr reader failed");
                String::new()
            }
            Err(_) => {
                abort.abort();
                String::new()
            }
        }
    }
}

/// Read all of `stderr`, keeping at most [`STDERR_CAP`] bytes.
async fn read_bounded(mut stderr: ChildStderr) -> String {
    let mut kept = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    loop {
        let n = match stderr.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                debug!(error = %e, "journalctl stderr read failed");
                break;
            }
        };
        let room = STDERR_CAP.saturating_sub(kept.len());
        kept.extend_from_slice(chunk.get(..n.min(room)).unwrap_or_default());
    }
    String::from_utf8_lossy(&kept).into_owned()
}

/// Wait briefly for an ended child's exit status; kill it if still running.
pub(crate) async fn reap(jail_id: &str, child: &mut Child) -> Option<ExitStatus> {
    match tokio::time::timeout(EXIT_WAIT, child.wait()).await {
        Ok(Ok(status)) => Some(status),
        Ok(Err(e)) => {
            debug!(jail = %jail_id, error = %e, "journalctl wait failed");
            None
        }
        Err(_) => {
            if let Err(e) = child.kill().await {
                debug!(jail = %jail_id, error = %e, "journalctl kill failed");
            }
            None
        }
    }
}

/// Whether an entry-less session shows `journalctl` rejected its cursor:
/// stderr mentions the cursor, or it failed within [`FAST_FAIL_WINDOW`].
#[must_use]
pub(crate) fn cursor_rejected(elapsed: Duration, status: Option<ExitStatus>, stderr: &str) -> bool {
    if stderr.to_ascii_lowercase().contains("cursor") {
        return true;
    }
    status.is_some_and(|s| !s.success()) && elapsed < FAST_FAIL_WINDOW
}

#[cfg(test)]
#[path = "journal_proc_test.rs"]
mod journal_proc_test;
