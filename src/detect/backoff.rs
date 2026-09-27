//! Capped exponential backoff shared by the file and journal watchers.
//!
//! Used when a log source is unavailable (file missing, `journalctl` exited)
//! so the watcher keeps retrying without spinning or spamming the log.

use std::time::Duration;

/// First retry delay.
pub(crate) const INITIAL_DELAY: Duration = Duration::from_secs(1);
/// Upper bound on the retry delay.
pub(crate) const MAX_DELAY: Duration = Duration::from_secs(30);

/// Capped exponential backoff (1s, 2s, 4s, ... 30s).
#[derive(Debug)]
pub(crate) struct Backoff {
    next: Duration,
    failures: u32,
}

impl Backoff {
    /// A fresh backoff starting at [`INITIAL_DELAY`].
    pub(crate) fn new() -> Self {
        Self {
            next: INITIAL_DELAY,
            failures: 0,
        }
    }

    /// Record a failure and return how long to wait before retrying.
    pub(crate) fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(MAX_DELAY);
        self.failures = self.failures.saturating_add(1);
        delay
    }

    /// Whether the most recent failure is the first since the last reset.
    ///
    /// Callers log the first failure at `warn!` and later ones at `debug!`
    /// so a persistently missing source doesn't flood the log.
    pub(crate) fn is_first_failure(&self) -> bool {
        self.failures <= 1
    }

    /// Reset after a success so the next failure starts from the minimum.
    pub(crate) fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Sleep for `delay` on a blocking thread, waking early on cancellation.
///
/// Polls `is_cancelled` every 50ms so a cancelled watcher exits promptly.
/// Returns `false` if cancelled before the delay elapsed.
pub(crate) fn blocking_sleep(
    delay: Duration,
    cancel: &tokio_util::sync::CancellationToken,
) -> bool {
    const TICK: Duration = Duration::from_millis(50);
    let deadline = std::time::Instant::now() + delay;
    loop {
        if cancel.is_cancelled() {
            return false;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return true;
        }
        std::thread::sleep(TICK.min(deadline - now));
    }
}

#[cfg(test)]
#[path = "backoff_test.rs"]
mod backoff_test;
