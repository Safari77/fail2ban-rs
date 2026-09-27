use super::*;

use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// L3: a SIGHUP delivered while nobody is polling (e.g. mid-reload) is
/// buffered by the long-lived listener and observed on the next poll.
#[cfg(unix)]
#[tokio::test]
async fn test_signals_hangup_delivered_while_not_polling_is_buffered() {
    let mut signals = Signals::register();
    kill(Pid::this(), Signal::SIGHUP).expect("send SIGHUP to self");
    // Simulate inline work (a reload) running before the loop polls again.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let sig = tokio::time::timeout(Duration::from_secs(5), signals.next())
        .await
        .expect("buffered SIGHUP must be observed");
    assert_eq!(
        sig,
        DaemonSignal::Reload,
        "SIGHUP is a reload, not a shutdown"
    );
}

/// A missing listener (registration failed) never resolves.
#[cfg(unix)]
#[tokio::test]
async fn test_recv_missing_listener_stays_pending() {
    let pending = tokio::time::timeout(Duration::from_millis(50), recv(None)).await;
    assert!(pending.is_err());
}
