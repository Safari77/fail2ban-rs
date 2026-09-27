use super::*;

use tokio_util::sync::CancellationToken;

#[test]
fn test_backoff_doubles_and_caps() {
    let mut b = Backoff::new();
    let delays: Vec<u64> = (0..7).map(|_| b.next_delay().as_secs()).collect();
    assert_eq!(delays, vec![1, 2, 4, 8, 16, 30, 30]);
}

#[test]
fn test_backoff_first_failure_then_quiet() {
    let mut b = Backoff::new();
    b.next_delay();
    assert!(b.is_first_failure());
    b.next_delay();
    assert!(!b.is_first_failure());
}

#[test]
fn test_backoff_reset_restarts_sequence() {
    let mut b = Backoff::new();
    b.next_delay();
    b.next_delay();
    b.reset();
    assert_eq!(b.next_delay(), INITIAL_DELAY);
    assert!(b.is_first_failure());
}

#[test]
fn test_blocking_sleep_elapses_when_not_cancelled() {
    let cancel = CancellationToken::new();
    assert!(blocking_sleep(Duration::from_millis(60), &cancel));
}

#[test]
fn test_blocking_sleep_returns_early_on_cancel() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let start = std::time::Instant::now();
    assert!(!blocking_sleep(Duration::from_secs(30), &cancel));
    assert!(start.elapsed() < Duration::from_secs(1));
}
