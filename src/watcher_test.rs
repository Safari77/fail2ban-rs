//! Tests for the watcher module.

use std::io::Write;

use tempfile::NamedTempFile;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::date::{DateFormat, DateParser};
use crate::ignore::IgnoreList;
use crate::matcher::JailMatcher;
use crate::watcher;

const SSHD_FAILURE_LINE: &str =
    "Jan 15 10:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22";
const SSHD_FAILURE_LINE2: &str =
    "Jan 15 10:31:00 server sshd[5678]: Failed password for admin from 10.0.0.42 port 22";

/// Spawn a watcher and return the cancel token, join handle, and receiver.
fn spawn_watcher(
    path: std::path::PathBuf,
) -> (
    CancellationToken,
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::Receiver<crate::watcher::Failure>,
) {
    let (tx, rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        watcher::run(
            "test".to_string(),
            path,
            JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&[], false).unwrap(),
            tx,
            cancel_clone,
        )
        .await;
    });
    (cancel, handle, rx)
}

fn test_matcher() -> JailMatcher {
    JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap()
}

#[tokio::test]
async fn detects_failure_in_appended_lines() {
    let mut tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let path_clone = path.clone();
    let handle = tokio::spawn(async move {
        watcher::run(
            "test".to_string(),
            path_clone,
            test_matcher(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&[], false).unwrap(),
            tx,
            cancel_clone,
        )
        .await;
    });

    // Give watcher time to start and seek to end.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Append a matching line.
    writeln!(
        tmpfile,
        "Jan 15 10:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"
    )
    .unwrap();
    tmpfile.flush().unwrap();

    // Wait for watcher to pick it up.
    let failure = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout waiting for failure")
        .expect("channel closed");

    assert_eq!(failure.ip.to_string(), "192.168.1.100");
    assert_eq!(failure.jail_id, "test");

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn ignores_non_matching_lines() {
    let mut tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let path_clone = path.clone();
    let handle = tokio::spawn(async move {
        watcher::run(
            "test".to_string(),
            path_clone,
            test_matcher(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&[], false).unwrap(),
            tx,
            cancel_clone,
        )
        .await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Append a non-matching line.
    writeln!(
        tmpfile,
        "Jan 15 10:30:00 server sshd[1234]: Accepted password for user from 10.0.0.1 port 22"
    )
    .unwrap();
    tmpfile.flush().unwrap();

    // Should not receive anything.
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
    assert!(result.is_err(), "should not have received a failure");

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn ignores_allowlisted_ips() {
    let mut tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let path_clone = path.clone();
    let handle = tokio::spawn(async move {
        watcher::run(
            "test".to_string(),
            path_clone,
            test_matcher(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&["192.168.1.0/24".to_string()], false).unwrap(),
            tx,
            cancel_clone,
        )
        .await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    writeln!(
        tmpfile,
        "Jan 15 10:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"
    )
    .unwrap();
    tmpfile.flush().unwrap();

    let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
    assert!(result.is_err(), "ignored IP should not produce a failure");

    cancel.cancel();
    handle.await.unwrap();
}

// --- UTF-8 robustness tests ---
//
// The watcher poll interval is 250ms. Each invalid UTF-8 line currently causes
// read_line() to return Err(InvalidData), which breaks the inner read loop for
// that polling cycle. The file cursor does advance past the invalid bytes (the
// BufReader internal buffer consumed them), but the valid line that follows
// is only reached on the NEXT poll — 250ms later.
//
// The fix replaces read_line() with byte-based reading + from_utf8_lossy(),
// which processes invalid lines in the same poll cycle with no error/sleep.
//
// Strategy: place N consecutive invalid lines before a valid matching line.
// Use a timeout of (N * poll_interval - margin). Current code sleeps N times
// → timeout fires. Fixed code handles all lines in one cycle → timeout passes.
//
// poll_interval = 250ms. With 3 invalid lines, the unfixed code needs 750ms
// minimum; we timeout at 600ms → test fails. After fix, <250ms → test passes.

/// The number of consecutive invalid UTF-8 lines placed before the valid line
/// in timing-sensitive tests. Three errors force at minimum 3×250ms = 750ms
/// of sleep under the unfixed code, reliably exceeding the 600ms test timeout.
const INVALID_LINES_BEFORE_VALID: usize = 3;

/// Timeout used by tests that must fail against unfixed code. Set below the
/// minimum time the unfixed code needs (3 × 250ms = 750ms) but above one poll
/// cycle (250ms) so the fixed code easily passes.
const TIGHT_TIMEOUT_MS: u64 = 600;

/// Regression guard: a normal ASCII sshd line is read and emits a failure.
/// Expected: PASS both before and after the fix.
#[tokio::test]
async fn test_read_line_bounded_valid_utf8() {
    let mut tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (cancel, handle, mut rx) = spawn_watcher(path);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    writeln!(tmpfile, "{SSHD_FAILURE_LINE}").unwrap();
    tmpfile.flush().unwrap();

    let failure = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout — valid UTF-8 line produced no failure event")
        .expect("channel closed unexpectedly");

    assert_eq!(failure.ip.to_string(), "192.168.1.100");

    cancel.cancel();
    handle.await.unwrap();
}

/// A line containing embedded invalid UTF-8 bytes must NOT cause a sleep
/// before the next line is processed. The valid line that follows must arrive
/// within TIGHT_TIMEOUT_MS, which is less than 3×poll_interval (the time the
/// unfixed code needs to work through 3 consecutive invalid lines).
/// Expected: FAIL before fix (each error causes +250ms sleep), PASS after.
#[tokio::test]
async fn test_read_line_bounded_invalid_utf8_continues() {
    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (cancel, handle, mut rx) = spawn_watcher(path.clone());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // INVALID_LINES_BEFORE_VALID invalid lines, then one valid matching line.
    let mut content: Vec<u8> = Vec::new();
    for _ in 0..INVALID_LINES_BEFORE_VALID {
        content.extend_from_slice(b"invalid \xff\xfe bytes in this line\n");
    }
    content.extend_from_slice(SSHD_FAILURE_LINE.as_bytes());
    content.push(b'\n');
    std::fs::write(&path, &content).unwrap();

    // Under the unfixed code each invalid line breaks the inner loop and waits
    // 250ms, so 3 invalid lines require ≥750ms. The 600ms timeout fires first.
    // Under the fixed code all lines are processed in one cycle (<250ms).
    let failure = tokio::time::timeout(
        std::time::Duration::from_millis(TIGHT_TIMEOUT_MS),
        rx.recv(),
    )
    .await
    .expect("timeout — watcher incurred sleep penalty per invalid UTF-8 line instead of continuing within same poll cycle")
    .expect("channel closed unexpectedly");

    assert_eq!(failure.ip.to_string(), "192.168.1.100");

    cancel.cancel();
    handle.await.unwrap();
}

/// A file with: valid line 1, then INVALID_LINES_BEFORE_VALID invalid lines,
/// then valid line 2. Both valid lines must produce failures within a single
/// poll cycle (TIGHT_TIMEOUT_MS from when the content is written).
/// Expected: FAIL before fix, PASS after.
#[tokio::test]
async fn test_read_line_bounded_mixed_valid_invalid_lines() {
    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (cancel, handle, mut rx) = spawn_watcher(path.clone());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut content: Vec<u8> = Vec::new();
    content.extend_from_slice(SSHD_FAILURE_LINE.as_bytes());
    content.push(b'\n');
    for _ in 0..INVALID_LINES_BEFORE_VALID {
        content.extend_from_slice(b"garbage \xc3\x28 invalid sequence here\n");
    }
    content.extend_from_slice(SSHD_FAILURE_LINE2.as_bytes());
    content.push(b'\n');
    std::fs::write(&path, &content).unwrap();

    let first = tokio::time::timeout(
        std::time::Duration::from_millis(TIGHT_TIMEOUT_MS),
        rx.recv(),
    )
    .await
    .expect("timeout waiting for first failure — valid line 1 not processed in time")
    .expect("channel closed");
    assert_eq!(
        first.ip.to_string(),
        "192.168.1.100",
        "first failure IP mismatch"
    );

    // The second failure must arrive quickly after the first — no additional
    // sleep cycles. If the unfixed code made it past line 1 it must still
    // sleep per invalid line before reaching line 2.
    let second = tokio::time::timeout(
        std::time::Duration::from_millis(TIGHT_TIMEOUT_MS),
        rx.recv(),
    )
    .await
    .expect("timeout waiting for second failure — watcher slept per invalid UTF-8 line")
    .expect("channel closed");
    assert_eq!(
        second.ip.to_string(),
        "10.0.0.42",
        "second failure IP mismatch"
    );

    cancel.cancel();
    handle.await.unwrap();
}

/// A line consisting entirely of invalid UTF-8 bytes must not cause an error.
/// INVALID_LINES_BEFORE_VALID all-invalid lines precede the valid matching line
/// to amplify the timing signal.
/// Expected: FAIL before fix, PASS after.
#[tokio::test]
async fn test_read_line_bounded_all_invalid_bytes() {
    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (cancel, handle, mut rx) = spawn_watcher(path.clone());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut content: Vec<u8> = Vec::new();
    for _ in 0..INVALID_LINES_BEFORE_VALID {
        // 32 bytes that are entirely 0xff — no valid UTF-8 codepoint at all.
        content.extend(std::iter::repeat(0xff_u8).take(32));
        content.push(b'\n');
    }
    content.extend_from_slice(SSHD_FAILURE_LINE.as_bytes());
    content.push(b'\n');
    std::fs::write(&path, &content).unwrap();

    let failure = tokio::time::timeout(
        std::time::Duration::from_millis(TIGHT_TIMEOUT_MS),
        rx.recv(),
    )
    .await
    .expect("timeout — watcher slept per all-invalid-bytes line instead of processing in-cycle")
    .expect("channel closed");

    assert_eq!(failure.ip.to_string(), "192.168.1.100");

    cancel.cancel();
    handle.await.unwrap();
}

/// An oversized line (>64 KB) containing invalid UTF-8 must be skipped by the
/// existing oversize guard, not cause a read error. The following valid line
/// must be processed.
///
/// The unfixed code calls read_line() which returns Err on the first invalid
/// byte — the oversize check is never reached. The cursor advances past the
/// invalid bytes but breaks the inner loop, requiring an extra poll cycle.
/// Under the fix, the oversize guard path is reached and drain_until_newline
/// skips correctly, continuing in the same cycle.
///
/// Expected: FAIL before fix (error path taken instead of oversize path, extra
/// sleep before valid line), PASS after.
#[tokio::test]
async fn test_read_line_bounded_invalid_utf8_oversized() {
    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (cancel, handle, mut rx) = spawn_watcher(path.clone());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // One oversized + all-invalid line, then INVALID_LINES_BEFORE_VALID - 1
    // more short invalid lines, then the valid line. Total invalid penalty
    // under unfixed code = INVALID_LINES_BEFORE_VALID sleeps → exceeds timeout.
    let oversize_len = crate::watcher::MAX_LINE_LEN + 256;
    let mut content: Vec<u8> = Vec::with_capacity(oversize_len + 512);
    content.extend(std::iter::repeat(0xff_u8).take(oversize_len));
    content.push(b'\n');
    for _ in 0..(INVALID_LINES_BEFORE_VALID - 1) {
        content.extend_from_slice(b"\xff\xfe short invalid\n");
    }
    content.extend_from_slice(SSHD_FAILURE_LINE.as_bytes());
    content.push(b'\n');
    std::fs::write(&path, &content).unwrap();

    let failure = tokio::time::timeout(
        std::time::Duration::from_millis(TIGHT_TIMEOUT_MS),
        rx.recv(),
    )
    .await
    .expect("timeout — watcher did not recover within one poll cycle after oversized invalid-UTF-8 line")
    .expect("channel closed");

    assert_eq!(failure.ip.to_string(), "192.168.1.100");

    cancel.cancel();
    handle.await.unwrap();
}

/// FileIdentity::from_file is called at watcher startup. If the file's first
/// line contains invalid UTF-8, from_file returns None (read_line fails) and
/// the watcher runs with identity = None. After the fix, from_file reads the
/// bytes lossily and produces a valid identity. Either way the watcher must
/// start and process appended lines correctly.
/// Expected: PASS today (regression guard — watcher is resilient to None
/// identity) and after fix (identity is now set from lossy first-line hash).
#[tokio::test]
async fn test_file_identity_invalid_utf8_first_line() {
    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    // Pre-populate with invalid UTF-8 so from_file sees it at startup.
    std::fs::write(&path, b"\xff\xfe this is the first line\n").unwrap();

    let (cancel, handle, mut rx) = spawn_watcher(path.clone());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Append a valid matching line — the watcher is at end so it sees this.
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    writeln!(f, "{SSHD_FAILURE_LINE}").unwrap();
    f.flush().unwrap();

    let failure = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout — watcher did not start correctly when first line has invalid UTF-8")
        .expect("channel closed");

    assert_eq!(failure.ip.to_string(), "192.168.1.100");

    cancel.cancel();
    handle.await.unwrap();
}

/// Integration: valid failure line, N invalid lines, valid failure line again.
/// Both failures must be emitted within TIGHT_TIMEOUT_MS.
/// Expected: FAIL before fix, PASS after.
#[tokio::test]
async fn test_watcher_processes_after_invalid_utf8() {
    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (cancel, handle, mut rx) = spawn_watcher(path.clone());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut content: Vec<u8> = Vec::new();
    content.extend_from_slice(SSHD_FAILURE_LINE.as_bytes());
    content.push(b'\n');
    for _ in 0..INVALID_LINES_BEFORE_VALID {
        content.extend_from_slice(b"corrupted log entry: \xed\xa0\x80\xed\xb0\x80\n");
    }
    content.extend_from_slice(SSHD_FAILURE_LINE2.as_bytes());
    content.push(b'\n');
    std::fs::write(&path, &content).unwrap();

    let first = tokio::time::timeout(
        std::time::Duration::from_millis(TIGHT_TIMEOUT_MS),
        rx.recv(),
    )
    .await
    .expect("timeout waiting for first failure event")
    .expect("channel closed");
    assert_eq!(first.ip.to_string(), "192.168.1.100");

    let second = tokio::time::timeout(
        std::time::Duration::from_millis(TIGHT_TIMEOUT_MS),
        rx.recv(),
    )
    .await
    .expect("timeout — invalid UTF-8 lines caused poll-cycle sleep penalty before second failure")
    .expect("channel closed");
    assert_eq!(second.ip.to_string(), "10.0.0.42");

    cancel.cancel();
    handle.await.unwrap();
}

/// Replacement characters produced by lossy UTF-8 decoding must not trigger
/// any jail pattern. Guards against false-positive bans from garbage bytes.
/// Expected: PASS both before and after fix.
#[tokio::test]
async fn test_invalid_utf8_does_not_match_pattern() {
    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (cancel, handle, mut rx) = spawn_watcher(path.clone());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Pure garbage — after lossy decode becomes a string of U+FFFD.
    // Must not match "Failed password for .* from <HOST>".
    let garbage: Vec<u8> = vec![0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, b'\n'];
    std::fs::write(&path, &garbage).unwrap();

    let result = tokio::time::timeout(std::time::Duration::from_millis(600), rx.recv()).await;
    assert!(
        result.is_err(),
        "replacement characters from invalid UTF-8 must not match any jail pattern"
    );

    cancel.cancel();
    handle.await.unwrap();
}
