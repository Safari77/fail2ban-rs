use super::*;
use std::io::Write;

use tempfile::NamedTempFile;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::detect::date::{DateFormat, DateParser};
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;

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
        run(
            "test".to_string(),
            path_clone,
            test_matcher(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&[], false).unwrap(),
            tx,
            cancel_clone,
            "startup",
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
        run(
            "test".to_string(),
            path_clone,
            test_matcher(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&[], false).unwrap(),
            tx,
            cancel_clone,
            "startup",
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
        run(
            "test".to_string(),
            path_clone,
            test_matcher(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&["192.168.1.0/24".to_string()], false).unwrap(),
            tx,
            cancel_clone,
            "startup",
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

// --- Shutdown, resume, and late-file handling (#19, #20, #25) ---------------

const FAILURE_LINE: &str =
    "Jan 15 10:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22";

/// Spawn `run_from` and return its cancel token, handle, and failure receiver.
fn spawn_from(
    path: std::path::PathBuf,
    resume: Option<ResumePoint>,
    capacity: usize,
) -> (
    CancellationToken,
    tokio::task::JoinHandle<Option<ResumePoint>>,
    mpsc::Receiver<Failure>,
) {
    let (tx, rx) = mpsc::channel(capacity);
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    let handle = tokio::spawn(async move {
        run_from(
            "test".to_string(),
            path,
            test_matcher(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&[], false).unwrap(),
            tx,
            c,
            "reload",
            resume,
        )
        .await
    });
    (cancel, handle, rx)
}

fn append(path: &std::path::Path, text: &str) {
    let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

async fn count_within(rx: &mut mpsc::Receiver<Failure>, ms: u64) -> usize {
    let mut n = 0;
    while let Ok(Some(_)) =
        tokio::time::timeout(std::time::Duration::from_millis(ms), rx.recv()).await
    {
        n += 1;
    }
    n
}

/// #25: with both the downstream and internal channels full, cancellation
/// must still finish the watcher (no hang on the blocked reader).
#[tokio::test]
async fn test_run_cancel_with_full_channels_finishes() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("auth.log");
    let content = format!("{FAILURE_LINE}\n").repeat(1000);
    std::fs::write(&path, content).unwrap();

    // Absent-file resume point → read from the start, flooding the channels.
    let resume = ResumePoint::file(FilePosition::absent(path.clone()));
    let (cancel, handle, rx) = spawn_from(path, Some(resume), 1);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    cancel.cancel();
    let bound = DRAIN_TIMEOUT + std::time::Duration::from_secs(3);
    let result = tokio::time::timeout(bound, handle).await;
    let resume = result.expect("watcher hung after cancel with full channels");
    // D4: queued failures were dropped on drain timeout, so the reader's
    // position is past undelivered failures and must not be handed on.
    assert!(
        resume.unwrap().is_none(),
        "drain timeout must not return a resume point"
    );
    drop(rx);
}

/// #19: a line written just before cancel is delivered by the final read.
#[tokio::test]
async fn test_run_cancel_performs_final_read() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("auth.log");
    std::fs::write(&path, "").unwrap();
    let (cancel, handle, mut rx) = spawn_from(path.clone(), None, 16);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    append(&path, &format!("{FAILURE_LINE}\n"));
    cancel.cancel();
    let resume = handle.await.unwrap().expect("resume point");

    assert_eq!(count_within(&mut rx, 200).await, 1);
    let pos = resume.into_file().expect("file resume point");
    assert_eq!(pos.offset, std::fs::metadata(&path).unwrap().len());
}

/// #19: lines written between the old watcher stopping and the new one
/// starting are observed exactly once by the resumed watcher.
#[tokio::test]
async fn test_run_from_resume_sees_gap_lines_once() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("auth.log");
    std::fs::write(&path, "preexisting line\n").unwrap();

    let (cancel, handle, mut rx) = spawn_from(path.clone(), None, 16);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    append(&path, &format!("{FAILURE_LINE}\n"));
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    cancel.cancel();
    let resume = handle.await.unwrap();
    assert_eq!(count_within(&mut rx, 100).await, 1);

    // Written while no watcher is running (the reload gap).
    append(&path, &format!("{FAILURE_LINE}\n"));

    let (cancel2, handle2, mut rx2) = spawn_from(path, resume, 16);
    assert_eq!(
        count_within(&mut rx2, 800).await,
        1,
        "gap line exactly once"
    );
    cancel2.cancel();
    handle2.await.unwrap();
}

/// #19: a partial trailing line is excluded from the resume offset, so the
/// successor re-reads it whole.
#[tokio::test]
async fn test_run_resume_offset_excludes_partial_line() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("auth.log");
    std::fs::write(&path, "done\n").unwrap();
    let (cancel, handle, _rx) = spawn_from(path.clone(), None, 16);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    append(&path, "partial without newline");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    cancel.cancel();
    let pos = handle
        .await
        .unwrap()
        .and_then(ResumePoint::into_file)
        .unwrap();
    assert_eq!(pos.offset, 5);
}

/// #20: a log file that does not exist at startup is picked up once it
/// appears, and read from its start.
#[tokio::test]
async fn test_run_detects_log_created_after_start() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("late.log");
    let (cancel, handle, mut rx) = spawn_from(path.clone(), None, 16);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    std::fs::write(&path, format!("{FAILURE_LINE}\n")).unwrap();
    let failure = tokio::time::timeout(std::time::Duration::from_secs(4), rx.recv())
        .await
        .expect("late log file was never read")
        .expect("channel closed");
    assert_eq!(failure.ip.to_string(), "192.168.1.100");

    cancel.cancel();
    handle.await.unwrap();
}

/// A watcher cancelled while its log is still missing returns an "absent"
/// resume point so the successor reads the file from the start.
#[tokio::test]
async fn test_run_cancel_while_missing_returns_absent_point() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("never.log");
    let (cancel, handle, _rx) = spawn_from(path.clone(), None, 16);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    cancel.cancel();
    let pos = tokio::time::timeout(std::time::Duration::from_secs(1), handle)
        .await
        .expect("cancel must interrupt the open retry")
        .unwrap()
        .and_then(ResumePoint::into_file)
        .unwrap();
    assert_eq!(pos.path, path);
    assert!(pos.identity.is_none());
}

/// Closing the downstream channel stops the watcher even with no matches.
#[tokio::test]
async fn test_run_downstream_closed_stops_watcher() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("auth.log");
    std::fs::write(&path, "").unwrap();
    let (_cancel, handle, rx) = spawn_from(path.clone(), None, 1);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    drop(rx);
    append(&path, &format!("{FAILURE_LINE}\n"));
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), handle).await;
    assert!(result.is_ok(), "watcher must stop once downstream closes");
}
