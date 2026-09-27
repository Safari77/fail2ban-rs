use super::*;

#[cfg(unix)]
fn exit_code(code: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(code << 8)
}

#[test]
fn test_cursor_rejected_stderr_mentions_cursor() {
    let msg = "Failed to seek to cursor: Invalid argument";
    assert!(cursor_rejected(Duration::from_secs(60), None, msg));
}

#[cfg(unix)]
#[test]
fn test_cursor_rejected_fast_nonzero_exit() {
    assert!(cursor_rejected(
        Duration::from_millis(100),
        Some(exit_code(1)),
        ""
    ));
}

#[cfg(unix)]
#[test]
fn test_cursor_rejected_slow_nonzero_exit_is_false() {
    assert!(!cursor_rejected(FAST_FAIL_WINDOW, Some(exit_code(1)), ""));
}

#[cfg(unix)]
#[test]
fn test_cursor_rejected_clean_exit_is_false() {
    assert!(!cursor_rejected(
        Duration::from_millis(10),
        Some(exit_code(0)),
        ""
    ));
}

#[test]
fn test_cursor_rejected_unknown_status_is_false() {
    assert!(!cursor_rejected(
        Duration::from_millis(10),
        None,
        "other noise"
    ));
}

#[tokio::test]
async fn test_stderr_capture_is_bounded() {
    let mut child = tokio::process::Command::new("/bin/sh")
        .args(["-c", "head -c 20000 /dev/zero | tr '\\0' x >&2"])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let capture = StderrCapture::spawn(&mut child);
    let status = reap("test", &mut child).await;
    assert!(status.is_some_and(|s| s.success()));
    let text = capture.collect().await;
    assert_eq!(text.len(), STDERR_CAP);
}
