//! Journal watcher — reads log entries from the systemd journal.
//!
//! Uses `journalctl --follow` as a subprocess to stream new journal entries.
//! Matched lines are sent as `Failure` events to the tracker.
//!
//! Only compiled when the `systemd` feature is enabled.

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{ChildStdout, Command};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::date::DateParser;
use crate::ignore::IgnoreList;
use crate::matcher::JailMatcher;
use crate::watcher::{Failure, MAX_LINE_LEN};

/// Run the journal watcher for a single jail.
///
/// Spawns `journalctl --follow --no-pager --output=short` with optional
/// match filters, reads new lines, and sends `Failure` events.
pub async fn run(
    jail_id: String,
    journalmatch: Vec<String>,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    failure_tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
) {
    info!(jail = %jail_id, "journal watcher started");

    let mut cmd = Command::new("journalctl");
    cmd.arg("--follow")
        .arg("--no-pager")
        .arg("--output=short")
        .arg("--lines=0"); // Start from current position, no backlog.

    for m in &journalmatch {
        cmd.arg(m);
    }

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            error!(jail = %jail_id, error = %e, "failed to spawn journalctl");
            return;
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            error!(jail = %jail_id, "journalctl stdout not available");
            return;
        }
    };

    let mut reader = BufReader::new(stdout);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        tokio::select! {
            _ = cancel.cancelled() => {
                info!(jail = %jail_id, "journal watcher shutting down");
                let _ = child.kill().await;
                break;
            }

            result = read_line_bounded(&mut reader, &mut line_buf, &jail_id) => {
                match result {
                    Ok(0) => {
                        warn!(jail = %jail_id, "journalctl stream ended");
                        break;
                    }
                    Ok(_) => {
                        let text = line_buf.trim_end();
                        if text.is_empty() {
                            continue;
                        }
                        process_line(
                            text,
                            &jail_id,
                            &matcher,
                            &date_parser,
                            &ignore_list,
                            &failure_tx,
                        ).await;
                    }
                    Err(e) => {
                        error!(jail = %jail_id, error = %e, "error reading journal");
                        break;
                    }
                }
            }
        }
    }

    let _ = child.wait().await;
    info!(jail = %jail_id, "journal watcher stopped");
}

async fn process_line(
    line: &str,
    jail_id: &str,
    matcher: &JailMatcher,
    date_parser: &DateParser,
    ignore_list: &IgnoreList,
    failure_tx: &mpsc::Sender<Failure>,
) {
    let match_result = match matcher.try_match(line) {
        Some(r) => r,
        None => return,
    };

    if ignore_list.is_ignored(&match_result.ip) {
        return;
    }

    let timestamp = date_parser
        .parse_line(line)
        .unwrap_or_else(|| chrono::Utc::now().timestamp());

    let failure = Failure {
        ip: match_result.ip,
        jail_id: jail_id.to_string(),
        timestamp,
    };

    if failure_tx.send(failure).await.is_err() {
        warn!(jail = %jail_id, "failure channel closed");
    }
}

/// Read a single line from the async reader, bounded by [`MAX_LINE_LEN`].
///
/// Uses `fill_buf` / `consume` to accumulate bytes into `buf` up to the
/// limit. If the line exceeds [`MAX_LINE_LEN`], logs a warning, drains
/// remaining bytes to the next newline, clears `buf`, and returns a
/// non-zero byte count so the caller can distinguish it from EOF (0).
async fn read_line_bounded(
    reader: &mut BufReader<ChildStdout>,
    buf: &mut String,
    jail_id: &str,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(total); // EOF — 0 if nothing was buffered
        }
        if let Some(pos) = memchr_newline(available) {
            return consume_up_to_newline(reader, buf, available, pos, total, jail_id);
        }
        // No newline found in this chunk.
        let chunk_len = available.len();
        if total + chunk_len > MAX_LINE_LEN {
            return skip_oversized(reader, buf, chunk_len, jail_id).await;
        }
        append_valid_utf8(buf, available);
        reader.consume(chunk_len);
        total += chunk_len;
    }
}

/// Consume bytes up to (and including) the newline at `pos`.
///
/// Returns the total bytes consumed, or skips the line if it exceeds the limit.
fn consume_up_to_newline(
    reader: &mut BufReader<ChildStdout>,
    buf: &mut String,
    available: &[u8],
    pos: usize,
    total: usize,
    jail_id: &str,
) -> std::io::Result<usize> {
    let to_take = pos + 1; // include the newline
    if total + to_take > MAX_LINE_LEN {
        warn!(jail = %jail_id, "skipping oversized journal line (>{MAX_LINE_LEN} bytes)");
        reader.consume(to_take);
        buf.clear();
        // Return non-zero so caller knows this is not EOF.
        return Ok(total + to_take);
    }
    append_valid_utf8(buf, &available[..to_take]);
    reader.consume(to_take);
    Ok(total + to_take)
}

/// Skip an oversized line: consume the current chunk and drain to the next newline.
async fn skip_oversized(
    reader: &mut BufReader<ChildStdout>,
    buf: &mut String,
    chunk_len: usize,
    jail_id: &str,
) -> std::io::Result<usize> {
    warn!(jail = %jail_id, "skipping oversized journal line (>{MAX_LINE_LEN} bytes)");
    reader.consume(chunk_len);
    buf.clear();
    drain_until_newline(reader).await?;
    // Return non-zero so caller knows this is not EOF.
    Ok(MAX_LINE_LEN + 1)
}

/// Discard bytes from the reader until a newline or EOF is reached.
async fn drain_until_newline(reader: &mut BufReader<ChildStdout>) -> std::io::Result<()> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            break; // EOF
        }
        if let Some(pos) = memchr_newline(available) {
            reader.consume(pos + 1);
            break;
        }
        let len = available.len();
        reader.consume(len);
    }
    Ok(())
}

/// Find the position of the first newline byte in a slice.
fn memchr_newline(buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| b == b'\n')
}

/// Append bytes to a `String`, replacing invalid UTF-8 sequences.
fn append_valid_utf8(buf: &mut String, bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    buf.push_str(&text);
}
