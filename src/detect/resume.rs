//! Watcher resume points — gap-free handoff between old and new watchers.
//!
//! When a watcher stops it reports where it got to: a file identity plus
//! byte offset for file watchers, or a journal cursor for journal watchers.
//! A replacement watcher started from that [`ResumePoint`] continues exactly
//! where the old one stopped instead of jumping to the end of the log.

use std::io::{BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::detect::backoff::{Backoff, blocking_sleep};
use crate::detect::identity::FileIdentity;

/// Opaque position a watcher reached when it stopped.
///
/// Returned by [`watcher::run`](crate::detect::watcher::run) and
/// [`journal::run`](crate::detect::journal::run); pass it to the matching
/// `run_from` of the replacement watcher. A resume point of the wrong kind
/// (file vs journal) or for a different log path is ignored, and the new
/// watcher falls back to its default start position.
#[derive(Debug, Clone)]
pub struct ResumePoint(Kind);

#[derive(Debug, Clone)]
enum Kind {
    File(FilePosition),
    Journal(String),
}

/// Where a file reader stopped.
#[derive(Debug, Clone)]
pub(crate) struct FilePosition {
    /// Log path the reader was tailing.
    pub(crate) path: PathBuf,
    /// Fingerprint of the handle the reader held; `None` if the file was
    /// never opened (it did not exist).
    pub(crate) identity: Option<FileIdentity>,
    /// Byte offset of the first unprocessed byte.
    pub(crate) offset: u64,
}

impl FilePosition {
    /// Marker for "the file did not exist": a successor reads it from the
    /// start once it appears.
    pub(crate) fn absent(path: PathBuf) -> Self {
        Self {
            path,
            identity: None,
            offset: 0,
        }
    }
}

impl ResumePoint {
    /// Wrap a file reader position.
    pub(crate) fn file(pos: FilePosition) -> Self {
        Self(Kind::File(pos))
    }

    /// Wrap a journal cursor.
    pub(crate) fn journal(cursor: String) -> Self {
        Self(Kind::Journal(cursor))
    }

    /// The file position, if this is a file resume point.
    pub(crate) fn into_file(self) -> Option<FilePosition> {
        match self.0 {
            Kind::File(p) => Some(p),
            Kind::Journal(_) => None,
        }
    }

    /// The journal cursor, if this is a journal resume point.
    pub(crate) fn into_journal_cursor(self) -> Option<String> {
        match self.0 {
            Kind::Journal(c) => Some(c),
            Kind::File(_) => None,
        }
    }
}

/// Where a freshly opened file should start reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartAt {
    /// Skip existing content (default, no resume point).
    End,
    /// Read the whole file (new file, or rotated during handoff).
    Start,
    /// Continue at a byte offset in the same file.
    Offset(u64),
}

/// Decide the start position for `file` at `path` given an optional resume.
pub(crate) fn start_for(
    path: &Path,
    resume: Option<&FilePosition>,
    file: &std::fs::File,
) -> StartAt {
    let Some(pos) = resume.filter(|p| p.path == path) else {
        return StartAt::End;
    };
    let Some(old) = pos.identity.as_ref() else {
        return StartAt::Start; // file was absent at handoff — it is new
    };
    match FileIdentity::from_handle(file) {
        Some(cur) if old.can_resume(&cur, pos.offset) => StartAt::Offset(pos.offset),
        _ => StartAt::Start, // replaced/truncated during handoff
    }
}

/// Open the log at `path`, retrying with capped backoff while it is missing.
///
/// Returns `None` only if `cancel` fires first. A file that only appears
/// after one or more retries is read from the start, since it is new.
pub(crate) fn open_log(
    jail_id: &str,
    path: &PathBuf,
    resume: Option<&FilePosition>,
    cancel: &CancellationToken,
) -> Option<BufReader<std::fs::File>> {
    let mut backoff = Backoff::new();
    let mut retried = false;
    loop {
        match open_positioned(path, resume, retried) {
            Ok(reader) => {
                if retried {
                    info!(jail = %jail_id, path = %path.display(), "log file opened after retry");
                }
                return Some(reader);
            }
            Err(e) => {
                let delay = backoff.next_delay();
                log_open_failure(jail_id, path, &e, &backoff, delay);
                if !blocking_sleep(delay, cancel) {
                    return None;
                }
                retried = true;
            }
        }
    }
}

fn open_positioned(
    path: &PathBuf,
    resume: Option<&FilePosition>,
    force_start: bool,
) -> std::io::Result<BufReader<std::fs::File>> {
    let mut file = std::fs::File::open(path)?;
    let start = if force_start {
        StartAt::Start
    } else {
        start_for(path, resume, &file)
    };
    match start {
        StartAt::End => file.seek(SeekFrom::End(0))?,
        StartAt::Start => 0,
        StartAt::Offset(off) => file.seek(SeekFrom::Start(off))?,
    };
    Ok(BufReader::new(file))
}

fn log_open_failure(
    jail_id: &str,
    path: &Path,
    err: &std::io::Error,
    backoff: &Backoff,
    delay: std::time::Duration,
) {
    let retry_secs = delay.as_secs();
    if backoff.is_first_failure() {
        warn!(jail = %jail_id, path = %path.display(), error = %err, retry_secs, "log open failed, retrying");
    } else {
        debug!(jail = %jail_id, path = %path.display(), error = %err, retry_secs, "log open retry failed");
    }
}

#[cfg(test)]
#[path = "resume_test.rs"]
mod resume_test;
