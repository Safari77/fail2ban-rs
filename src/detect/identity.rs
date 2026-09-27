//! Log file identity and rotation detection.
//!
//! Captures a fingerprint of a log file (inode, size, first-line hash) so the
//! [`reader`](crate::detect::reader) can detect when a file has been rotated,
//! truncated, or replaced and needs reopening.
//!
//! A file that is empty, or whose first line is still unterminated, has no
//! stable first line yet: its hash is recorded as *unknown* so that the line
//! completing later is not mistaken for a rotation (which would re-read and
//! double-count every line).

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;

use xxhash_rust::xxh3::xxh3_64;

use crate::detect::watcher::MAX_LINE_LEN;

/// Identifies a log file for rotation detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    /// File inode (unix only).
    #[cfg(unix)]
    inode: u64,
    /// File size in bytes.
    size: u64,
    /// Hash of the first line; `None` while the file is empty or its first
    /// line is not yet newline-terminated.
    first_line_hash: Option<u64>,
}

/// Hash a first-line candidate read from at most [`MAX_LINE_LEN`] + 1 bytes.
///
/// `None` when the bytes hold no complete line yet (empty, or unterminated
/// and still short enough that it may grow). A capped, unterminated line is
/// hashed as-is: bytes past the cap never change its prefix.
fn first_line_hash(bytes: &[u8]) -> Option<u64> {
    let complete = bytes.last() == Some(&b'\n') || bytes.len() > MAX_LINE_LEN;
    complete.then(|| xxh3_64(bytes))
}

impl FileIdentity {
    /// Fingerprint the file at `path`, or `None` if it can't be read.
    pub(crate) fn from_file(path: &PathBuf) -> Option<Self> {
        let file = std::fs::File::open(path).ok()?;
        let meta = file.metadata().ok()?;

        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            meta.ino()
        };

        let mut bytes = Vec::new();
        BufReader::new(file)
            .take(MAX_LINE_LEN as u64 + 1)
            .read_until(b'\n', &mut bytes)
            .ok()?;

        Some(Self {
            #[cfg(unix)]
            inode,
            size: meta.len(),
            first_line_hash: first_line_hash(&bytes),
        })
    }

    /// Fingerprint an already-open file handle without moving its cursor.
    ///
    /// Unlike [`from_file`](Self::from_file) this describes exactly the file
    /// the reader holds, even if the path has since been rotated. The first
    /// line is hashed from at most [`MAX_LINE_LEN`] + 1 bytes.
    #[cfg(unix)]
    pub(crate) fn from_handle(file: &std::fs::File) -> Option<Self> {
        use std::os::unix::fs::{FileExt, MetadataExt};
        let meta = file.metadata().ok()?;
        let mut buf = vec![0u8; MAX_LINE_LEN + 1];
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = file.read_at(buf.get_mut(filled..)?, filled as u64).ok()?;
            if n == 0 {
                break;
            }
            let chunk = buf.get(filled..filled + n)?;
            filled += n;
            if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
                filled = filled - n + pos + 1;
                break;
            }
        }
        Some(Self {
            inode: meta.ino(),
            size: meta.len(),
            first_line_hash: first_line_hash(buf.get(..filled)?),
        })
    }

    /// Non-unix fallback: handle fingerprinting is unsupported.
    #[cfg(not(unix))]
    pub(crate) fn from_handle(_file: &std::fs::File) -> Option<Self> {
        None
    }

    /// Whether `current` is the same file as `self` and still holds at least
    /// `offset` bytes, so a reader may safely resume at `offset`.
    ///
    /// An unknown first line on `self` (the file was empty or its first line
    /// unterminated) is compatible with any current first line.
    pub(crate) fn can_resume(&self, current: &FileIdentity, offset: u64) -> bool {
        #[cfg(unix)]
        if self.inode != current.inode {
            return false;
        }
        let same_first_line = match (self.first_line_hash, current.first_line_hash) {
            (None, _) => true,
            (Some(a), Some(b)) => a == b,
            (Some(_), None) => false,
        };
        same_first_line && current.size >= offset
    }

    /// Whether `other` represents a rotated/truncated/replaced version of `self`.
    ///
    /// A first line that was unknown in `self` and has since completed is
    /// growth of the same file, not a rotation (same inode, size not shrunk).
    pub(crate) fn is_rotated(&self, other: &FileIdentity) -> bool {
        #[cfg(unix)]
        if self.inode != other.inode {
            return true;
        }
        // Size shrunk → truncated/rotated.
        if other.size < self.size {
            return true;
        }
        match (self.first_line_hash, other.first_line_hash) {
            // First line hash changed → different file.
            (Some(a), Some(b)) => a != b,
            // A complete first line cannot become incomplete by appending.
            (Some(_), None) => true,
            // Still unknown, or completed since: same file, still growing.
            (None, _) => false,
        }
    }
}

#[cfg(test)]
#[path = "identity_test.rs"]
mod identity_test;
