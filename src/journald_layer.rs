//! Custom journald tracing layer that composes structured fields into MESSAGE.
//!
//! Unlike stock `tracing_journald`, which leaves MESSAGE as just the event
//! phrase and writes fields only as journald metadata, this layer:
//!
//! - Composes MESSAGE as `<phrase> key=value key=value ...` so operators
//!   reading `journalctl` (which displays MESSAGE only by default) see full
//!   context without needing `-o verbose` or `-o json`.
//! - Still writes each field as journald metadata (uppercased), so
//!   `journalctl IP=1.2.3.4` queries and witness → Tell structured
//!   forwarding both work.
//!
//! This eliminates the source-level duplication that would otherwise be
//! required (fields written once as structured data, again embedded in the
//! format string) and makes the non-journald `tracing_subscriber::fmt`
//! output clean (no doubled fields).

use std::fmt::Write as _;
use std::os::unix::net::UnixDatagram;
use std::sync::Mutex;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// Custom journald layer with composed MESSAGE + per-field metadata.
pub struct JournaldLayer {
    socket: Mutex<UnixDatagram>,
}

impl JournaldLayer {
    /// Create a layer connected to the default systemd journal socket.
    ///
    /// # Errors
    /// Returns an error if an unbound unix datagram socket cannot be created.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            socket: Mutex::new(UnixDatagram::unbound()?),
        })
    }
}

impl<S> Layer<S> for JournaldLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let priority = level_to_priority(*event.metadata().level());
        let composed = compose_message(&visitor.message, &visitor.fields);

        let mut buf = Vec::with_capacity(256);
        write_field(&mut buf, "MESSAGE", &composed);
        write_field(&mut buf, "PRIORITY", &priority.to_string());
        for (k, v) in &visitor.fields {
            write_field(&mut buf, &k.to_ascii_uppercase(), v);
        }

        if let Ok(sock) = self.socket.lock() {
            let _ = sock.send_to(&buf, JOURNAL_SOCKET);
        }
    }
}

/// Visitor that splits the event `message` from all other structured fields.
#[derive(Default)]
pub struct FieldVisitor {
    pub message: String,
    pub fields: Vec<(String, String)>,
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let formatted = format!("{value:?}");
        if field.name() == "message" {
            // Debug on a &str adds surrounding quotes — strip them for MESSAGE.
            self.message = formatted
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .map_or_else(|| formatted.clone(), std::string::ToString::to_string);
        } else {
            self.fields.push((field.name().to_string(), formatted));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

/// Map tracing levels to syslog priorities, matching the project's existing
/// convention (INFO → notice for operator visibility in journal viewers).
fn level_to_priority(level: Level) -> u8 {
    match level {
        Level::ERROR => 3, // err
        Level::WARN => 4,  // warning
        Level::INFO => 5,  // notice
        Level::DEBUG => 6, // info
        Level::TRACE => 7, // debug
    }
}

/// Build the human-readable MESSAGE string: `<phrase> key=value key=value`.
pub fn compose_message(phrase: &str, fields: &[(String, String)]) -> String {
    if fields.is_empty() {
        return phrase.to_string();
    }
    let mut s = String::with_capacity(phrase.len() + fields.len() * 24);
    s.push_str(phrase);
    for (k, v) in fields {
        s.push(' ');
        s.push_str(k);
        s.push('=');
        if needs_quoting(v) {
            s.push('"');
            for c in v.chars() {
                match c {
                    '"' => s.push_str("\\\""),
                    '\\' => s.push_str("\\\\"),
                    '\n' => s.push_str("\\n"),
                    _ => s.push(c),
                }
            }
            s.push('"');
        } else {
            s.push_str(v);
        }
    }
    s
}

fn needs_quoting(v: &str) -> bool {
    v.is_empty() || v.contains(' ') || v.contains('"') || v.contains('\n')
}

/// Serialize a journal field using the native socket protocol.
///
/// Single-line values: `KEY=value\n`.
/// Multi-line values: `KEY\n<little-endian u64 length><value>\n`.
pub fn write_field(buf: &mut Vec<u8>, key: &str, value: &str) {
    if value.contains('\n') {
        buf.extend_from_slice(key.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
        buf.extend_from_slice(value.as_bytes());
        buf.push(b'\n');
    } else {
        buf.extend_from_slice(key.as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(value.as_bytes());
        buf.push(b'\n');
    }
}

/// Format a float without trailing zeros — helper retained for callers that
/// want to pre-format floats before passing as strings.
#[allow(dead_code)]
fn _fmt_f64(v: f64) -> String {
    let mut s = String::new();
    let _ = write!(s, "{v}");
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn compose_message_no_fields() {
        assert_eq!(compose_message("banned", &[]), "banned");
    }

    #[test]
    fn compose_message_with_fields() {
        let fields = vec![
            ("ip".to_string(), "1.2.3.4".to_string()),
            ("jail".to_string(), "sshd".to_string()),
        ];
        assert_eq!(
            compose_message("banned", &fields),
            "banned ip=1.2.3.4 jail=sshd"
        );
    }

    #[test]
    fn compose_message_quotes_values_with_spaces() {
        let fields = vec![("error".to_string(), "nft command failed".to_string())];
        assert_eq!(
            compose_message("ban failed", &fields),
            r#"ban failed error="nft command failed""#
        );
    }

    #[test]
    fn compose_message_escapes_quotes() {
        let fields = vec![("msg".to_string(), r#"a "quoted" value"#.to_string())];
        assert_eq!(
            compose_message("event", &fields),
            r#"event msg="a \"quoted\" value""#
        );
    }

    #[test]
    fn compose_message_quotes_empty_values() {
        let fields = vec![("x".to_string(), String::new())];
        assert_eq!(compose_message("event", &fields), r#"event x="""#);
    }

    #[test]
    fn write_field_single_line() {
        let mut buf = Vec::new();
        write_field(&mut buf, "MESSAGE", "hello");
        assert_eq!(&buf, b"MESSAGE=hello\n");
    }

    #[test]
    fn write_field_multiline() {
        let mut buf = Vec::new();
        write_field(&mut buf, "MESSAGE", "line1\nline2");
        // "MESSAGE\n" + 8-byte LE length (11) + value + "\n"
        assert_eq!(&buf[..8], b"MESSAGE\n");
        assert_eq!(&buf[8..16], &11u64.to_le_bytes());
        assert_eq!(&buf[16..27], b"line1\nline2");
        assert_eq!(buf[27], b'\n');
    }

    #[test]
    fn level_to_priority_mapping() {
        assert_eq!(level_to_priority(Level::ERROR), 3);
        assert_eq!(level_to_priority(Level::WARN), 4);
        assert_eq!(level_to_priority(Level::INFO), 5);
        assert_eq!(level_to_priority(Level::DEBUG), 6);
        assert_eq!(level_to_priority(Level::TRACE), 7);
    }

    #[test]
    fn needs_quoting_basic() {
        assert!(!needs_quoting("sshd"));
        assert!(!needs_quoting("1.2.3.4"));
        assert!(needs_quoting(""));
        assert!(needs_quoting("has space"));
        assert!(needs_quoting(r#"has"quote"#));
        assert!(needs_quoting("has\nnewline"));
    }
}
