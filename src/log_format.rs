//! Structured stderr formatter for logfmt and JSON output.
//!
//! Emits each event as a single line on stderr. Under systemd, prepends
//! `<N>` per-line so journald sets PRIORITY correctly (systemd strips the
//! prefix before storing MESSAGE). Without systemd, prepends a human
//! level tag (e.g. ` INFO`) instead.
//!
//! This replaces writing to the journald socket directly. The entire
//! structured payload — message phrase + all fields — ends up in
//! journald's MESSAGE field as one parseable string. Consumers (journalctl,
//! rsyslog, witness) read MESSAGE and parse it according to the chosen
//! format.

use std::fmt;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// Output format for each log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// `banned ip=1.2.3.4 jail=sshd reason=threshold`
    Logfmt,
    /// `{"msg":"banned","ip":"1.2.3.4","jail":"sshd","reason":"threshold"}`
    Json,
}

impl LogFormat {
    /// Parse from config string. Defaults to `Logfmt` on unknown/missing.
    pub fn parse(s: Option<&str>) -> Self {
        match s.map(str::to_ascii_lowercase).as_deref() {
            Some("json") => Self::Json,
            _ => Self::Logfmt,
        }
    }
}

/// Single-line stderr formatter.
pub struct StructuredFormatter {
    format: LogFormat,
    systemd: bool,
}

impl StructuredFormatter {
    /// Create a new formatter. `systemd` controls whether `<N>` priority
    /// prefixes are emitted (auto-detected via `JOURNAL_STREAM`).
    pub fn new(format: LogFormat, systemd: bool) -> Self {
        Self { format, systemd }
    }
}

impl<S, N> FormatEvent<S, N> for StructuredFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let level = *event.metadata().level();

        if self.systemd {
            // <N> systemd priority prefix — stripped by journald, sets PRIORITY.
            write!(writer, "<{}>", level_to_priority(level))?;
        } else {
            // Non-systemd: prepend level tag + timestamp for human readability.
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
            write!(writer, "{ts}  {:>5} ", level.as_str())?;
        }

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        match self.format {
            LogFormat::Logfmt => visitor.write_logfmt(&mut writer)?,
            LogFormat::Json => visitor.write_json(&mut writer)?,
        }

        writeln!(writer)
    }
}

/// Visitor that collects the event message and structured fields.
#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: Vec<(String, Value)>,
}

impl FieldVisitor {
    fn push(&mut self, name: &str, value: Value) {
        if name == "message" {
            if let Value::String(s) = value {
                self.message = s;
            } else {
                self.message = value.to_string();
            }
        } else {
            self.fields.push((name.to_string(), value));
        }
    }

    fn write_logfmt(&self, w: &mut Writer<'_>) -> fmt::Result {
        w.write_str(&self.message)?;
        for (k, v) in &self.fields {
            write!(w, " {k}=")?;
            write_logfmt_value(w, v)?;
        }
        Ok(())
    }

    fn write_json(&self, w: &mut Writer<'_>) -> fmt::Result {
        let mut obj = Map::with_capacity(self.fields.len() + 1);
        obj.insert("msg".to_string(), Value::String(self.message.clone()));
        for (k, v) in &self.fields {
            obj.insert(k.clone(), v.clone());
        }
        match serde_json::to_string(&obj) {
            Ok(s) => w.write_str(&s),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field.name(), Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let formatted = format!("{value:?}");
        // Debug on &str adds surrounding quotes — strip for the message field.
        let clean = if field.name() == "message" {
            formatted
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .map_or(formatted.clone(), std::string::ToString::to_string)
        } else {
            formatted
        };
        self.push(field.name(), Value::String(clean));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field.name(), Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field.name(), Value::Number(value.into()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field.name(), Value::Bool(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        // serde_json::Number can fail on NaN/Inf — fall back to string.
        if let Some(n) = serde_json::Number::from_f64(value) {
            self.push(field.name(), Value::Number(n));
        } else {
            self.push(field.name(), Value::String(value.to_string()));
        }
    }
}

/// Map tracing level to syslog priority (matches the project convention
/// where INFO shows as NOTICE in journald for operator visibility).
fn level_to_priority(level: Level) -> u8 {
    match level {
        Level::ERROR => 3, // err
        Level::WARN => 4,  // warning
        Level::INFO => 5,  // notice
        Level::DEBUG => 6, // info
        Level::TRACE => 7, // debug
    }
}

fn write_logfmt_value(w: &mut Writer<'_>, v: &Value) -> fmt::Result {
    match v {
        Value::String(s) => write_logfmt_string(w, s),
        Value::Number(n) => write!(w, "{n}"),
        Value::Bool(b) => write!(w, "{b}"),
        Value::Null => w.write_str("null"),
        other => write_logfmt_string(w, &other.to_string()),
    }
}

fn write_logfmt_string(w: &mut Writer<'_>, s: &str) -> fmt::Result {
    if needs_quoting(s) {
        w.write_char('"')?;
        for c in s.chars() {
            match c {
                '"' => w.write_str("\\\"")?,
                '\\' => w.write_str("\\\\")?,
                '\n' => w.write_str("\\n")?,
                _ => w.write_char(c)?,
            }
        }
        w.write_char('"')
    } else {
        w.write_str(s)
    }
}

fn needs_quoting(s: &str) -> bool {
    s.is_empty() || s.contains(' ') || s.contains('"') || s.contains('\n') || s.contains('=')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn log_format_parse() {
        assert_eq!(LogFormat::parse(None), LogFormat::Logfmt);
        assert_eq!(LogFormat::parse(Some("logfmt")), LogFormat::Logfmt);
        assert_eq!(LogFormat::parse(Some("json")), LogFormat::Json);
        assert_eq!(LogFormat::parse(Some("JSON")), LogFormat::Json);
        assert_eq!(LogFormat::parse(Some("bogus")), LogFormat::Logfmt);
    }

    #[test]
    fn level_priority() {
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
        assert!(needs_quoting("has\"quote"));
        assert!(needs_quoting("has\nnewline"));
        assert!(needs_quoting("has=equals"));
    }

    fn logfmt_from_fields(fields: &[(&str, Value)], msg: &str) -> String {
        let visitor = FieldVisitor {
            message: msg.to_string(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        };
        let mut buf = String::new();
        visitor.write_logfmt(&mut Writer::new(&mut buf)).unwrap();
        buf
    }

    fn json_from_fields(fields: &[(&str, Value)], msg: &str) -> String {
        let visitor = FieldVisitor {
            message: msg.to_string(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        };
        let mut buf = String::new();
        visitor.write_json(&mut Writer::new(&mut buf)).unwrap();
        buf
    }

    #[test]
    fn logfmt_basic() {
        let out = logfmt_from_fields(
            &[
                ("ip", Value::String("1.2.3.4".to_string())),
                ("jail", Value::String("sshd".to_string())),
            ],
            "banned",
        );
        assert_eq!(out, "banned ip=1.2.3.4 jail=sshd");
    }

    #[test]
    fn logfmt_preserves_numbers() {
        let out = logfmt_from_fields(
            &[
                ("ban_time", Value::Number(3600.into())),
                ("ban_count", Value::Number(1.into())),
            ],
            "banned",
        );
        assert_eq!(out, "banned ban_time=3600 ban_count=1");
    }

    #[test]
    fn logfmt_quotes_values_with_spaces() {
        let out = logfmt_from_fields(
            &[("error", Value::String("nft command failed".to_string()))],
            "ban failed",
        );
        assert_eq!(out, r#"ban failed error="nft command failed""#);
    }

    #[test]
    fn json_basic() {
        let out = json_from_fields(
            &[
                ("ip", Value::String("1.2.3.4".to_string())),
                ("jail", Value::String("sshd".to_string())),
            ],
            "banned",
        );
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["msg"], "banned");
        assert_eq!(parsed["ip"], "1.2.3.4");
        assert_eq!(parsed["jail"], "sshd");
    }

    #[test]
    fn json_preserves_number_types() {
        let out = json_from_fields(
            &[
                ("ban_time", Value::Number(3600.into())),
                ("ban_count", Value::Number(1.into())),
            ],
            "banned",
        );
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["ban_time"], 3600);
        assert_eq!(parsed["ban_count"], 1);
    }
}
