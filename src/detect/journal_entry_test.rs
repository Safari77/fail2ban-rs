use super::*;

use crate::detect::matcher::JailMatcher;

const TS_MICROS: i64 = 1_705_314_600_123_456;

fn ts_text() -> String {
    format_timestamp(TS_MICROS).unwrap()
}

#[test]
fn test_parse_entry_builds_short_line() {
    let json = format!(
        r#"{{"__CURSOR":"s=abc;i=1","__REALTIME_TIMESTAMP":"{TS_MICROS}","_HOSTNAME":"web1","SYSLOG_IDENTIFIER":"sshd","_PID":"42","MESSAGE":"Failed password for root from 192.168.1.100 port 22"}}"#
    );
    let entry = parse_entry(&json).unwrap();
    assert_eq!(entry.cursor.as_deref(), Some("s=abc;i=1"));
    assert_eq!(entry.timestamp, Some(TS_MICROS / 1_000_000));
    let lines: Vec<String> = entry.lines().collect();
    assert_eq!(
        lines,
        vec![format!(
            "{} web1 sshd[42]: Failed password for root from 192.168.1.100 port 22",
            ts_text()
        )]
    );
}

#[test]
fn test_parse_entry_line_matches_sshd_filter() {
    let json = r#"{"__CURSOR":"c","__REALTIME_TIMESTAMP":"1705314600000000","_HOSTNAME":"h","SYSLOG_IDENTIFIER":"sshd","_PID":"1","MESSAGE":"Failed password for root from 10.0.0.9 port 22 ssh2"}"#;
    let entry = parse_entry(json).unwrap();
    let matcher = JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap();
    let line = entry.lines().next().unwrap();
    let m = matcher.try_match(&line).expect("rebuilt line should match");
    assert_eq!(m.ip.to_string(), "10.0.0.9");
}

#[test]
fn test_parse_entry_prefers_source_timestamp() {
    let json = r#"{"__REALTIME_TIMESTAMP":"2000000000","_SOURCE_REALTIME_TIMESTAMP":"1000000000","MESSAGE":"x"}"#;
    let entry = parse_entry(json).unwrap();
    assert_eq!(entry.timestamp, Some(1000));
}

#[test]
fn test_parse_entry_byte_array_message_decoded_lossily() {
    let json = r#"{"MESSAGE":[104,105,255]}"#;
    let entry = parse_entry(json).unwrap();
    assert_eq!(entry.message, "hi\u{FFFD}");
}

#[test]
fn test_parse_entry_multi_value_field_uses_first() {
    let json = r#"{"SYSLOG_IDENTIFIER":["sshd","other"],"MESSAGE":"m"}"#;
    let entry = parse_entry(json).unwrap();
    assert_eq!(entry.prefix, "sshd: ");
}

#[test]
fn test_parse_entry_falls_back_to_comm_and_syslog_pid() {
    let json = r#"{"_COMM":"dovecot","SYSLOG_PID":"7","MESSAGE":"m"}"#;
    let entry = parse_entry(json).unwrap();
    assert_eq!(entry.prefix, "dovecot[7]: ");
    assert!(entry.cursor.is_none());
    assert!(entry.timestamp.is_none());
}

#[test]
fn test_parse_entry_without_ident_has_no_colon() {
    let json = r#"{"_HOSTNAME":"h","MESSAGE":"m"}"#;
    let entry = parse_entry(json).unwrap();
    assert_eq!(entry.prefix, "h ");
}

#[test]
fn test_parse_entry_invalid_json_is_none() {
    assert!(parse_entry("not json").is_none());
    assert!(parse_entry("[1,2]").is_none());
}

#[test]
fn test_parse_entry_null_message_is_empty() {
    let entry = parse_entry(r#"{"MESSAGE":null}"#).unwrap();
    assert_eq!(entry.lines().count(), 0);
}

#[test]
fn test_lines_multiline_message_prefixes_only_first_line() {
    let json = r#"{"SYSLOG_IDENTIFIER":"app","MESSAGE":"first  \nsecond"}"#;
    let entry = parse_entry(json).unwrap();
    let lines: Vec<String> = entry.lines().collect();
    assert_eq!(lines, vec!["app: first", "     second"]);
}

/// A multi-byte character straddling the cap is dropped whole, never split.
#[test]
fn test_truncate_message_respects_char_boundary() {
    let mut s = "a".repeat(MAX_LINE_LEN - 1);
    s.push('\u{e9}'); // 2 bytes: straddles MAX_LINE_LEN
    let out = truncate_message(Cow::Owned(s));
    assert_eq!(out.len(), MAX_LINE_LEN - 1);
    let short = truncate_message(Cow::Borrowed("short"));
    assert!(matches!(short, Cow::Borrowed("short")));
}

/// D1: continuation lines are indented like `journalctl --output=short`,
/// without the ident prefix.
#[test]
fn test_lines_continuation_lines_are_indented_without_prefix() {
    let json = r#"{"SYSLOG_IDENTIFIER":"app","_PID":"7","MESSAGE":"first\nsecond\n"}"#;
    let entry = parse_entry(json).unwrap();
    let lines: Vec<String> = entry.lines().collect();
    let indent = " ".repeat("app[7]: ".len());
    assert_eq!(
        lines,
        vec!["app[7]: first".to_string(), format!("{indent}second")]
    );
}

/// D1: a newline injected into an sshd message must not forge a matching
/// `sshd[pid]: Failed password ...` line for a victim IP.
#[test]
fn test_lines_forged_continuation_does_not_match_sshd_filter() {
    let json = r#"{"__REALTIME_TIMESTAMP":"1705314600000000","_HOSTNAME":"h","SYSLOG_IDENTIFIER":"sshd","_PID":"42","MESSAGE":"Invalid user x from 10.0.0.1 port 1\nFailed password for root from 203.0.113.7 port 22 ssh2"}"#;
    let entry = parse_entry(json).unwrap();
    let mut lines = entry.lines();
    let (first, forged) = (lines.next().unwrap(), lines.next().unwrap());
    assert!(lines.next().is_none());
    crate::detect::filters::test_util::assert_filter_matches("sshd", &first, "10.0.0.1");
    crate::detect::filters::test_util::assert_filter_no_match("sshd", &forged);
}
