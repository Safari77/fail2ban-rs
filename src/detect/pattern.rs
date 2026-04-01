//! Pattern expansion and literal prefix extraction.
//!
//! User-facing patterns use `<HOST>` as a placeholder for the IP capture group.
//! This module expands `<HOST>` into a regex that matches both IPv4 and IPv6
//! addresses, and extracts literal prefixes for Aho-Corasick pre-filtering.

use crate::error::{Error, Result};

/// Named capture group for the host IP (IPv4, IPv4-mapped IPv6, or IPv6).
///
/// Using a named group lets `try_match()` extract the IP from the exact
/// `<HOST>` position via `captures()`, instead of scanning the full match
/// span — which breaks when other IPs appear in the matched text.
///
/// The first alternative handles plain IPv4 and `::ffff:`-mapped IPv4
/// (common in ProFTPD, Courier, PAM logs). The second handles pure IPv6.
const HOST_CAPTURE: &str =
    r"(?P<host>(?:::[fF]{4}:)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{2,39})";

/// The placeholder token in user patterns.
const HOST_TAG: &str = "<HOST>";

/// Expand `<HOST>` in a user pattern into the IP capture group regex.
///
/// Returns an error if the pattern contains zero or more than one `<HOST>`.
pub fn expand_host(pattern: &str) -> Result<String> {
    let count = pattern.matches(HOST_TAG).count();
    if count == 0 {
        return Err(Error::config(format!(
            "pattern missing <HOST> placeholder: {pattern}"
        )));
    }
    if count > 1 {
        return Err(Error::config(format!(
            "pattern has multiple <HOST> placeholders ({count}): {pattern}"
        )));
    }
    Ok(pattern.replace(HOST_TAG, HOST_CAPTURE))
}

/// Strategy for extracting the host IP from a regex match span.
///
/// Determined at compile time from the pattern structure around `<HOST>`.
#[derive(Debug, Clone)]
pub enum HostExtractor {
    /// `<HOST>` is at the start of the pattern (or after `^`).
    /// Extract IP from the beginning of the match span.
    AtStart,
    /// `<HOST>` is preceded by this literal string.
    /// Search for the literal in the match span, extract IP after it.
    AfterLiteral(String),
    /// `<HOST>` is followed by this literal string.
    /// Search for the literal in the match span, extract the rightmost IP
    /// token immediately before it.
    BeforeLiteral(String),
    /// Ambiguous context — fall back to `captures()`.
    Captures,
}

/// Regex metacharacters used to identify literal boundaries.
const META_CHARS: &[char] = &[
    '\\', '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$',
];

/// Determine how to extract the host IP for a given pattern.
///
/// Examines the literal text around `<HOST>` to decide the fastest
/// extraction strategy. Falls back to `Captures` only when neither
/// the before nor after literal is usable.
pub fn host_extractor(pattern: &str) -> HostExtractor {
    let Some(host_pos) = pattern.find(HOST_TAG) else {
        return HostExtractor::Captures;
    };
    let before = &pattern[..host_pos];
    let after = &pattern[host_pos + HOST_TAG.len()..];

    // HOST at the very start, or only preceded by ^ anchor.
    if before.is_empty() || before.chars().all(|c| c == '^') {
        return HostExtractor::AtStart;
    }

    // Try literal immediately before HOST.
    let lit_before = trailing_literal(before);
    if lit_before.len() >= 2 {
        let prefix_before_literal = &before[..before.len() - lit_before.len()];
        if !prefix_before_literal.contains(&*lit_before) {
            return HostExtractor::AfterLiteral(lit_before);
        }
    }

    // Try literal immediately after HOST.
    let lit_after = leading_literal(after);
    if lit_after.len() >= 2 && !before.contains(&*lit_after) {
        return HostExtractor::BeforeLiteral(lit_after);
    }

    HostExtractor::Captures
}

/// Extract contiguous literal characters from the end of `s`.
fn trailing_literal(s: &str) -> String {
    let start = s
        .rfind(|c: char| META_CHARS.contains(&c))
        .map_or(0, |pos| pos + 1);
    s[start..].to_string()
}

/// Extract contiguous literal characters from the start of `s`.
fn leading_literal(s: &str) -> String {
    let end = s.find(|c: char| META_CHARS.contains(&c)).unwrap_or(s.len());
    s[..end].to_string()
}

/// Extract the literal prefix before `<HOST>` for Aho-Corasick pre-filtering.
///
/// Walks backwards from the `<HOST>` position to find the longest substring
/// that contains no regex metacharacters. Returns `None` if no usable literal
/// prefix exists (e.g. pattern starts with `<HOST>`).
pub fn literal_prefix(pattern: &str) -> Option<String> {
    let host_pos = pattern.find(HOST_TAG)?;
    let before = &pattern[..host_pos];
    if before.is_empty() {
        return None;
    }

    // Walk backwards from the end of `before` to find a literal run.
    // Stop at regex metacharacters.
    let meta_chars = &[
        '\\', '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$',
    ];
    let literal_start = before
        .rfind(|c: char| meta_chars.contains(&c))
        .map_or(0, |pos| pos + 1);

    let trailing = &before[literal_start..];

    // If the trailing segment is long enough, use it directly.
    if trailing.len() >= 3 {
        return Some(trailing.to_string());
    }

    // Trailing segment is too short (e.g. " " from `user .* <HOST>`).
    // Search the whole prefix for a longer literal segment.
    if let Some(longer) = extract_longest_literal(before) {
        return Some(longer);
    }

    // Fall back to short trailing segment (still better than nothing).
    if !trailing.is_empty() {
        return Some(trailing.to_string());
    }

    None
}

/// Find the longest contiguous literal (no metacharacters) segment in `s`.
fn extract_longest_literal(s: &str) -> Option<String> {
    let meta_chars = &[
        '\\', '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$',
    ];
    let mut best = "";
    let mut current_start = 0;

    for (i, c) in s.char_indices() {
        if meta_chars.contains(&c) {
            let segment = &s[current_start..i];
            if segment.len() > best.len() {
                best = segment;
            }
            current_start = i + c.len_utf8();
        }
    }
    // Check the last segment
    let segment = &s[current_start..];
    if segment.len() > best.len() {
        best = segment;
    }

    if best.len() >= 3 {
        Some(best.to_string())
    } else {
        None
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod tests {
    use crate::detect::pattern::{HostExtractor, expand_host, host_extractor, literal_prefix};

    #[test]
    fn expand_host_ipv4() {
        let expanded = expand_host(r"Failed password for .* from <HOST>").unwrap();
        assert!(expanded.contains("(?P<host>"));
        assert!(!expanded.contains("<HOST>"));
        // Verify the expanded regex compiles
        regex::Regex::new(&expanded).unwrap();
    }

    #[test]
    fn expand_host_with_regex() {
        let expanded =
            expand_host(r"sshd\[\d+\]: Failed password for .* from <HOST> port").unwrap();
        let re = regex::Regex::new(&expanded).unwrap();
        assert!(re.is_match("sshd[1234]: Failed password for root from 192.168.1.100 port"));
    }

    #[test]
    fn expand_host_ipv6() {
        let expanded = expand_host(r"from <HOST>").unwrap();
        let re = regex::Regex::new(&expanded).unwrap();
        assert!(re.is_match("from 2001:db8::1"));
    }

    #[test]
    fn expand_host_missing() {
        let result = expand_host(r"no host placeholder here");
        assert!(result.is_err());
    }

    #[test]
    fn expand_host_multiple() {
        let result = expand_host(r"<HOST> and <HOST>");
        assert!(result.is_err());
    }

    #[test]
    fn literal_prefix_ssh() {
        let prefix = literal_prefix(r"sshd\[\d+\]: Failed password for .* from <HOST>");
        // Should extract " from " — the longest literal before <HOST>
        let p = prefix.unwrap();
        assert!(p.contains("from ") || p.contains(" from"), "got: {p}");
    }

    #[test]
    fn literal_prefix_simple() {
        let prefix = literal_prefix(r"Connection refused from <HOST>");
        assert_eq!(prefix, Some("Connection refused from ".to_string()));
    }

    #[test]
    fn literal_prefix_none() {
        // Pattern starts with <HOST> — no usable prefix
        let prefix = literal_prefix(r"<HOST> did something");
        assert!(prefix.is_none());
    }

    #[test]
    fn literal_prefix_short() {
        // Prefix too short (< 3 chars)
        let prefix = literal_prefix(r".*<HOST>");
        assert!(prefix.is_none());
    }

    #[test]
    fn literal_prefix_dot_treated_as_meta() {
        // Dot is a regex metacharacter — should split literal segments.
        let prefix = literal_prefix(r"prefix.thing from <HOST>");
        // "prefix" is 6 chars, "thing from " is 11 chars.
        // Dot splits them; "thing from " should be chosen as the longer segment.
        let p = prefix.unwrap();
        assert!(
            p.contains("thing from "),
            "dot should split segments; got: {p}"
        );
    }

    #[test]
    fn expand_host_empty_pattern() {
        let result = expand_host("");
        assert!(result.is_err());
    }

    #[test]
    fn literal_prefix_all_metacharacters() {
        let prefix = literal_prefix(r".*\d+\[\d+\]<HOST>");
        // All chars before <HOST> are metachar or escape sequences — no 3-char literal.
        assert!(prefix.is_none());
    }

    #[test]
    fn literal_prefix_boundary_three_chars() {
        // Exactly 3 chars — the minimum for extract_longest_literal.
        let prefix = literal_prefix(r".*abc<HOST>");
        assert_eq!(prefix, Some("abc".to_string()));
    }

    #[test]
    fn literal_prefix_boundary_two_chars() {
        // 2-char trailing literal after metachar — still returned since the
        // main path doesn't apply the 3-char minimum (only extract_longest_literal does).
        let prefix = literal_prefix(r".*ab<HOST>");
        assert_eq!(prefix, Some("ab".to_string()));
    }

    #[test]
    fn literal_prefix_fallback_too_short() {
        // When the trailing literal is empty, we fall through to extract_longest_literal
        // which requires >= 3 chars. All segments here are < 3 chars.
        let prefix = literal_prefix(r".*a\d+b\w+<HOST>");
        // "a" and "b" are 1 char each — both below the 3-char minimum in extract_longest_literal.
        assert!(prefix.is_none());
    }

    // ---------------------------------------------------------------------------
    // host_extractor selection
    // ---------------------------------------------------------------------------

    #[test]
    fn extractor_at_start_bare() {
        assert!(matches!(
            host_extractor(r"<HOST> - - \["),
            HostExtractor::AtStart
        ));
    }

    #[test]
    fn extractor_at_start_with_caret() {
        assert!(matches!(
            host_extractor(r"^<HOST> .*"),
            HostExtractor::AtStart
        ));
    }

    #[test]
    fn extractor_after_literal() {
        match host_extractor(r"from <HOST> port") {
            HostExtractor::AfterLiteral(lit) => assert_eq!(lit, "from "),
            other => panic!("expected AfterLiteral, got {other:?}"),
        }
    }

    #[test]
    fn extractor_after_literal_with_regex_prefix() {
        // `sshd\[\d+\]: .* from <HOST>` — trailing literal is " from ".
        match host_extractor(r"sshd\[\d+\]: .* from <HOST>") {
            HostExtractor::AfterLiteral(lit) => assert!(
                lit.contains("from "),
                "expected literal containing 'from ', got '{lit}'"
            ),
            other => panic!("expected AfterLiteral, got {other:?}"),
        }
    }

    #[test]
    fn extractor_before_literal() {
        // `user .* <HOST> port` — literal before HOST is " " (1 char, too short),
        // so it falls through to literal after HOST: " port".
        match host_extractor(r"user .* <HOST> port \d+") {
            HostExtractor::BeforeLiteral(lit) => assert_eq!(lit, " port "),
            other => panic!("expected BeforeLiteral, got {other:?}"),
        }
    }

    #[test]
    fn extractor_before_literal_real_sshd() {
        match host_extractor(
            r"sshd\[\d+\]: Connection closed by authenticating user .* <HOST> port \d+",
        ) {
            HostExtractor::BeforeLiteral(lit) => assert_eq!(lit, " port "),
            other => panic!("expected BeforeLiteral, got {other:?}"),
        }
    }

    #[test]
    fn extractor_captures_fallback() {
        // Both literals too short: `\d+ <HOST> \d+` → before=" " after=" ".
        assert!(matches!(
            host_extractor(r"\d+ <HOST> \d+"),
            HostExtractor::Captures
        ));
    }

    #[test]
    fn extractor_after_literal_repeated_keyword() {
        // `from .* from <HOST>` — the literal " from " only appears once in
        // the pattern prefix (the earlier "from" lacks a leading space).
        // AfterLiteral is safe because extract_ip_after_literal's retry loop
        // skips occurrences not followed by a valid IP.
        match host_extractor(r"from .* from <HOST> port \d+") {
            HostExtractor::AfterLiteral(lit) => assert_eq!(lit, " from "),
            other => panic!("expected AfterLiteral, got {other:?}"),
        }
    }

    #[test]
    fn extractor_bracket_encapsulated() {
        // `\[<HOST>\]` — literal before is empty (metachar boundary),
        // literal after is empty (metachar `\]`). Both too short → Captures.
        assert!(matches!(
            host_extractor(r"\[<HOST>\]"),
            HostExtractor::Captures
        ));
    }

    #[test]
    fn extractor_no_host_tag() {
        // Missing <HOST> — should return Captures (graceful fallback).
        assert!(matches!(
            host_extractor(r"no host here"),
            HostExtractor::Captures
        ));
    }
}
