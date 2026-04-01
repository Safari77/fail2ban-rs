//! Fast matching engine for log lines.
//!
//! Phase 1: Aho-Corasick automaton over deduplicated literal prefixes rejects
//! non-matching lines in ~10ns.
//! Phase 2: AC-guided regex selection — only tries regexes whose literal
//! prefix was found in the line, skipping impossible patterns.
//! IP extraction uses `find()` (DFA) plus positional string ops to extract
//! the IP from the `<HOST>` location, falling back to `captures()` only for
//! patterns with ambiguous literal context.

use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::detect::pattern::{self, HostExtractor};
use crate::error::{Error, Result};

/// Result of a successful match against a log line.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// The extracted IP address.
    pub ip: IpAddr,
    /// Index of the pattern that matched.
    pub pattern_idx: usize,
}

/// Per-jail matching engine.
pub struct JailMatcher {
    /// Aho-Corasick automaton for literal prefix filtering.
    /// `None` if no patterns have usable literal prefixes.
    ac: Option<AhoCorasick>,
    /// Individual compiled regexes (with `<HOST>` expanded).
    regexes: Vec<Regex>,
    /// Per-pattern extraction strategy.
    extractors: Vec<HostExtractor>,
    /// Compiled ignoreregex patterns — matched lines are suppressed.
    ignore_regexes: Vec<Regex>,
    /// Maps each AC pattern slot → regex indices to try. Deduplicated:
    /// patterns sharing the same literal prefix are grouped under one slot.
    ac_to_regex: Vec<Vec<usize>>,
}

impl JailMatcher {
    /// Build a matcher from user-facing patterns (containing `<HOST>`).
    pub fn new(patterns: &[String]) -> Result<Self> {
        if patterns.is_empty() {
            return Err(Error::config("no patterns provided"));
        }

        // Expand <HOST> in all patterns.
        let expanded: Vec<String> = patterns
            .iter()
            .map(|p| pattern::expand_host(p))
            .collect::<Result<Vec<_>>>()?;

        // Build individual regexes.
        let regexes: Vec<Regex> = expanded
            .iter()
            .zip(patterns.iter())
            .map(|(p, orig)| {
                Regex::new(p).map_err(|e| Error::Regex {
                    pattern: orig.clone(),
                    source: e,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Determine extraction strategy for each pattern.
        let extractors: Vec<HostExtractor> = patterns
            .iter()
            .map(|p| pattern::host_extractor(p))
            .collect();

        // Extract and deduplicate literal prefixes for Aho-Corasick.
        // Patterns sharing the same prefix are grouped under one AC slot.
        let mut unique_prefixes: Vec<String> = Vec::new();
        let mut ac_to_regex: Vec<Vec<usize>> = Vec::new();

        for (i, p) in patterns.iter().enumerate() {
            if let Some(prefix) = pattern::literal_prefix(p) {
                if let Some(pos) = unique_prefixes.iter().position(|x| x == &prefix) {
                    if let Some(group) = ac_to_regex.get_mut(pos) {
                        group.push(i);
                    }
                } else {
                    unique_prefixes.push(prefix);
                    ac_to_regex.push(vec![i]);
                }
            }
        }

        let ac = if unique_prefixes.is_empty() {
            None
        } else {
            let automaton = AhoCorasick::new(&unique_prefixes).map_err(|e| {
                Error::config(format!("failed to build Aho-Corasick automaton: {e}"))
            })?;
            Some(automaton)
        };

        Ok(Self {
            ac,
            regexes,
            extractors,
            ignore_regexes: Vec::new(),
            ac_to_regex,
        })
    }

    /// Build a matcher with both fail patterns and ignore patterns.
    pub fn with_ignoreregex(patterns: &[String], ignoreregex: &[String]) -> Result<Self> {
        let mut matcher = Self::new(patterns)?;
        for (i, pat) in ignoreregex.iter().enumerate() {
            let re = Regex::new(pat).map_err(|e| Error::Regex {
                pattern: format!("ignoreregex[{i}]: {pat}"),
                source: e,
            })?;
            matcher.ignore_regexes.push(re);
        }
        Ok(matcher)
    }

    /// Try to match a log line, returning the extracted IP and pattern index.
    ///
    /// Returns `None` if the line doesn't match any fail pattern, or if it
    /// matches an ignoreregex pattern.
    pub fn try_match(&self, line: &str) -> Option<MatchResult> {
        if let Some(ref ac) = self.ac {
            if let Some(ac_match) = ac.find(line)
                && let Some(primary) = self.ac_to_regex.get(ac_match.pattern().as_usize())
            {
                // Phase 2: Try only regexes whose AC prefix was found (fast path).
                for &idx in primary {
                    if let Some(result) = self.match_regex(idx, line) {
                        return Some(result);
                    }
                }

                // Fallback: try remaining regexes in order (handles cases
                // where multiple AC prefixes appear in the same line, or
                // patterns without an AC prefix).
                for idx in 0..self.regexes.len() {
                    if primary.contains(&idx) {
                        continue;
                    }
                    if let Some(result) = self.match_regex(idx, line) {
                        return Some(result);
                    }
                }

                return None;
            }

            // AC found no known prefix — still try patterns that have no AC
            // entry (they were never added to the automaton, so AC can't
            // filter them). Skip patterns that DO have an AC entry, since the
            // line clearly doesn't contain their required literal.
            let ac_indexed: Vec<usize> = self.ac_to_regex.iter().flatten().copied().collect();
            for idx in 0..self.regexes.len() {
                if ac_indexed.contains(&idx) {
                    continue;
                }
                if let Some(result) = self.match_regex(idx, line) {
                    return Some(result);
                }
            }
            None
        } else {
            // No AC automaton — try all regexes sequentially.
            for idx in 0..self.regexes.len() {
                if let Some(result) = self.match_regex(idx, line) {
                    return Some(result);
                }
            }
            None
        }
    }

    /// Try a single regex against `line`.
    ///
    /// Fast path: `find()` (DFA) for match/reject, then positional string
    /// ops to extract the IP from the `<HOST>` location in the match span.
    /// Slow path: `captures()` for patterns with ambiguous literal context.
    fn match_regex(&self, idx: usize, line: &str) -> Option<MatchResult> {
        let regex = self.regexes.get(idx)?;
        let extractor = self.extractors.get(idx)?;

        let ip = match extractor {
            HostExtractor::AtStart => {
                let m = regex.find(line)?;
                extract_ip_at_start(m.as_str())?
            }
            HostExtractor::AfterLiteral(lit) => {
                let m = regex.find(line)?;
                extract_ip_after_literal(m.as_str(), lit)?
            }
            HostExtractor::BeforeLiteral(lit) => {
                let m = regex.find(line)?;
                extract_ip_before_literal(m.as_str(), lit)?
            }
            HostExtractor::Captures => {
                let caps = regex.captures(line)?;
                let host_text = caps.name("host")?.as_str();
                let ip = host_text.parse::<IpAddr>().ok()?;
                normalize_mapped(ip)
            }
        };

        if self.ignore_regexes.iter().any(|re| re.is_match(line)) {
            return None;
        }

        Some(MatchResult {
            ip,
            pattern_idx: idx,
        })
    }

    /// Number of patterns in this matcher.
    pub fn pattern_count(&self) -> usize {
        self.regexes.len()
    }
}

/// Extract an IP from the start of a match span.
fn extract_ip_at_start(span: &str) -> Option<IpAddr> {
    let end = span
        .find(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':')
        .unwrap_or(span.len());
    let token = span.get(..end).filter(|t| t.len() >= 2)?;
    try_parse_ip(token)
}

/// Extract an IP that follows `literal` in the match span.
///
/// If the literal appears multiple times, tries each occurrence until one
/// is followed by a valid IP address.
fn extract_ip_after_literal(span: &str, literal: &str) -> Option<IpAddr> {
    let mut pos = 0;
    while let Some(found) = span.get(pos..)?.find(literal) {
        let ip_start = pos + found + literal.len();
        if let Some(ip) = parse_ip_at(span, ip_start) {
            return Some(ip);
        }
        pos += found + 1;
    }
    None
}

/// Extract the rightmost IP token immediately before `literal` in the span.
fn extract_ip_before_literal(span: &str, literal: &str) -> Option<IpAddr> {
    let lit_pos = span.find(literal)?;
    let before = span.get(..lit_pos)?;
    // Scan right-to-left: the token closest to the literal is the HOST IP.
    for token in before.rsplit(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':') {
        if token.len() >= 2
            && let Some(ip) = try_parse_ip(token)
        {
            return Some(ip);
        }
    }
    None
}

/// Parse an IP-like token starting at byte offset `start` in `span`.
fn parse_ip_at(span: &str, start: usize) -> Option<IpAddr> {
    let remaining = span.get(start..)?;
    let end = remaining
        .find(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':')
        .unwrap_or(remaining.len());
    let token = remaining.get(..end).filter(|t| t.len() >= 2)?;
    try_parse_ip(token)
}

/// Try to parse an IP from a token that may include a trailing port
/// (e.g. `10.0.0.1:8080` or `2001:db8::1:443`).
///
/// The scan includes `:` to support IPv6, but this means `IPv4:port` tokens
/// are captured as one string. If the full token fails, split at the last `:`
/// and try the prefix — it handles both `IPv4:port` and `IPv6:port`.
///
/// IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) are normalized to their
/// IPv4 form so that firewall rules target the correct address family.
fn try_parse_ip(token: &str) -> Option<IpAddr> {
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Some(normalize_mapped(ip));
    }
    // Strip trailing `:port` or `:port:` suffixes iteratively.
    // Handles `10.0.0.1:8080`, `192.168.0.1:29530:`, `2001:db8::1:443`.
    let mut s = token;
    while let Some(colon) = s.rfind(':') {
        s = &s[..colon];
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Some(normalize_mapped(ip));
        }
    }
    None
}

/// Normalize IPv4-mapped IPv6 addresses (e.g. `::ffff:192.168.1.1`) to
/// plain IPv4. Many services log client addresses in this form; banning
/// the IPv6 representation would miss the actual IPv4 traffic.
fn normalize_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::detect::matcher::JailMatcher;

    fn ssh_patterns() -> Vec<String> {
        vec![
            r"sshd\[\d+\]: Failed password for .* from <HOST>".to_string(),
            r"sshd\[\d+\]: Invalid user .* from <HOST>".to_string(),
        ]
    }

    #[test]
    fn match_failed_password() {
        let m = JailMatcher::new(&ssh_patterns()).unwrap();
        let line = "Jan 15 10:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2";
        let result = m.try_match(line).unwrap();
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(result.pattern_idx, 0);
    }

    #[test]
    fn match_invalid_user() {
        let m = JailMatcher::new(&ssh_patterns()).unwrap();
        let line =
            "Jan 15 10:30:00 server sshd[5678]: Invalid user admin from 10.0.0.50 port 22 ssh2";
        let result = m.try_match(line).unwrap();
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)));
        assert_eq!(result.pattern_idx, 1);
    }

    #[test]
    fn no_match_normal_log() {
        let m = JailMatcher::new(&ssh_patterns()).unwrap();
        let line = "Jan 15 10:30:00 server sshd[1234]: Accepted password for user from 192.168.1.1 port 22";
        assert!(m.try_match(line).is_none());
    }

    #[test]
    fn no_match_unrelated() {
        let m = JailMatcher::new(&ssh_patterns()).unwrap();
        let line = "Jan 15 10:30:00 server kernel: CPU0: Core temperature above threshold";
        assert!(m.try_match(line).is_none());
    }

    #[test]
    fn match_ipv6() {
        let patterns = vec![r"from <HOST> port".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "from 2001:db8::1 port 22";
        let result = m.try_match(line).unwrap();
        let expected: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(result.ip, expected);
    }

    #[test]
    fn multiple_patterns_first_wins() {
        let patterns = vec![
            r"Failed .* from <HOST>".to_string(),
            r"from <HOST>".to_string(),
        ];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "Failed login from 1.2.3.4";
        let result = m.try_match(line).unwrap();
        assert_eq!(result.pattern_idx, 0);
    }

    #[test]
    fn empty_patterns_error() {
        assert!(JailMatcher::new(&[]).is_err());
    }

    #[test]
    fn pattern_count() {
        let m = JailMatcher::new(&ssh_patterns()).unwrap();
        assert_eq!(m.pattern_count(), 2);
    }

    #[test]
    fn various_ipv4() {
        let patterns = vec![r"from <HOST>".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();

        let ips = ["1.1.1.1", "255.255.255.255", "10.0.0.1", "172.16.0.1"];
        for ip_str in &ips {
            let line = format!("from {ip_str} something");
            let result = m.try_match(&line);
            assert!(result.is_some(), "failed to match IP: {ip_str}");
            assert_eq!(result.unwrap().ip, ip_str.parse::<IpAddr>().unwrap());
        }
    }

    #[test]
    fn invalid_ip_returns_none() {
        // 999.999.999.999 matches the regex \d{1,3}... but fails IpAddr::parse.
        let patterns = vec![r"from <HOST> port".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "from 999.999.999.999 port 22";
        // The regex matches but the IP is unparseable — should return None.
        assert!(m.try_match(line).is_none());
    }

    #[test]
    fn no_ac_prefix_still_matches() {
        // Pattern starts with regex metachar — no usable AC prefix.
        let patterns = vec![r"\d+ failures from <HOST>".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "5 failures from 10.0.0.1 end";
        let result = m.try_match(line).unwrap();
        assert_eq!(result.ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ac_passes_but_regex_fails() {
        // The literal prefix "from " appears but the full regex doesn't match.
        let patterns = vec![r"Failed .* from <HOST> port \d+".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        // "from " is present but "Failed" is not.
        let line = "Accepted from 1.2.3.4 port 22";
        assert!(m.try_match(line).is_none());
    }

    #[test]
    fn empty_line() {
        let m = JailMatcher::new(&ssh_patterns()).unwrap();
        assert!(m.try_match("").is_none());
    }

    // ---------------------------------------------------------------------------
    // IP extraction without surrounding whitespace (issue #1)
    // ---------------------------------------------------------------------------

    #[test]
    fn host_in_brackets_no_spaces() {
        // Exact reproduction from issue #1: postfix log with IP in brackets, no spaces.
        let patterns = vec![r"connect from .*\.internet-measurement\.com\[<HOST>\]".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "postfix/smtpd[327792]: connect from imperative.monitoring.internet-measurement.com[185.247.137.113]";
        let result = m
            .try_match(line)
            .expect("should match IP in brackets without spaces");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(185, 247, 137, 113)));
    }

    #[test]
    fn host_in_brackets_with_spaces_still_works() {
        // The original working case from issue #1 — must not regress.
        let patterns = vec![r"connect from .*\.internet-measurement\.com\[ <HOST> \]".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "postfix/smtpd[327792]: connect from imperative.monitoring.internet-measurement.com[ 185.247.137.113 ]";
        let result = m
            .try_match(line)
            .expect("should match IP in brackets with spaces");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(185, 247, 137, 113)));
    }

    #[test]
    fn host_in_parens_no_spaces() {
        let patterns = vec![r"blocked \(<HOST>\)".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "blocked (10.0.0.1)";
        let result = m.try_match(line).expect("should match IP in parens");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn host_ipv6_in_brackets_no_spaces() {
        let patterns = vec![r"from \[<HOST>\]".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "from [2001:db8::1]";
        let result = m.try_match(line).expect("should match IPv6 in brackets");
        assert_eq!(result.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    // ---------------------------------------------------------------------------
    // Issue #6: positional IP extraction — every extractor path + edge cases
    // ---------------------------------------------------------------------------

    // --- AtStart extractor: <HOST> at position 0 or after ^ ----------------------

    #[test]
    fn at_start_extracts_first_ip_ignoring_url_ip() {
        // Reporter's exact reproduction case from issue #6.
        let patterns = vec![r#"^<HOST> .* "(GET|POST) .* HTTP/\d\.\d" 444"#.to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = r#"14.225.18.20 - - [25/Mar/2026:09:37:18 +0000] "POST http://161.5.6.7/hello.world HTTP/1.1" 444 0"#;
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(14, 225, 18, 20)));
    }

    #[test]
    fn at_start_no_other_ips() {
        let patterns = vec![r#"^<HOST> .* "(GET|POST) .* HTTP/\d\.\d" 444"#.to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line =
            r#"14.225.18.20 - - [25/Mar/2026:09:37:18 +0000] "GET /robots.txt HTTP/1.1" 444 0"#;
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(14, 225, 18, 20)));
    }

    #[test]
    fn at_start_ipv6() {
        let patterns = vec![r"^<HOST> denied".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "2001:db8::1 denied";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn at_start_without_caret() {
        // <HOST> at position 0, no ^ anchor — still AtStart.
        let patterns = vec![r"<HOST> - - \[".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "10.0.0.1 - - [25/Mar/2026:09:37:18 +0000]";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn at_start_multiple_ips_in_url_and_header() {
        // Three IPs total: HOST at start, one in URL, one in referrer.
        let patterns = vec![r#"^<HOST> .* HTTP/\d\.\d" 444"#.to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = r#"14.225.18.20 - - [25/Mar/2026:09:37:18 +0000] "GET http://161.5.6.7/ref=10.10.10.10 HTTP/1.1" 444 0"#;
        let result = m.try_match(line).expect("should match");
        assert_eq!(
            result.ip,
            IpAddr::V4(Ipv4Addr::new(14, 225, 18, 20)),
            "must pick the HOST IP, not one of the IPs in the URL"
        );
    }

    // --- AfterLiteral extractor: literal before <HOST> ---------------------------

    #[test]
    fn after_literal_simple() {
        let patterns = vec![r"from <HOST> port".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "Failed login from 10.0.0.1 port 22";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn after_literal_with_trailing_ip() {
        // <HOST> after "from ", but a second IP appears later in the match span.
        let patterns = vec![r"from <HOST> port \d+ .* to \d+\.\d+\.\d+\.\d+".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "Failed from 10.0.0.1 port 22 forwarded to 192.168.1.1";
        let result = m.try_match(line).expect("should match");
        assert_eq!(
            result.ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "must extract the <HOST> IP, not the trailing IP"
        );
    }

    #[test]
    fn after_literal_with_preceding_ip_in_line() {
        // An IP appears earlier in the line (outside the match), HOST in middle.
        let patterns = vec![r"sshd\[\d+\]: Failed .* from <HOST>".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "192.168.1.1 server sshd[1234]: Failed password for root from 10.0.0.50 port 22";
        let result = m.try_match(line).expect("should match");
        assert_eq!(
            result.ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
            "must not confuse the server IP at the start of the line with the HOST"
        );
    }

    #[test]
    fn after_literal_ipv6() {
        let patterns = vec![r"from <HOST> port".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "from 2001:db8::ff port 22";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, "2001:db8::ff".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn after_literal_encapsulated_in_brackets() {
        // IP in brackets with literal "from" resolved via AfterLiteral
        // because the escaped `\[` before HOST is a metachar boundary, leaving
        // only the text before that as a potential literal.
        let patterns = vec![r"connect from .*\[<HOST>\]".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "connect from evil.example.com[185.247.137.113]";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(185, 247, 137, 113)));
    }

    #[test]
    fn after_literal_host_ip_same_as_trailing_ip() {
        // Both IPs in the line are identical — must still return one.
        let patterns = vec![r"from <HOST> proxy \d+\.\d+\.\d+\.\d+".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "from 10.0.0.1 proxy 10.0.0.1";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn after_literal_literal_appears_twice_but_only_second_has_ip() {
        // "from " appears in the text before the match point but the
        // extract_ip_after_literal retry loop should skip the non-IP occurrence.
        let patterns = vec![r"rejected from <HOST> port".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        // The literal " from " appears after "rejected" which is the correct one.
        let line = "rejected from 10.0.0.1 port 22";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    // --- BeforeLiteral extractor: literal after <HOST> ---------------------------

    #[test]
    fn before_literal_conn_closed() {
        // The real sshd pattern that triggers BeforeLiteral: `user .* <HOST> port`
        // — only a single space before HOST (too short), but " port" after.
        let patterns = vec![
            r"sshd\[\d+\]: Connection closed by authenticating user .* <HOST> port".to_string(),
        ];
        let m = JailMatcher::new(&patterns).unwrap();
        let line =
            "sshd[1234]: Connection closed by authenticating user root 103.174.103.249 port 58414";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(103, 174, 103, 249)));
    }

    #[test]
    fn before_literal_with_earlier_ip_in_span() {
        // Match span contains an IP before HOST — BeforeLiteral must pick the
        // one closest (rightmost) to the literal, which is the HOST IP.
        let patterns = vec![
            r"sshd\[\d+\]: Connection closed by authenticating user .* <HOST> port".to_string(),
        ];
        let m = JailMatcher::new(&patterns).unwrap();
        // 10.0.0.1 appears in the username field (unusual but valid); HOST is 5.6.7.8.
        let line = "sshd[1234]: Connection closed by authenticating user 10.0.0.1 5.6.7.8 port 22";
        let result = m.try_match(line).expect("should match");
        assert_eq!(
            result.ip,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            "must pick the IP closest to ' port', not an earlier one"
        );
    }

    #[test]
    fn before_literal_ipv6() {
        let patterns = vec![r"user .* <HOST> port".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "user root 2001:db8::1 port 22";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn before_literal_disconnected_pattern() {
        // Another real sshd pattern that lands on BeforeLiteral.
        let patterns =
            vec![r"sshd\[\d+\]: Disconnected from authenticating user .* <HOST> port".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line =
            "sshd[5678]: Disconnected from authenticating user admin 176.120.22.47 port 27094";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(176, 120, 22, 47)));
    }

    // --- Captures fallback -------------------------------------------------------

    #[test]
    fn captures_fallback_short_literals() {
        // Both before and after literals are < 2 chars — falls back to captures().
        // Pattern: `\d+ <HOST> \d+` — literal before = " " (1 char), after = " " (1 char).
        let patterns = vec![r"\d+ <HOST> \d+".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "42 10.0.0.1 99";
        let result = m
            .try_match(line)
            .expect("should match via captures fallback");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn captures_fallback_with_other_ips_in_line() {
        // Captures fallback must still extract the correct HOST IP when other
        // IPs are present.  Pattern uses `\(` and `\)` which are metachar
        // boundaries — no usable literal before or after HOST → Captures path.
        let patterns = vec![r"\(<HOST>\) .* \d+\.\d+\.\d+\.\d+".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "(10.0.0.1) gateway 192.168.1.1";
        let result = m
            .try_match(line)
            .expect("should match via captures fallback");
        assert_eq!(
            result.ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "captures() must extract the exact <HOST> group, not the gateway IP"
        );
    }

    // --- Multi-IP stress tests (extractor-agnostic) ------------------------------

    #[test]
    fn three_ips_host_is_first() {
        // HOST is the first IP; two more follow.
        let patterns =
            vec![r"from <HOST> via \d+\.\d+\.\d+\.\d+ gw \d+\.\d+\.\d+\.\d+".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "from 1.1.1.1 via 2.2.2.2 gw 3.3.3.3";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn three_ips_host_is_middle() {
        // HOST sandwiched between two other IPs.
        let patterns =
            vec![r"src \d+\.\d+\.\d+\.\d+ from <HOST> dst \d+\.\d+\.\d+\.\d+".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "src 1.1.1.1 from 2.2.2.2 dst 3.3.3.3";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));
    }

    #[test]
    fn two_ips_host_is_last() {
        // HOST is the second IP; the first is a literal in the pattern context.
        let patterns = vec![r"proxy \d+\.\d+\.\d+\.\d+ client <HOST>".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "proxy 10.0.0.1 client 5.6.7.8 end";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
    }

    #[test]
    fn duplicate_ip_values_in_line() {
        // The same IP value appears for HOST and in another position —
        // must still return successfully.
        let patterns = vec![r"from <HOST> to \d+\.\d+\.\d+\.\d+".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "from 10.0.0.1 to 10.0.0.1";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    // --- IPv4-mapped IPv6 (::ffff:) normalization --------------------------------

    #[test]
    fn ipv4_mapped_in_brackets() {
        let patterns = vec![r"ip=\[<HOST>\]".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "ip=[::ffff:1.2.3.4]";
        let result = m
            .try_match(line)
            .expect("should match ::ffff: mapped address");
        assert_eq!(
            result.ip,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            "::ffff: mapped address should normalize to IPv4"
        );
    }

    #[test]
    fn ipv4_mapped_after_literal() {
        let patterns = vec![r"rhost=<HOST>".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "authentication failure; rhost=::ffff:192.168.1.1";
        let result = m
            .try_match(line)
            .expect("should match ::ffff: after literal");
        assert_eq!(
            result.ip,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            "::ffff: mapped address should normalize to IPv4"
        );
    }

    #[test]
    fn ipv4_mapped_uppercase_ffff() {
        let patterns = vec![r"from \[<HOST>\]".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "from [::FFFF:10.0.0.1]";
        let result = m.try_match(line).expect("should match ::FFFF: uppercase");
        assert_eq!(
            result.ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "::FFFF: uppercase should normalize to IPv4"
        );
    }

    #[test]
    fn plain_ipv6_not_normalized() {
        let patterns = vec![r"from <HOST> port".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "from 2001:db8::1 port 22";
        let result = m.try_match(line).expect("should match plain IPv6");
        assert_eq!(
            result.ip,
            "2001:db8::1".parse::<IpAddr>().unwrap(),
            "plain IPv6 should NOT be normalized to IPv4"
        );
    }

    // --- Encapsulated/delimited IPs ----------------------------------------------

    #[test]
    fn host_in_square_brackets() {
        let patterns = vec![r"client \[<HOST>\]".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "client [10.0.0.1] connected";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn host_in_angle_brackets() {
        let patterns = vec![r"relay <HOST>>".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "relay 10.0.0.1>";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn host_in_parens_with_other_ip_outside() {
        let patterns = vec![r"denied \(<HOST>\) gw \d+\.\d+\.\d+\.\d+".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "denied (5.6.7.8) gw 10.0.0.1";
        let result = m.try_match(line).expect("should match");
        assert_eq!(
            result.ip,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            "must extract IP in parens, not the gateway IP"
        );
    }

    #[test]
    fn host_colon_port_delimiter() {
        // IP followed by `:port` — the colon is an IP char for IPv6,
        // but the host regex \d{1,3}.\d{1,3}... stops before non-matching chars.
        let patterns = vec![r"client <HOST>:\d+ denied".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "client 10.0.0.1:8080 denied";
        let result = m.try_match(line).expect("should match");
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn ipv6_in_brackets_with_trailing_ipv4() {
        let patterns = vec![r"from \[<HOST>\] to \d+\.\d+\.\d+\.\d+".to_string()];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "from [2001:db8::1] to 10.0.0.1";
        let result = m.try_match(line).expect("should match");
        assert_eq!(
            result.ip,
            "2001:db8::1".parse::<IpAddr>().unwrap(),
            "must extract the IPv6 HOST, not the trailing IPv4"
        );
    }

    // ---------------------------------------------------------------------------
    // ignoreregex tests
    // ---------------------------------------------------------------------------

    #[test]
    fn ignoreregex_suppresses_match() {
        let patterns = vec![r"from <HOST> port".to_string()];
        let ignore = vec![r"Accepted".to_string()];
        let m = JailMatcher::with_ignoreregex(&patterns, &ignore).unwrap();

        // Line matches failregex but also matches ignoreregex.
        let line = "Accepted login from 1.2.3.4 port 22";
        assert!(m.try_match(line).is_none());
    }

    #[test]
    fn ignoreregex_does_not_suppress_non_matching() {
        let patterns = vec![r"Failed .* from <HOST> port".to_string()];
        let ignore = vec![r"Accepted".to_string()];
        let m = JailMatcher::with_ignoreregex(&patterns, &ignore).unwrap();

        // Line matches failregex but NOT ignoreregex.
        let line = "Failed login from 1.2.3.4 port 22";
        let result = m.try_match(line).unwrap();
        assert_eq!(result.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ignoreregex_empty_is_noop() {
        let patterns = vec![r"from <HOST> port".to_string()];
        let m = JailMatcher::with_ignoreregex(&patterns, &[]).unwrap();
        let line = "from 1.2.3.4 port 22";
        assert!(m.try_match(line).is_some());
    }

    #[test]
    fn ignoreregex_multiple_patterns() {
        let patterns = vec![r"from <HOST> port".to_string()];
        let ignore = vec![r"Accepted".to_string(), r"internal".to_string()];
        let m = JailMatcher::with_ignoreregex(&patterns, &ignore).unwrap();

        // Matches second ignoreregex.
        let line = "internal from 1.2.3.4 port 22";
        assert!(m.try_match(line).is_none());

        // Doesn't match either ignoreregex.
        let line2 = "Failed from 1.2.3.4 port 22";
        assert!(m.try_match(line2).is_some());
    }

    // AC fallback: patterns without AC entries must still be tried when AC finds no match.
    #[test]
    fn ac_fallback_tries_non_ac_patterns() {
        // Pattern 1 has AC prefix "Login attempt failed from ". Pattern 2 has no AC prefix.
        // When the line doesn't contain pattern 1's prefix, pattern 2 must still be tried.
        let patterns = vec![
            r"drupal.*Login attempt failed from <HOST>".to_string(),
            r"(?:[^|]*\|){3}<HOST>\|.*Login attempt failed".to_string(),
        ];
        let m = JailMatcher::new(&patterns).unwrap();
        // This line uses "|" delimited format (no "from <HOST>"), so pattern 1 fails.
        let line = "Apr 26 13:15:25 webserver example.com: https://example.com|1430068525|user|1.2.3.4|https://example.com/?q=user|https://example.com/?q=user|0||Login attempt failed for drupaladmin.";
        let result = m
            .try_match(line)
            .expect("pattern 2 should match via AC fallback");
        assert_eq!(result.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(result.pattern_idx, 1);
    }
}
