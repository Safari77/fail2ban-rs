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

use crate::error::{Error, Result};
use crate::pattern::{self, HostExtractor};

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
            // Phase 1: AC pre-filter — reject lines without any known prefix.
            let ac_match = ac.find(line)?;
            let primary = self.ac_to_regex.get(ac_match.pattern().as_usize())?;

            // Phase 2: Try only regexes whose AC prefix was found (fast path).
            for &idx in primary {
                if let Some(result) = self.match_regex(idx, line) {
                    return Some(result);
                }
            }

            // Fallback: try remaining regexes in order (handles rare cases
            // where multiple AC prefixes appear in the same line, or patterns
            // without an AC prefix).
            for idx in 0..self.regexes.len() {
                if primary.contains(&idx) {
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
                host_text.parse::<IpAddr>().ok()?
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
fn try_parse_ip(token: &str) -> Option<IpAddr> {
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Some(ip);
    }
    // `10.0.0.1:8080` → try `10.0.0.1`; `2001:db8::1:443` → try `2001:db8::1`
    let colon = token.rfind(':')?;
    token.get(..colon)?.parse::<IpAddr>().ok()
}
