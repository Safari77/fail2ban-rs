//! Log line timestamp parsing.
//!
//! Supports four explicit date format presets. No auto-detection — the format
//! must be specified in the jail config. ISO 8601 uses a zero-alloc byte
//! scanner; other formats fall back to regex + chrono.

use chrono::{NaiveDateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Supported date format presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DateFormat {
    /// Syslog: `Jan 15 10:30:00` (no year — assumes current year)
    Syslog,
    /// ISO 8601: `2024-01-15T10:30:00Z` or `2024-01-15T10:30:00+00:00`
    Iso8601,
    /// Unix epoch seconds: `1705312200`
    Epoch,
    /// Common log format: `15/Jan/2024:10:30:00 +0000`
    Common,
}

/// Parser that extracts timestamps from log lines.
pub struct DateParser {
    format: DateFormat,
    /// Regex for syslog/epoch/common formats. Unused for ISO 8601.
    regex: Option<Regex>,
}

impl DateParser {
    /// Create a parser for the given format.
    pub fn new(format: DateFormat) -> Result<Self> {
        // ISO 8601 uses zero-alloc byte scanning — no regex needed.
        let regex = if format == DateFormat::Iso8601 {
            None
        } else {
            let pattern = match format {
                DateFormat::Syslog => r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})",
                DateFormat::Epoch => r"(\d{10,})",
                DateFormat::Common => r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})",
                DateFormat::Iso8601 => unreachable!(),
            };
            Some(Regex::new(pattern).map_err(|e| Error::Regex {
                pattern: pattern.to_string(),
                source: e,
            })?)
        };
        Ok(Self { format, regex })
    }

    /// Parse a log line and extract a unix timestamp.
    pub fn parse_line(&self, line: &str) -> Option<i64> {
        if self.format == DateFormat::Iso8601 {
            scan_iso8601(line.as_bytes())
        } else {
            let caps = self.regex.as_ref()?.captures(line)?;
            match self.format {
                DateFormat::Syslog => parse_syslog(&caps),
                DateFormat::Epoch => parse_epoch(&caps),
                DateFormat::Common => parse_common(&caps),
                DateFormat::Iso8601 => unreachable!(),
            }
        }
    }
}

fn parse_syslog(caps: &regex::Captures<'_>) -> Option<i64> {
    let month_str = caps.get(1)?.as_str();
    let day: u32 = caps.get(2)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(3)?.as_str().parse().ok()?;
    let min: u32 = caps.get(4)?.as_str().parse().ok()?;
    let sec: u32 = caps.get(5)?.as_str().parse().ok()?;
    let month = month_from_abbr(month_str)?;
    let year = Utc::now().format("%Y").to_string().parse::<i32>().ok()?;
    let dt = NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month, day)?,
        chrono::NaiveTime::from_hms_opt(hour, min, sec)?,
    );
    Some(dt.and_utc().timestamp())
}

fn parse_epoch(caps: &regex::Captures<'_>) -> Option<i64> {
    caps.get(1)?.as_str().parse::<i64>().ok()
}

fn parse_common(caps: &regex::Captures<'_>) -> Option<i64> {
    let day: u32 = caps.get(1)?.as_str().parse().ok()?;
    let month_str = caps.get(2)?.as_str();
    let year: i32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let min: u32 = caps.get(5)?.as_str().parse().ok()?;
    let sec: u32 = caps.get(6)?.as_str().parse().ok()?;
    let month = month_from_abbr(month_str)?;
    let dt = NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month, day)?,
        chrono::NaiveTime::from_hms_opt(hour, min, sec)?,
    );
    Some(dt.and_utc().timestamp())
}

// ---------------------------------------------------------------------------
// Fast ISO 8601 parsing — zero allocation, no regex, no chrono.
// ---------------------------------------------------------------------------

/// Scan bytes for an ISO 8601 timestamp (`YYYY-MM-DDThh:mm:ss`).
///
/// Checks position 0 first (the common case), then scans forward.
fn scan_iso8601(b: &[u8]) -> Option<i64> {
    if b.len() < 19 {
        return None;
    }
    for i in 0..=b.len() - 19 {
        let Some(window) = b.get(i..i + 19) else {
            continue;
        };
        // SAFETY of indexing: window is exactly 19 bytes from the .get() above.
        #[allow(clippy::indexing_slicing)]
        let matches_structure = window[4] == b'-'
            && window[7] == b'-'
            && (window[10] == b'T' || window[10] == b' ')
            && window[13] == b':'
            && window[16] == b':';
        if matches_structure {
            let year = parse_4(b, i)?;
            let month = parse_2(b, i + 5)?;
            let day = parse_2(b, i + 8)?;
            let hour = parse_2(b, i + 11)?;
            let min = parse_2(b, i + 14)?;
            let sec = parse_2(b, i + 17)?;
            if (1..=12).contains(&month)
                && (1..=31).contains(&day)
                && hour <= 23
                && min <= 59
                && sec <= 59
            {
                return Some(unix_timestamp(year as i32, month, day, hour, min, sec));
            }
        }
    }
    None
}

/// Parse a 2-digit decimal number from bytes.
#[inline]
fn parse_2(b: &[u8], pos: usize) -> Option<u32> {
    let d1 = (*b.get(pos)?).wrapping_sub(b'0');
    let d2 = (*b.get(pos + 1)?).wrapping_sub(b'0');
    if d1 > 9 || d2 > 9 {
        return None;
    }
    Some(u32::from(d1) * 10 + u32::from(d2))
}

/// Parse a 4-digit decimal number from bytes.
#[inline]
fn parse_4(b: &[u8], pos: usize) -> Option<u32> {
    let d1 = (*b.get(pos)?).wrapping_sub(b'0');
    let d2 = (*b.get(pos + 1)?).wrapping_sub(b'0');
    let d3 = (*b.get(pos + 2)?).wrapping_sub(b'0');
    let d4 = (*b.get(pos + 3)?).wrapping_sub(b'0');
    if d1 > 9 || d2 > 9 || d3 > 9 || d4 > 9 {
        return None;
    }
    Some(u32::from(d1) * 1000 + u32::from(d2) * 100 + u32::from(d3) * 10 + u32::from(d4))
}

/// Convert date/time components to Unix timestamp (UTC).
///
/// Uses Howard Hinnant's `civil_from_days` algorithm — pure arithmetic,
/// no branches, no loops, no allocations.
fn unix_timestamp(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> i64 {
    let y = if month <= 2 {
        i64::from(year) - 1
    } else {
        i64::from(year)
    };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = if month > 2 {
        u64::from(month) - 3
    } else {
        u64::from(month) + 9
    };
    let doy = (153 * m + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    days * 86400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec)
}

fn month_from_abbr(s: &str) -> Option<u32> {
    match s {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::detect::date::{DateFormat, DateParser};

    #[test]
    fn syslog_format() {
        let parser = DateParser::new(DateFormat::Syslog).unwrap();
        let line = "Jan 15 10:30:00 server sshd[1234]: Failed password";
        let ts = parser.parse_line(line);
        assert!(ts.is_some());
        let ts = ts.unwrap();
        assert!(ts > 0);
    }

    #[test]
    fn syslog_single_digit_day() {
        let parser = DateParser::new(DateFormat::Syslog).unwrap();
        let line = "Feb  3 08:15:22 host kernel: something";
        let ts = parser.parse_line(line);
        assert!(ts.is_some());
    }

    #[test]
    fn iso8601_format() {
        let parser = DateParser::new(DateFormat::Iso8601).unwrap();
        let line = "2024-01-15T10:30:00Z some log message";
        let ts = parser.parse_line(line).unwrap();
        assert!(ts > 0);
        // Should be consistent — parsing twice gives the same result.
        let ts2 = parser.parse_line(line).unwrap();
        assert_eq!(ts, ts2);
    }

    #[test]
    fn iso8601_space_separator() {
        let parser = DateParser::new(DateFormat::Iso8601).unwrap();
        let line = "2024-01-15 10:30:00 some log message";
        let ts = parser.parse_line(line).unwrap();
        // Should produce same result as T-separated.
        let line_t = "2024-01-15T10:30:00 some log message";
        let ts_t = parser.parse_line(line_t).unwrap();
        assert_eq!(ts, ts_t);
    }

    #[test]
    fn epoch_format() {
        let parser = DateParser::new(DateFormat::Epoch).unwrap();
        let line = "1705312200 something happened";
        let ts = parser.parse_line(line).unwrap();
        assert_eq!(ts, 1_705_312_200);
    }

    #[test]
    fn common_log_format() {
        let parser = DateParser::new(DateFormat::Common).unwrap();
        let line = r#"192.168.1.1 - - [15/Jan/2024:10:30:00 +0000] "GET / HTTP/1.1""#;
        let ts = parser.parse_line(line).unwrap();
        assert!(ts > 0);
        // Common and ISO8601 for the same date/time should match.
        let iso_parser = DateParser::new(DateFormat::Iso8601).unwrap();
        let iso_ts = iso_parser.parse_line("2024-01-15T10:30:00 log").unwrap();
        assert_eq!(ts, iso_ts);
    }

    #[test]
    fn no_match_returns_none() {
        let parser = DateParser::new(DateFormat::Iso8601).unwrap();
        let line = "this line has no date";
        assert!(parser.parse_line(line).is_none());
    }

    #[test]
    fn wrong_format_returns_none() {
        let parser = DateParser::new(DateFormat::Epoch).unwrap();
        let line = "Jan 15 10:30:00 syslog format line";
        // Epoch parser looks for 10+ digit number — "10" won't match
        assert!(parser.parse_line(line).is_none());
    }

    #[test]
    fn all_months_parse() {
        let parser = DateParser::new(DateFormat::Syslog).unwrap();
        let months = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        for month in months {
            let line = format!("{month} 15 12:00:00 test");
            assert!(
                parser.parse_line(&line).is_some(),
                "failed to parse month: {month}"
            );
        }
    }

    #[test]
    fn invalid_month_returns_none() {
        let parser = DateParser::new(DateFormat::Syslog).unwrap();
        let line = "Xyz 15 10:30:00 server test";
        assert!(parser.parse_line(line).is_none());
    }

    #[test]
    fn epoch_nine_digits_no_match() {
        let parser = DateParser::new(DateFormat::Epoch).unwrap();
        // 9-digit number should NOT match \d{10,}
        let line = "999999999 short";
        assert!(parser.parse_line(line).is_none());
    }

    #[test]
    fn epoch_ten_digits_matches() {
        let parser = DateParser::new(DateFormat::Epoch).unwrap();
        let line = "1000000000 ten digits";
        let ts = parser.parse_line(line).unwrap();
        assert_eq!(ts, 1_000_000_000);
    }

    #[test]
    fn common_invalid_month_returns_none() {
        let parser = DateParser::new(DateFormat::Common).unwrap();
        let line = r#"10.0.0.1 - - [15/Xyz/2024:10:30:00 +0000] "GET /""#;
        assert!(parser.parse_line(line).is_none());
    }

    #[test]
    fn syslog_invalid_time_returns_none() {
        let parser = DateParser::new(DateFormat::Syslog).unwrap();
        // Hour 25 — from_hms_opt returns None.
        let line = "Jan 15 25:30:00 server test";
        assert!(parser.parse_line(line).is_none());
    }
}
