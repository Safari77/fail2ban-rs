//! CLI regex testing tool — test patterns against log lines.

use crate::detect::matcher::JailMatcher;

/// Test a single pattern against a log line and print the result.
pub fn test_pattern(pattern: &str, line: &str) {
    let matcher = match JailMatcher::new(&[pattern.to_string()]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error compiling pattern: {e}");
            eprintln!("  Hint: <HOST> expands to an IPv4/IPv6 capture group automatically.");
            std::process::exit(1);
        }
    };

    if let Some(result) = matcher.try_match(line) {
        println!("Match found — this line would count as a failure.");
        println!();
        println!("  Extracted IP: {}", result.ip);
        println!("  Pattern:      {pattern}");
        println!("  Line:         {line}");
        println!();
        println!(
            "In production, max_retry failures from {} within find_time triggers a ban.",
            result.ip
        );
    } else {
        println!("No match — this line would be ignored.");
        println!();
        println!("  Pattern: {pattern}");
        println!("  Line:    {line}");
        println!();
        println!("Hints:");
        println!("  - <HOST> expands to match IPv4/IPv6 addresses");
        println!("  - Escape brackets with \\[ and \\]");
        println!("  - Use .* for flexible gaps");
        println!("  - Try: fail2ban-rs list-filters  (for built-in patterns)");
    }
}

#[cfg(test)]
mod tests {
    use crate::detect::matcher::JailMatcher;

    #[test]
    fn test_pattern_match() {
        let m = JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap();
        let line = "sshd[123]: Failed password for root from 10.0.0.1 port 22";
        let result = m.try_match(line).unwrap();
        assert_eq!(result.ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_pattern_no_match() {
        let m = JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap();
        let line = "sshd[123]: Accepted password for user from 10.0.0.1 port 22";
        assert!(m.try_match(line).is_none());
    }

    #[test]
    fn test_patterns_multiple_first_wins() {
        let patterns = vec![
            r"Failed password .* from <HOST>".to_string(),
            r"Invalid user .* from <HOST>".to_string(),
        ];
        let m = JailMatcher::new(&patterns).unwrap();

        let line = "Invalid user admin from 1.2.3.4 port 22";
        let result = m.try_match(line).unwrap();
        assert_eq!(result.ip.to_string(), "1.2.3.4");
        assert_eq!(result.pattern_idx, 1);
    }

    #[test]
    fn test_patterns_no_match_any() {
        let patterns = vec![
            r"Failed .* from <HOST>".to_string(),
            r"Invalid .* from <HOST>".to_string(),
        ];
        let m = JailMatcher::new(&patterns).unwrap();
        let line = "Accepted password for user from 10.0.0.1 port 22";
        assert!(m.try_match(line).is_none());
    }
}
