use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "horde",
    description: "Horde groupware authentication failures",
    log_path: "/var/log/horde/horde.log",
    date_format: "syslog",
    patterns: &[r"HORDE.*FAILED LOGIN for \S+ \[<HOST>\]"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn horde_failed_login() {
        assert_filter_matches(
            "horde",
            r#"Nov 11 18:57:57 HORDE [error] [horde] FAILED LOGIN for graham [203.16.208.190] to Horde [on line 116 of "/home/ace-hosting/public_html/horde/login.php"]"#,
            "203.16.208.190",
        );
    }
}
