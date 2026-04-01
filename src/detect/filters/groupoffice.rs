use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "groupoffice",
    description: "Group-Office groupware authentication failures",
    log_path: "/var/log/groupoffice.log",
    date_format: "iso8601",
    patterns: &[r"LOGIN FAILED.*IP: <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn groupoffice_login_failed() {
        assert_filter_matches(
            "groupoffice",
            r#"[2014-01-06 10:59:38]LOGIN FAILED for user: "asdsad" from IP: 127.0.0.1"#,
            "127.0.0.1",
        );
    }
}
