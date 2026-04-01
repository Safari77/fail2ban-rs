use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "guacamole",
    description: "Apache Guacamole remote desktop gateway authentication failures",
    log_path: "/var/log/guacamole.log",
    date_format: "iso8601",
    patterns: &[r"Authentication attempt from <HOST> for user .* failed"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn guacamole_auth_failed() {
        assert_filter_matches(
            "guacamole",
            r#"WARNING: Authentication attempt from 192.0.2.0 for user "null" failed."#,
            "192.0.2.0",
        );
    }

    #[test]
    fn guacamole_webapp_format() {
        assert_filter_matches(
            "guacamole",
            r#"12:57:32.907 [http-nio-8080-exec-10] WARN  o.a.g.r.auth.AuthenticationService - Authentication attempt from 182.23.72.36 for user "guacadmin" failed."#,
            "182.23.72.36",
        );
    }
}
