use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "nginx-bad-request",
    description: "Nginx malformed HTTP requests (400 status)",
    log_path: "/var/log/nginx/access.log",
    date_format: "common",
    patterns: &[r#"<HOST> - \S+ .+"[^"]*" 400 "#],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn nginx_bad_request_empty() {
        assert_filter_matches(
            "nginx-bad-request",
            r#"12.34.56.78 - - [20/Jan/2015:19:53:28 +0100] "" 400 47 "-" "-" "-""#,
            "12.34.56.78",
        );
    }

    #[test]
    fn nginx_bad_request_binary() {
        assert_filter_matches(
            "nginx-bad-request",
            r#"12.34.56.78 - - [20/Jan/2015:19:53:28 +0100] "\x03\x00\x00/*\xE0\x00\x00\x00\x00\x00Cookie: mstshash=Administr" 400 47 "-" "-" "-""#,
            "12.34.56.78",
        );
    }

    #[test]
    fn nginx_bad_request_connect() {
        assert_filter_matches(
            "nginx-bad-request",
            r#"7.8.9.10 - root [20/Jan/2015:01:17:07 +0100] "CONNECT 123.123.123.123 HTTP/1.1" 400 162 "-" "-" "-""#,
            "7.8.9.10",
        );
    }
}
