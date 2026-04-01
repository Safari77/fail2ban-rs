use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "nginx-forbidden",
    description: "Nginx access forbidden by rule",
    log_path: "/var/log/nginx/error.log",
    date_format: "common",
    patterns: &[r"access forbidden by rule, client: <HOST>,"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn nginx_forbidden_rule() {
        assert_filter_matches(
            "nginx-forbidden",
            r#"2018/09/14 19:03:05 [error] 2035#2035: *9134 access forbidden by rule, client: 12.34.56.78, server: www.example.net, request: "GET /wp-content/themes/evolve/js/back-end/libraries/fileuploader/upload_handler.php HTTP/1.1", host: "www.example.net""#,
            "12.34.56.78",
        );
    }

    #[test]
    fn nginx_forbidden_wp_config() {
        assert_filter_matches(
            "nginx-forbidden",
            r#"2018/09/13 15:42:05 [error] 2035#2035: *287 access forbidden by rule, client: 12.34.56.78, server: www.example.com, request: "GET /wp-config.php~ HTTP/1.1", host: "www.example.com""#,
            "12.34.56.78",
        );
    }
}
