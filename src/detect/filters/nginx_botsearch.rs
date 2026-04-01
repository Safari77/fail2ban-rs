use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "nginx-botsearch",
    description: "Nginx requests for known exploit paths",
    log_path: "/var/log/nginx/access.log",
    date_format: "common",
    patterns: &[r#"<HOST> .* "(GET|POST) /(wp-login|xmlrpc|wp-admin|\.env|phpmyadmin|admin)"#],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn wp_login_get() {
        assert_filter_matches(
            "nginx-botsearch",
            r#"12.34.56.78 - - [20/Jan/2015:19:53:28 +0100] "GET /wp-login.php HTTP/1.1" 404 47 "-" "Mozilla""#,
            "12.34.56.78",
        );
    }

    #[test]
    fn phpmyadmin_get() {
        assert_filter_matches(
            "nginx-botsearch",
            r#"12.34.56.78 - - [20/Jan/2015:19:53:28 +0100] "GET /phpmyadmin/scripts/setup.php HTTP/1.1" 404 47 "-" "Mozilla""#,
            "12.34.56.78",
        );
    }

    #[test]
    fn admin_post() {
        assert_filter_matches(
            "nginx-botsearch",
            r#"7.8.9.10 - - [20/Jan/2015:01:17:07 +0100] "POST /admin/config.php HTTP/1.1" 404 162 "-" "Mozilla""#,
            "7.8.9.10",
        );
    }

    #[test]
    fn dotenv() {
        assert_filter_matches(
            "nginx-botsearch",
            r#"5.6.7.8 - - [01/Feb/2020:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/7.64""#,
            "5.6.7.8",
        );
    }
}
