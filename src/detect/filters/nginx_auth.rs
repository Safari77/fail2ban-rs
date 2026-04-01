use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "nginx-auth",
    description: "Nginx HTTP basic authentication failures",
    log_path: "/var/log/nginx/error.log",
    date_format: "common",
    patterns: &[
        r"no user/password was provided for basic authentication.*client: <HOST>",
        r"user .* was not found.*client: <HOST>",
        r"user .* password mismatch.*client: <HOST>",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn nginx_auth_upstream_user_not_found() {
        assert_filter_matches(
            "nginx-auth",
            "2012/04/09 11:53:29 [error] 2865#0: *66647 user \"xyz\" was not found in \"/var/www/.htpasswd\", client: 192.0.43.10, server: www.myhost.com, request: \"GET / HTTP/1.1\", host: \"www.myhost.com\"",
            "192.0.43.10",
        );
    }

    #[test]
    fn nginx_auth_upstream_password_mismatch() {
        assert_filter_matches(
            "nginx-auth",
            "2012/04/09 11:53:36 [error] 2865#0: *66647 user \"xyz\": password mismatch, client: 192.0.43.10, server: www.myhost.com, request: \"GET / HTTP/1.1\", host: \"www.myhost.com\"",
            "192.0.43.10",
        );
    }
}
