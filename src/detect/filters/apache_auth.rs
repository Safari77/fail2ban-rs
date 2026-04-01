use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "apache-auth",
    description: "Apache HTTP basic/digest authentication failures",
    log_path: "/var/log/apache2/error.log",
    date_format: "common",
    patterns: &[
        r"client <HOST>.*user .* authentication failure",
        r"client <HOST>.*user .* not found",
        r"client <HOST>.*password mismatch",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn user_not_found_apache22() {
        assert_filter_matches(
            "apache-auth",
            "[Mon Dec 23 13:12:31 2013] [error] [client 194.228.20.113] user dsfasdf not found: /",
            "194.228.20.113",
        );
    }

    #[test]
    fn user_not_found_ipv6() {
        assert_filter_matches(
            "apache-auth",
            "[Mon Dec 23 13:12:31 2013] [error] [client 2001:db8::80da:af6b:8b2c] user test-ipv6 not found: /",
            "2001:db8::80da:af6b:8b2c",
        );
    }

    #[test]
    fn password_mismatch_apache22() {
        assert_filter_matches(
            "apache-auth",
            "[Mon Dec 23 13:12:31 2013] [error] [client 127.0.0.1] user username: authentication failure for \"/basic/file\": Password Mismatch",
            "127.0.0.1",
        );
    }

    #[test]
    fn password_mismatch_apache24() {
        assert_filter_matches(
            "apache-auth",
            "[Mon Dec 23 13:12:31.123456 2013] [auth_basic:error] [pid 1234:tid 5678] [client 127.0.0.1:54321] AH01617: user username: authentication failure for \"/basic/file\": Password Mismatch",
            "127.0.0.1",
        );
    }
}
