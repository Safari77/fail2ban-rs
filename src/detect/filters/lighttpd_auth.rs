use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "lighttpd-auth",
    description: "Lighttpd HTTP authentication failures",
    log_path: "/var/log/lighttpd/error.log",
    date_format: "iso8601",
    patterns: &[r"(?:password doesn.t match|digest: auth failed|get_password failed).* IP: <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn lighttpd_auth_password_mismatch() {
        assert_filter_matches(
            "lighttpd-auth",
            "2011-12-25 17:09:20: (http_auth.c.875) password doesn't match for /gitweb/ username: francois, IP: 4.4.4.4",
            "4.4.4.4",
        );
    }

    #[test]
    fn lighttpd_auth_digest_failed() {
        assert_filter_matches(
            "lighttpd-auth",
            "2012-09-26 10:24:35: (http_auth.c.1136) digest: auth failed for  xxx : wrong password, IP: 4.4.4.4",
            "4.4.4.4",
        );
    }
}
