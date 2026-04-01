use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "courier-auth",
    description: "Courier IMAP/POP3 authentication failures",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[r"LOGIN FAILED,.* ip=\[<HOST>\]"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn courier_imapd_login_failed() {
        assert_filter_matches(
            "courier-auth",
            "Apr 23 21:59:01 dns2 imapd: LOGIN FAILED, user=sales@example.com, ip=[::ffff:1.2.3.4]",
            "1.2.3.4",
        );
    }

    #[test]
    fn courier_pop3d_login_failed() {
        assert_filter_matches(
            "courier-auth",
            "Apr 23 21:59:38 dns2 pop3d: LOGIN FAILED, user=info@example.com, ip=[::ffff:198.51.100.76]",
            "198.51.100.76",
        );
    }

    #[test]
    fn courier_imapd_ssl_login_failed() {
        assert_filter_matches(
            "courier-auth",
            "Nov 13 08:11:53 server imapd-ssl: LOGIN FAILED, user=user@domain.tld, ip=[::ffff:198.51.100.33]",
            "198.51.100.33",
        );
    }

    #[test]
    fn courier_pop3_login_method() {
        assert_filter_matches(
            "courier-auth",
            "Apr 17 19:17:12 server imapd-ssl: LOGIN FAILED, method=PLAIN, ip=[::ffff:192.0.2.4]",
            "192.0.2.4",
        );
    }

    #[test]
    fn courier_pop3login_legacy() {
        assert_filter_matches(
            "courier-auth",
            "Apr 17 19:17:11 SERVER courierpop3login: LOGIN FAILED, user=USER@EXAMPLE.org, ip=[::ffff:1.2.3.4]",
            "1.2.3.4",
        );
    }
}
