use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "dovecot",
    description: "Dovecot IMAP/POP3 authentication failures",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[
        r"dovecot: .*auth failed.*rip=<HOST>",
        r"dovecot: .*Aborted login.*rip=<HOST>",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn auth_failed_rip() {
        assert_filter_matches(
            "dovecot",
            "Feb 12 12:07:14 mx dovecot: pop3-login: Disconnected (auth failed, 1 attempts): user=<info@example.com>, method=PLAIN, rip=80.187.101.33, lip=178.63.84.151",
            "80.187.101.33",
        );
    }

    #[test]
    fn aborted_login() {
        assert_filter_matches(
            "dovecot",
            "Jan 05 10:00:01 mailhost dovecot: imap-login: Aborted login (tried to use disallowed plaintext auth): user=<>, rip=49.176.98.87, lip=10.0.0.2, TLS",
            "49.176.98.87",
        );
    }

    #[test]
    fn auth_failed_secured() {
        assert_filter_matches(
            "dovecot",
            "Jan 05 10:05:00 mailhost dovecot: pop3-login: Disconnected (auth failed, 1 attempts): user=<admin>, method=PLAIN, rip=59.167.242.100, lip=10.0.0.1, secured",
            "59.167.242.100",
        );
    }
}
