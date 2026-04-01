use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "cyrus-imap",
    description: "Cyrus IMAP/POP3 authentication failures",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[r"badlogin:.*\[<HOST>\].*SASL\(-13\)"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn cyrus_imap_badlogin() {
        assert_filter_matches(
            "cyrus-imap",
            "Jan 4 21:51:05 hostname cyrus/imap[5355]: badlogin: localhost.localdomain [127.0.0.1] plaintext cyrus@localdomain SASL(-13): authentication failure: checkpass failed",
            "127.0.0.1",
        );
    }

    #[test]
    fn cyrus_imap_user_not_found() {
        assert_filter_matches(
            "cyrus-imap",
            "Jul 17 22:55:56 derry cyrus/imaps[7568]: badlogin: serafinat.xxxxxx [1.2.3.4] plain [SASL(-13): user not found: user: pressy@derry property: cmusaslsecretPLAIN not found in sasldb]",
            "1.2.3.4",
        );
    }
}
