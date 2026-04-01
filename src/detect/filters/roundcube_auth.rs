use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "roundcube-auth",
    description: "Roundcube webmail authentication failures",
    log_path: "/var/log/roundcubemail/errors",
    date_format: "iso8601",
    patterns: &[
        r"(?i)login failed for .* from <HOST>",
        r"(?i)failed login for .* from <HOST>",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn roundcube_failed_login() {
        assert_filter_matches(
            "roundcube-auth",
            "[22-Jan-2013 22:28:21 +0200]: FAILED login for user1 from 192.0.43.10",
            "192.0.43.10",
        );
    }

    #[test]
    fn roundcube_imap_error() {
        assert_filter_matches(
            "roundcube-auth",
            "May 26 07:12:40 hamster roundcube: IMAP Error: Login failed for sales@example.com from 10.1.1.47",
            "10.1.1.47",
        );
    }

    #[test]
    fn roundcube_imap_with_response() {
        assert_filter_matches(
            "roundcube-auth",
            "Jul 11 03:06:37 myhostname roundcube: IMAP Error: Login failed for admin from 1.2.3.4. AUTHENTICATE PLAIN: A0002 NO Login failed. in /usr/share/roundcube/program/include/rcube_imap.php on line 205 (POST /wmail/?_task=login&_action=login)",
            "1.2.3.4",
        );
    }

    #[test]
    fn roundcube_failed_login_session() {
        assert_filter_matches(
            "roundcube-auth",
            "[10-May-2015 13:02:52 -0400]: Failed login for sampleuser from 1.2.3.4 in session 1z506z6rvddstv6k7jz08hxo27 (error: 0)",
            "1.2.3.4",
        );
    }
}
