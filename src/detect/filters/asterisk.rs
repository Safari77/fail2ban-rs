use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "asterisk",
    description: "Asterisk VoIP SIP registration failures",
    log_path: "/var/log/asterisk/messages",
    date_format: "iso8601",
    patterns: &[
        r"NOTICE.* <HOST> failed to authenticate",
        r#"SECURITY.* SecurityEvent="FailedACL".*RemoteAddress.*<HOST>"#,
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn host_failed_to_authenticate() {
        assert_filter_matches(
            "asterisk",
            "[2012-02-13 17:53:59] NOTICE[1638] chan_iax2.c: Host 1.2.3.4 failed to authenticate as 'Fail2ban'",
            "1.2.3.4",
        );
    }

    #[test]
    fn host_failed_to_authenticate_ipv6() {
        assert_filter_matches(
            "asterisk",
            "[2022-01-01 00:00:00] NOTICE[999] chan_sip.c: Host 2001:db8::1 failed to authenticate as 'test'",
            "2001:db8::1",
        );
    }
}
