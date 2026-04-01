use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "perdition",
    description: "Perdition mail proxy authentication failures",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[
        r"perdition.*Auth: <HOST>:\d+.*status=.failed",
        r"perdition.*Fatal Error reading authentication.*client <HOST>:\d+",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn perdition_auth_failed() {
        assert_filter_matches(
            "perdition",
            r#"Jul 18 16:07:18 ares perdition.imaps[3194]: Auth: 192.168.8.100:2274->193.48.191.9:993 client-secure=ssl authorisation_id=NONE authentication_id="carles" server="imap.biotoul.fr:993" protocol=IMAP4S server-secure=ssl status="failed: Re-Authentication Failure""#,
            "192.168.8.100",
        );
    }

    #[test]
    fn perdition_fatal_error() {
        assert_filter_matches(
            "perdition",
            "Jul 18 16:08:58 ares perdition.imaps[3194]: Fatal Error reading authentication information from client 192.168.8.100:2274->193.48.191.9:993: Exiting child",
            "192.168.8.100",
        );
    }
}
