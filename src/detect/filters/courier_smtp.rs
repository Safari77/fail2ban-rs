use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "courier-smtp",
    description: "Courier SMTP relay and authentication failures",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[r"courieresmtpd.*error,relay=<HOST>,"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn courier_smtp_user_unknown_ipv4_mapped() {
        assert_filter_matches(
            "courier-smtp",
            "Apr 10 03:47:57 web courieresmtpd: error,relay=::ffff:1.2.3.4,ident=tmf,from=<tmf@example.com>,to=<mailman-subscribe@example.com>: 550 User unknown.",
            "1.2.3.4",
        );
    }

    #[test]
    fn courier_smtp_auth_failed_ipv4_mapped() {
        assert_filter_matches(
            "courier-smtp",
            r#"Jul  3 23:07:20 szerver courieresmtpd: error,relay=::ffff:1.2.3.4,msg="535 Authentication failed.",cmd: YWRvYmVhZG9iZQ=="#,
            "1.2.3.4",
        );
    }
}
