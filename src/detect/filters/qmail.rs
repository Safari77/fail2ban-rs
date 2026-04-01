use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "qmail",
    description: "Qmail RBL-blocked SMTP connections",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[r"rblsmtpd: <HOST>", r"badiprbl: ip <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn qmail_rblsmtpd() {
        assert_filter_matches(
            "qmail",
            "Sep  6 07:33:33 sd6 qmail: 1157520813.485077 rblsmtpd: 198.51.100.77 pid 19597 sbl-xbl.spamhaus.org: 451 http://www.spamhaus.org/query/bl?ip=198.51.100.77",
            "198.51.100.77",
        );
    }
}
