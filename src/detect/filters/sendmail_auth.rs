use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "sendmail-auth",
    description: "Sendmail SMTP AUTH brute force attempts",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[r"\[<HOST>\]: possible SMTP attack: command=AUTH"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn sendmail_auth_attack() {
        assert_filter_matches(
            "sendmail-auth",
            "Feb 16 23:33:20 smtp1 sm-mta[5133]: s1GNXHYB005133: [190.5.230.178]: possible SMTP attack: command=AUTH, count=5",
            "190.5.230.178",
        );
    }
}
