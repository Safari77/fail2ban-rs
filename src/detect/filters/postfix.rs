use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "postfix",
    description: "Postfix SMTP authentication and relay failures",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[
        r"postfix/smtpd\[\d+\]: warning: .*\[<HOST>\]: SASL .* authentication failed",
        r"postfix/smtpd\[\d+\]: NOQUEUE: reject: RCPT from .*\[<HOST>\]",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

    #[test]
    fn sasl_login_failed() {
        assert_filter_matches(
            "postfix",
            "Jun 24 07:42:17 srv postfix/smtpd[27364]: warning: unknown[114.44.142.233]: SASL CRAM-MD5 authentication failed: PDEyMzQ1LjEzMjg5MjI5MTdAZXVyb3N0cmVhbT4=",
            "114.44.142.233",
        );
    }

    #[test]
    fn sasl_login_authentication() {
        assert_filter_matches(
            "postfix",
            "Jun 24 08:10:01 srv postfix/smtpd[28000]: warning: unknown[1.1.1.1]: SASL LOGIN authentication failed: UGFzc3dvcmQ6",
            "1.1.1.1",
        );
    }

    #[test]
    fn noqueue_reject_rcpt() {
        assert_filter_matches(
            "postfix",
            "Aug  7 15:14:11 h11 postfix/smtpd[18713]: NOQUEUE: reject: RCPT from example.com[192.0.43.10]: 550 5.1.1 <admin@example.com>: Recipient address rejected: User unknown in virtual mailbox table; from=<spammer@example.net> to=<admin@example.com> proto=ESMTP helo=<test.example.com>",
            "192.0.43.10",
        );
    }

    #[test]
    fn noqueue_reject_relay_denied() {
        assert_filter_matches(
            "postfix",
            "Sep  1 21:07:00 MAIL postfix/smtpd[6712]: NOQUEUE: reject: RCPT from unknown[93.184.216.34]: 454 4.7.1 <user@example.com>: Relay access denied; from=<some@body.com> to=<user@example.com> proto=ESMTP helo=<[93.184.216.34]>",
            "93.184.216.34",
        );
    }

    #[test]
    fn no_match_improper_pipelining() {
        assert_filter_no_match(
            "postfix",
            "Jun 12 08:58:35 srv postfix/smtpd[29306]: improper command pipelining after AUTH from unknown[192.0.2.11]: QUIT",
        );
    }
}
