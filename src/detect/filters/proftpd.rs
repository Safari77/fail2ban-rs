use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "proftpd",
    description: "ProFTPD FTP authentication failures",
    log_path: "/var/log/auth.log",
    date_format: "syslog",
    patterns: &[
        r"proftpd\[\d+\].*?\([^\[]+\[<HOST>\]\).*Login failed",
        r"proftpd\[\d+\].*?\([^\[]+\[<HOST>\]\).*no such user",
        r"proftpd\[\d+\].*?\([^\[]+\[<HOST>\]\).*Incorrect password",
        r"proftpd\[\d+\].*?\([^\[]+\[<HOST>\]\).*SECURITY VIOLATION",
        r"proftpd\[\d+\].*?\([^\[]+\[<HOST>\]\).*Maximum login attempts",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn proftpd_login_failed() {
        assert_filter_matches(
            "proftpd",
            "Jan 10 00:00:00 myhost proftpd[12345] myhost.domain.com (123.123.123.123[123.123.123.123]): USER username (Login failed): User in /etc/ftpusers",
            "123.123.123.123",
        );
    }

    #[test]
    fn proftpd_no_such_user() {
        assert_filter_matches(
            "proftpd",
            "Feb 1 00:00:00 myhost proftpd[12345] myhost.domain.com (123.123.123.123[123.123.123.123]): USER username: no such user found from 123.123.123.123 [123.123.123.123] to 234.234.234.234:21",
            "123.123.123.123",
        );
    }

    #[test]
    fn proftpd_incorrect_password_ipv4_mapped() {
        // ::ffff: IPv4-mapped address — tests the HOST_CAPTURE fix
        assert_filter_matches(
            "proftpd",
            "Jun 09 07:30:58 platypus.ace-hosting.com.au proftpd[11864] platypus.ace-hosting.com.au (mail.bloodymonster.net[::ffff:67.227.224.66]): USER username (Login failed): Incorrect password.",
            "67.227.224.66",
        );
    }

    #[test]
    fn proftpd_security_violation_ipv4_mapped() {
        assert_filter_matches(
            "proftpd",
            "Jun 13 22:07:23 platypus.ace-hosting.com.au proftpd[15719] platypus.ace-hosting.com.au (::ffff:59.167.242.100[::ffff:59.167.242.100]): SECURITY VIOLATION: root login attempted.",
            "59.167.242.100",
        );
    }

    #[test]
    fn proftpd_max_login_attempts_ipv4_mapped() {
        assert_filter_matches(
            "proftpd",
            "May 31 10:53:25 mail proftpd[15302]: xxxxxxxxxx (::ffff:1.2.3.4[::ffff:1.2.3.4]) - Maximum login attempts (3) exceeded",
            "1.2.3.4",
        );
    }

    #[test]
    fn proftpd_log_injection_attack() {
        // Malicious username injects a fake log entry with IP 1.2.3.44 — must extract 59.167.242.100
        assert_filter_matches(
            "proftpd",
            "Jun 14 00:09:59 platypus.ace-hosting.com.au proftpd[17839] platypus.ace-hosting.com.au (::ffff:59.167.242.100[::ffff:59.167.242.100]): USER platypus.ace-hosting.com.au proftpd[17424] platypus.ace-hosting.com.au (hihoinjection[1.2.3.44]): no such user found from ::ffff:59.167.242.100 [::ffff:59.167.242.100] to ::ffff:113.212.99.194:21",
            "59.167.242.100",
        );
    }

    #[test]
    fn proftpd_mod_sftp_dash_separator() {
        assert_filter_matches(
            "proftpd",
            "Oct  2 15:45:44 ftp01 proftpd[5517]: 192.0.2.13 (192.0.2.13[192.0.2.13]) - SECURITY VIOLATION: Root login attempted",
            "192.0.2.13",
        );
    }
}
