use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "sshd",
    description: "OpenSSH daemon — brute force and invalid user detection",
    log_path: "/var/log/auth.log",
    date_format: "syslog",
    patterns: &[
        r"sshd\[\d+\]: Failed password for .* from <HOST> port \d+",
        r"sshd\[\d+\]: Invalid user .* from <HOST> port \d+",
        r"sshd\[\d+\]: Connection closed by authenticating user .* <HOST> port \d+",
        r"sshd\[\d+\]: Disconnected from authenticating user .* <HOST> port \d+",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

    #[test]
    fn failed_password_ipv4() {
        assert_filter_matches(
            "sshd",
            "Feb 25 14:34:10 belka sshd[31602]: Failed password for invalid user ROOT from 194.117.26.69 port 50273 ssh2",
            "194.117.26.69",
        );
    }

    #[test]
    fn failed_password_ipv6() {
        assert_filter_matches(
            "sshd",
            "Feb 25 14:34:10 belka sshd[31603]: Failed password for invalid user ROOT from aaaa:bbbb:cccc:1234::1:1 port 50273 ssh2",
            "aaaa:bbbb:cccc:1234::1:1",
        );
    }

    #[test]
    fn invalid_user_with_port() {
        assert_filter_matches(
            "sshd",
            "Jul 20 14:42:12 localhost sshd[22708]: Invalid user ftp from 192.0.2.2 port 37220",
            "192.0.2.2",
        );
    }

    #[test]
    fn failed_password_ipv4_ssh1() {
        assert_filter_matches(
            "sshd",
            "Sep 29 16:28:02 spaceman sshd[16699]: Failed password for dan from 127.0.0.1 port 45416 ssh1",
            "127.0.0.1",
        );
    }

    #[test]
    fn disconnected_from_authenticating_user() {
        assert_filter_matches(
            "sshd",
            "Sep 29 16:28:05 spaceman sshd[16700]: Disconnected from authenticating user root 127.0.0.1 port 45416",
            "127.0.0.1",
        );
    }

    #[test]
    fn no_match_break_in_attempt() {
        assert_filter_no_match(
            "sshd",
            "Oct 15 19:51:35 server sshd[7592]: Address 1.2.3.4 maps to 1234.bbbbbb.com, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!",
        );
    }

    #[test]
    fn no_match_account_locked() {
        assert_filter_no_match(
            "sshd",
            "Apr 24 01:39:19 host sshd[3719]: User root not allowed because account is locked",
        );
    }

    #[test]
    fn no_match_connection_from() {
        assert_filter_no_match(
            "sshd",
            "Feb 12 04:09:18 localhost sshd[26713]: Connection from 115.249.163.77 port 51353",
        );
    }

    #[test]
    fn no_match_accepted_publickey() {
        assert_filter_no_match(
            "sshd",
            "Nov 28 09:16:03 srv sshd[32307]: Accepted publickey for git from 192.0.2.1 port 57904 ssh2: DSA 36:48:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx",
        );
    }
}
