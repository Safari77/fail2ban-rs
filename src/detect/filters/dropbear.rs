use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "dropbear",
    description: "Dropbear SSH authentication failures",
    log_path: "/var/log/auth.log",
    date_format: "syslog",
    patterns: &[
        r"dropbear\[\d+\].*[Bb]ad password attempt for .* from <HOST>:\d+",
        r"dropbear\[\d+\].*[Ll]ogin attempt for nonexistent user.*from <HOST>:\d+",
        r"dropbear\[\d+\].*[Ee]xit before auth.*from .?<HOST>:\d+",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn dropbear_bad_password() {
        assert_filter_matches(
            "dropbear",
            "Mar 24 15:25:51 buffalo1 dropbear[4092]: bad password attempt for 'root' from 198.51.100.87:5543",
            "198.51.100.87",
        );
    }

    #[test]
    fn dropbear_nonexistent_user_ipv4_mapped() {
        assert_filter_matches(
            "dropbear",
            "Feb 11 15:23:17 dropbear[1252]: login attempt for nonexistent user from ::ffff:198.51.100.215:60495",
            "198.51.100.215",
        );
    }

    #[test]
    fn dropbear_bad_password_caps() {
        assert_filter_matches(
            "dropbear",
            "Jul 27 01:04:12 fail2ban-test dropbear[1335]: Bad password attempt for 'root' from 1.2.3.4:60588",
            "1.2.3.4",
        );
    }

    #[test]
    fn dropbear_exit_before_auth() {
        assert_filter_matches(
            "dropbear",
            "Jul 27 01:04:22 fail2ban-test dropbear[1335]: Exit before auth (user 'root', 10 fails): Max auth tries reached - user 'root' from 1.2.3.4:60588",
            "1.2.3.4",
        );
    }

    #[test]
    fn dropbear_exit_before_auth_angle_brackets() {
        assert_filter_matches(
            "dropbear",
            "Jul 10 23:57:29 fail2ban-test dropbear[825]: [825] Jul 10 23:57:29 Exit before auth from <192.0.2.3:52289>: (user 'root', 10 fails): Max auth tries reached - user 'root'",
            "192.0.2.3",
        );
    }

    #[test]
    fn dropbear_extra_pid_timestamp() {
        assert_filter_matches(
            "dropbear",
            "Jul 10 23:53:52 fail2ban-test dropbear[825]: [825] Jul 10 23:53:52 Bad password attempt for 'root' from 1.2.3.4:52289",
            "1.2.3.4",
        );
    }
}
