use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "routeros-auth",
    description: "MikroTik RouterOS login failures",
    log_path: "/var/log/routeros.log",
    date_format: "syslog",
    patterns: &[r"system,error,critical login failure for user .* from <HOST> via"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn routeros_auth_login_failure() {
        assert_filter_matches(
            "routeros-auth",
            "Feb 15 11:25:46 gw.local system,error,critical login failure for user admin from 192.168.88.6 via web",
            "192.168.88.6",
        );
    }

    #[test]
    fn routeros_auth_ipv6() {
        assert_filter_matches(
            "routeros-auth",
            "Feb 15 11:57:42 1234.hostname.cz system,error,critical login failure for user  from 2001:470:1:c84::24 via ssh",
            "2001:470:1:c84::24",
        );
    }
}
