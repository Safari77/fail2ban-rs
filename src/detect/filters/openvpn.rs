use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "openvpn",
    description: "OpenVPN authentication failures",
    log_path: "/var/log/syslog",
    date_format: "syslog",
    patterns: &[
        r"ovpn-.* <HOST>:\d+ TLS Auth Error",
        r"ovpn-.* <HOST>:\d+.*AUTH_FAILED",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn tls_auth_error() {
        assert_filter_matches(
            "openvpn",
            "Apr 25 11:19:22 ovpn-server[13821]: 192.0.2.254:64480 TLS Auth Error: Auth Username/Password verification failed for peer",
            "192.0.2.254",
        );
    }
}
