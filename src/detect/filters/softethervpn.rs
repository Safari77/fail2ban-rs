use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "softethervpn",
    description: "SoftEther VPN authentication failures",
    log_path: "/usr/local/vpnserver/security_log/DEFAULT/sec.log",
    date_format: "iso8601",
    patterns: &[r"User authentication failed.* from <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn softethervpn_auth_failed() {
        assert_filter_matches(
            "softethervpn",
            r#"2020-05-12 10:53:19.781 Connection "CID-72": User authentication failed. The user name that has been provided was "bob", from 80.10.11.12."#,
            "80.10.11.12",
        );
    }
}
