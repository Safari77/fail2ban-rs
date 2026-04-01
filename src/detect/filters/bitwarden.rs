use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "bitwarden",
    description: "Bitwarden self-hosted login failures",
    log_path: "bwdata/logs/identity/log.txt",
    date_format: "iso8601",
    patterns: &[r"Failed login attempt.* <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn failed_login() {
        assert_filter_matches(
            "bitwarden",
            "2019-11-26 01:04:49.008 +08:00 [WRN] Failed login attempt. 192.168.0.16",
            "192.168.0.16",
        );
    }

    #[test]
    fn failed_login_2fa_invalid() {
        assert_filter_matches(
            "bitwarden",
            "2019-11-25 21:39:58.464 +01:00 [WRN] Failed login attempt, 2FA invalid. 192.168.0.21",
            "192.168.0.21",
        );
    }

    #[test]
    fn failed_login_docker() {
        assert_filter_matches(
            "bitwarden",
            "2019-09-24T13:16:50 e5a81dbf7fd1 Bitwarden-Identity[1]: [Bit.Core.IdentityServer.ResourceOwnerPasswordValidator] Failed login attempt. 192.168.0.23",
            "192.168.0.23",
        );
    }
}
