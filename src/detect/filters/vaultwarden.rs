use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "vaultwarden",
    description: "Vaultwarden (Bitwarden-compatible) login failures",
    log_path: "/var/log/vaultwarden.log",
    date_format: "iso8601",
    patterns: &[
        r"Username or password is incorrect.*IP: <HOST>",
        r"Invalid admin token.*IP: <HOST>",
        r"Invalid TOTP code.*IP: <HOST>",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn wrong_password_ipv6() {
        assert_filter_matches(
            "vaultwarden",
            "[2024-08-31 02:11:22.129][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 2001:db8::b6d3:95d7:1425:766d. Username: test@example.com.",
            "2001:db8::b6d3:95d7:1425:766d",
        );
    }

    #[test]
    fn wrong_password_ipv4() {
        assert_filter_matches(
            "vaultwarden",
            "[2024-08-31 02:11:28.562][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 80.187.85.94. Username: test@example.com.",
            "80.187.85.94",
        );
    }

    #[test]
    fn invalid_admin_token_ipv4() {
        assert_filter_matches(
            "vaultwarden",
            "[2024-08-31 02:11:28.725][vaultwarden::api::admin][ERROR] Invalid admin token. IP: 80.187.85.94",
            "80.187.85.94",
        );
    }

    #[test]
    fn invalid_admin_token_ipv6() {
        assert_filter_matches(
            "vaultwarden",
            "[2024-08-31 02:11:28.725][vaultwarden::api::admin][ERROR] Invalid admin token. IP: 2001:db8::b6d3:95d7:1425:766d",
            "2001:db8::b6d3:95d7:1425:766d",
        );
    }

    #[test]
    fn invalid_totp_ipv4() {
        assert_filter_matches(
            "vaultwarden",
            "[2024-08-31 02:11:28.892][vaultwarden::api::core::two_factor::authenticator][ERROR] Invalid TOTP code! Server time: 2024-08-31 02:11:28 UTC IP: 80.187.85.94",
            "80.187.85.94",
        );
    }

    #[test]
    fn invalid_totp_with_tz_offset() {
        assert_filter_matches(
            "vaultwarden",
            "[2024-08-31 02:11:28.892+0800][vaultwarden::api::core::two_factor::authenticator][ERROR] Invalid TOTP code! Server time: 2024-08-30 18:11:28 UTC IP: 80.187.85.94",
            "80.187.85.94",
        );
    }

    #[test]
    fn invalid_admin_token_with_username() {
        assert_filter_matches(
            "vaultwarden",
            "[2024-08-31 02:11:30.123+0800][vaultwarden::api::admin][ERROR] Invalid admin token! IP: 192.0.2.7. Username: alice",
            "192.0.2.7",
        );
    }
}
