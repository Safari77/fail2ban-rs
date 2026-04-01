use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "froxlor-auth",
    description: "Froxlor hosting panel authentication failures",
    log_path: "/var/log/syslog",
    date_format: "syslog",
    patterns: &[r"Login Action <HOST>.*(?:Unknown user|wrong password)"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn froxlor_auth_unknown_user() {
        assert_filter_matches(
            "froxlor-auth",
            "May 21 00:56:27 jomu Froxlor: [Login Action 1.2.3.4] Unknown user 'user' tried to login.",
            "1.2.3.4",
        );
    }

    #[test]
    fn froxlor_auth_wrong_password() {
        assert_filter_matches(
            "froxlor-auth",
            "May 21 00:57:38 jomu Froxlor: [Login Action 1.2.3.4] User 'admin' tried to login with wrong password.",
            "1.2.3.4",
        );
    }
}
