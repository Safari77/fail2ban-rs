use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "sogo-auth",
    description: "SOGo groupware authentication failures",
    log_path: "/var/log/sogo/sogo.log",
    date_format: "syslog",
    patterns: &[r"SOGoRootPage Login from '<HOST>.*might not have worked"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn sogo_auth_login_might_not_work() {
        assert_filter_matches(
            "sogo-auth",
            "Mar 24 08:58:32 sogod [26818]: SOGoRootPage Login from '173.194.44.31' for user 'hack0r' might not have worked - password policy: 65535  grace: -1  expire: -1  bound: 0",
            "173.194.44.31",
        );
    }

    #[test]
    fn sogo_auth_behind_proxy() {
        assert_filter_matches(
            "sogo-auth",
            "Mar 24 19:29:32 sogod [1526]: SOGoRootPage Login from '192.0.2.16, 10.0.0.1' for user 'admin' might not have worked - password policy: 65535  grace: -1  expire: -1  bound: 0",
            "192.0.2.16",
        );
    }
}
