use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "webmin-auth",
    description: "Webmin administration panel authentication failures",
    log_path: "/var/log/auth.log",
    date_format: "syslog",
    patterns: &[r"webmin\[\d+\]: (?:Invalid|Non-existent) login as .* from <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn webmin_auth_invalid_login() {
        assert_filter_matches(
            "webmin-auth",
            "Dec 13 08:15:18 sb1 webmin[25875]: Invalid login as root from 89.2.49.230",
            "89.2.49.230",
        );
    }

    #[test]
    fn webmin_auth_nonexistent_login() {
        assert_filter_matches(
            "webmin-auth",
            "Dec 12 23:14:19 sb1 webmin[22134]: Non-existent login as robert from 188.40.105.142",
            "188.40.105.142",
        );
    }
}
