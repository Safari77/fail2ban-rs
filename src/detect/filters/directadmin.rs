use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "directadmin",
    description: "DirectAdmin hosting panel login failures",
    log_path: "/var/log/directadmin/login.log",
    date_format: "iso8601",
    patterns: &[r"'<HOST>' \d+ failed login attempt"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn directadmin_failed_login() {
        assert_filter_matches(
            "directadmin",
            "2014:07:02-00:17:45: '3.2.1.4' 2 failed login attempts. Account 'test'",
            "3.2.1.4",
        );
    }
}
