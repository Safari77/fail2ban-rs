use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "tine20",
    description: "Tine 2.0 groupware authentication failures",
    log_path: "/var/log/tine20/tine20.log",
    date_format: "iso8601",
    patterns: &[r"Login with username .* from <HOST> failed"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn tine20_login_failed() {
        assert_filter_matches(
            "tine20",
            "78017 00cff -- none -- - 2014-01-13T05:02:22+00:00 WARN (4): Tinebase_Controller::login::106 Login with username sdfsadf from 127.0.0.1 failed (-1)!",
            "127.0.0.1",
        );
    }
}
