use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "centreon",
    description: "Centreon IT monitoring authentication failures",
    log_path: "/var/log/centreon/login.log",
    date_format: "iso8601",
    patterns: &[r"\[<HOST>\] Authentication failed"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn centreon_auth_failed() {
        assert_filter_matches(
            "centreon",
            "2019-10-21 18:55:15|-1|0|0|[WEB] [50.97.225.132] Authentication failed for 'admin' : password mismatch",
            "50.97.225.132",
        );
    }
}
