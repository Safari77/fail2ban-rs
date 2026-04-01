use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "gitlab",
    description: "GitLab authentication failures",
    log_path: "/var/log/gitlab/gitlab-rails/application.log",
    date_format: "iso8601",
    patterns: &[r"Failed Login:.*ip=<HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn failed_login_admin() {
        assert_filter_matches(
            "gitlab",
            "Failed Login: username=admin ip=80.10.11.12",
            "80.10.11.12",
        );
    }

    #[test]
    fn failed_login_user_with_space() {
        assert_filter_matches(
            "gitlab",
            "Failed Login: username=user name ip=80.10.11.12",
            "80.10.11.12",
        );
    }
}
