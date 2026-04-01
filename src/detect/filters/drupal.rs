use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "drupal",
    description: "Drupal CMS authentication failures",
    log_path: "/var/log/syslog",
    date_format: "syslog",
    patterns: &[
        r"drupal.*Login attempt failed from <HOST>",
        r"(?:[^|]*\|){3}<HOST>\|.*Login attempt failed",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn drupal_upstream_login_failed() {
        assert_filter_matches(
            "drupal",
            "Apr 26 13:15:25 webserver example.com: https://example.com|1430068525|user|1.2.3.4|https://example.com/?q=user|https://example.com/?q=user|0||Login attempt failed for drupaladmin.",
            "1.2.3.4",
        );
    }
}
