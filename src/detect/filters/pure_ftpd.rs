use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "pure-ftpd",
    description: "Pure-FTPd authentication failures",
    log_path: "/var/log/auth.log",
    date_format: "syslog",
    patterns: &[r"pure-ftpd: \(.+?@<HOST>\) \[WARNING\]"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn pure_ftpd_auth_failed() {
        assert_filter_matches(
            "pure-ftpd",
            "Jan 31 16:54:07 desktop pure-ftpd: (?@24.79.92.194) [WARNING] Authentication failed for user [Administrator]",
            "24.79.92.194",
        );
    }
}
