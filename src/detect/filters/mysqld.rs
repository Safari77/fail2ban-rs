use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "mysqld",
    description: "MySQL/MariaDB authentication failures",
    log_path: "/var/log/mysql/error.log",
    date_format: "iso8601",
    patterns: &[
        r"Access denied for user .*@'<HOST>'",
        r"Access denied for user .* from '<HOST>'",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn mysqld_upstream_access_denied() {
        assert_filter_matches(
            "mysqld",
            "130324  0:04:00 [Warning] Access denied for user 'root'@'192.168.1.35' (using password: NO)",
            "192.168.1.35",
        );
    }
}
