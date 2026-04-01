use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "phpmyadmin-syslog",
    description: "phpMyAdmin authentication failures via syslog",
    log_path: "/var/log/auth.log",
    date_format: "syslog",
    patterns: &[r"phpMyAdmin\[\d+\]: user denied: .* from <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn phpmyadmin_syslog_denied() {
        assert_filter_matches(
            "phpmyadmin-syslog",
            "Aug 22 14:50:22 eurostream phpMyAdmin[16358]: user denied: root (mysql-denied) from 192.0.2.1",
            "192.0.2.1",
        );
    }
}
