use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "gssftpd",
    description: "GSS-FTP (Kerberos FTP) authentication failures",
    log_path: "/var/log/auth.log",
    date_format: "syslog",
    patterns: &[r"ftpd\[\d+\]: repeated login failures from <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn gssftpd_repeated_failures() {
        assert_filter_matches(
            "gssftpd",
            "Jan 22 18:09:46 host ftpd[132]: repeated login failures from 198.51.100.23 (example.com)",
            "198.51.100.23",
        );
    }
}
