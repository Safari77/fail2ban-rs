use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "vsftpd",
    description: "vsftpd FTP login failures",
    log_path: "/var/log/vsftpd.log",
    date_format: "syslog",
    patterns: &[r#"vsftpd.*FAIL LOGIN: Client "<HOST>""#],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn fail_login_syslog() {
        assert_filter_matches(
            "vsftpd",
            r#"2025-03-04T01:06:36.645577 host vsftpd[1658]: [username] FAIL LOGIN: Client "192.0.2.222""#,
            "192.0.2.222",
        );
    }

    #[test]
    fn fail_login_ipv4_mapped() {
        assert_filter_matches(
            "vsftpd",
            r#"Thu Sep  8 00:39:49 2016 [pid 15019] vsftpd: [guest] FAIL LOGIN: Client "::ffff:192.0.2.1", "User is not in the allow user list.""#,
            "192.0.2.1",
        );
    }
}
