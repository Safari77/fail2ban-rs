use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "uwimap-auth",
    description: "UW-IMAP server authentication failures",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[r"Login failed user=.* \[<HOST>\]"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn uwimap_login_failed() {
        assert_filter_matches(
            "uwimap-auth",
            "Jul 3 20:56:53 Linux2 imapd[666]: Login failed user=lizdy auth=lizdy host=h2066373.stratoserver.net [81.169.154.112]",
            "81.169.154.112",
        );
    }
}
