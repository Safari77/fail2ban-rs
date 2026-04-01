use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "openwebmail",
    description: "Open WebMail authentication failures",
    log_path: "/var/log/openwebmail.log",
    date_format: "common",
    patterns: &[r"\(<HOST>\).*(?:login error|userinfo error)"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn openwebmail_login_error() {
        assert_filter_matches(
            "openwebmail",
            "Sat Dec 28 19:04:03 2013 - [72926] (178.123.108.196) gsdfg - login error - no such user - loginname=gsdfg",
            "178.123.108.196",
        );
    }
}
