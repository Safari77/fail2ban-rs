use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "monit",
    description: "Monit process supervisor authentication failures",
    log_path: "/var/log/monit.log",
    date_format: "syslog",
    patterns: &[
        r"Client .?<HOST>.? supplied wrong password",
        r"Client .?<HOST>.? supplied unknown user",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn monit_wrong_password() {
        assert_filter_matches(
            "monit",
            "[PDT Apr 16 20:59:33] error    : Warning: Client '97.113.189.111' supplied wrong password for user 'admin' accessing monit httpd",
            "97.113.189.111",
        );
    }

    #[test]
    fn monit_unknown_user() {
        assert_filter_matches(
            "monit",
            "[PDT Apr 16 21:05:29] error    : Warning: Client '69.93.127.111' supplied unknown user 'foo' accessing monit httpd",
            "69.93.127.111",
        );
    }
}
