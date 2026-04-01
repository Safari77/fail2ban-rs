use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "xinetd-fail",
    description: "xinetd service connection failures",
    log_path: "/var/log/syslog",
    date_format: "syslog",
    patterns: &[r"FAIL:.*from=<HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn xinetd_fail_telnet() {
        assert_filter_matches(
            "xinetd-fail",
            "May 15 17:38:49 boo xinetd[16256]: FAIL: telnet address from=198.51.100.169",
            "198.51.100.169",
        );
    }
}
