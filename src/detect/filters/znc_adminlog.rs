use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "znc-adminlog",
    description: "ZNC IRC bouncer login failures",
    log_path: "/var/lib/znc/moddata/adminlog/znc.log",
    date_format: "iso8601",
    patterns: &[r"failed to login from <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn znc_adminlog_failed_login() {
        assert_filter_matches(
            "znc-adminlog",
            "[2018-10-27 01:40:55] [girst] failed to login from 1.2.3.4",
            "1.2.3.4",
        );
    }

    #[test]
    fn znc_adminlog_with_port() {
        assert_filter_matches(
            "znc-adminlog",
            "[2019-09-08 15:53:19] [admin] failed to login from 192.0.2.1:65001",
            "192.0.2.1",
        );
    }
}
