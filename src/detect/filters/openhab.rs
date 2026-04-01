use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "openhab",
    description: "openHAB home automation authentication failures",
    log_path: "/var/log/openhab/request.log",
    date_format: "common",
    patterns: &[r#"<HOST>\s+-\s+.+\s+"[A-Z]+ .+" 401 "#],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn openhab_401() {
        assert_filter_matches(
            "openhab",
            r#"175.18.15.10 -  -  [02/sept./2015:00:11:31 +0200] "GET /openhab.app HTTP/1.1" 401 1382"#,
            "175.18.15.10",
        );
    }
}
