use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "scanlogd",
    description: "scanlogd port scan detection",
    log_path: "/var/log/syslog",
    date_format: "syslog",
    patterns: &[r"scanlogd: <HOST> to"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn scanlogd_portscan() {
        assert_filter_matches(
            "scanlogd",
            "Mar  5 21:44:43 srv scanlogd: 192.0.2.123 to 192.0.2.1 ports 80, 81, 83, 88, 99, 443, 1080, 3128, ..., f????uxy, TOS 00, TTL 49 @20:44:43",
            "192.0.2.123",
        );
    }
}
