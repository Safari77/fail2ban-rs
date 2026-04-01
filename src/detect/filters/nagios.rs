use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "nagios",
    description: "Nagios NRPE host access denied",
    log_path: "/var/log/syslog",
    date_format: "syslog",
    patterns: &[r"Host <HOST> is not allowed to talk to us"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn nagios_host_not_allowed() {
        assert_filter_matches(
            "nagios",
            "Feb  3 11:22:44 valhalla nrpe[63284]: Host 50.97.225.132 is not allowed to talk to us!",
            "50.97.225.132",
        );
    }
}
