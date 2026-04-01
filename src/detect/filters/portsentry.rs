use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "portsentry",
    description: "PortSentry port scan detection",
    log_path: "/var/lib/portsentry/portsentry.history",
    date_format: "epoch",
    patterns: &[r"/<HOST> Port: \d+ (?:TCP|UDP) Blocked"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn portsentry_tcp_blocked() {
        assert_filter_matches(
            "portsentry",
            "1403884279 - 06/27/2014 17:51:19 Host: 192.168.56.1/192.168.56.1 Port: 1 TCP Blocked",
            "192.168.56.1",
        );
    }
}
