use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "pf-portscan",
    description: "PF blocked packets (tcpdump pflog to syslog) \u{2014} port scan detection",
    log_path: "/var/log/pf.log",
    date_format: "syslog",
    patterns: &[
        r"block in on \S+:\s+<HOST>\.\d+ >",
        r"block in on \S+:\s+<HOST> >",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn pf_portscan_tcp_ipv4() {
        assert_filter_matches(
            "pf-portscan",
            "Feb 16 16:43:20 firewall pf: rule 0/(match) block in on ep0: 194.54.59.189.2559 > 194.54.107.19.139: [|tcp] (DF)",
            "194.54.59.189",
        );
    }

    #[test]
    fn pf_portscan_tcp_flags() {
        assert_filter_matches(
            "pf-portscan",
            "Mar 28 09:00:01 gw pf: rule 22/0(match): block in on vlan2: 10.52.0.39.58012 > 10.55.0.131.8080: Flags [S], seq 2837144143, win 14600, length 0",
            "10.52.0.39",
        );
    }

    #[test]
    fn pf_portscan_icmp_no_port() {
        assert_filter_matches(
            "pf-portscan",
            "Feb 16 16:53:10 firewall pf: rule 0/(match) block in on ep0: 68.194.177.173 > 194.54.107.19: [|icmp]",
            "68.194.177.173",
        );
    }

    #[test]
    fn pf_portscan_ipv6_tcp() {
        assert_filter_matches(
            "pf-portscan",
            "Jan 05 12:00:00 fw pf: rule 18/0(match): block in on bce0: 2a02:840:beef:1d::2.42214 > 2a02:840:1:200::2.80: Flags [S]",
            "2a02:840:beef:1d::2",
        );
    }
}
