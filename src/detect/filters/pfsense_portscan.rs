use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "pfsense-portscan",
    description: "pfSense/OPNsense filterlog blocked packets \u{2014} port scan detection",
    log_path: "/var/log/filter.log",
    date_format: "syslog",
    patterns: &[
        r"filterlog\[\d+\]: .*,block,in,4,(?:[^,]*,){9}<HOST>,",
        r"filterlog\[\d+\]: .*,block,in,6,(?:[^,]*,){6}<HOST>,",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

    #[test]
    fn pfsense_portscan_ipv4_tcp() {
        assert_filter_matches(
            "pfsense-portscan",
            "Mar 28 12:00:00 fw filterlog[58921]: 4,,,1000000103,pppoe0,match,block,in,4,0x0,,242,26160,0,none,6,tcp,44,89.248.165.17,125.229.96.130,44961,30129,0,S,3258086147,,1025,,mss",
            "89.248.165.17",
        );
    }

    #[test]
    fn pfsense_portscan_ipv4_smb() {
        assert_filter_matches(
            "pfsense-portscan",
            "Oct 27 08:49:34 fw filterlog[58921]: 12,,,7ca0bdbea8e636fba2e984923ed67866,igb0,match,block,in,4,0x0,,107,19362,0,DF,6,tcp,52,177.229.216.18,125.229.96.130,51305,445,0,S,1581211380,,8192,,mss;nop;wscale;nop;nop;sackOK",
            "177.229.216.18",
        );
    }

    #[test]
    fn pfsense_portscan_ipv6_udp() {
        assert_filter_matches(
            "pfsense-portscan",
            "Mar 28 12:00:00 fw filterlog[1234]: 7,16777216,,1000000105,vmx1,match,block,in,6,0x00,0x00000,64,UDP,17,57,fe80::5505:5394:1ba7:b3e4,2001:db8:1:ee30:20c:29ff:fe78:6e58,54978,53,57",
            "fe80::5505:5394:1ba7:b3e4",
        );
    }

    #[test]
    fn pfsense_portscan_no_match_pass() {
        // action=pass — should not match
        assert_filter_no_match(
            "pfsense-portscan",
            "Mar 28 12:00:00 fw filterlog[1234]: 4,,,1000000103,pppoe0,match,pass,in,4,0x0,,242,26160,0,none,6,tcp,44,89.248.165.17,125.229.96.130,44961,80,0,S,3258086147,,1025,,mss",
        );
    }
}
