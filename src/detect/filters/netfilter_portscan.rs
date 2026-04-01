use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "netfilter-portscan",
    description: "Netfilter dropped packets (iptables/nftables LOG target) \u{2014} port scan detection",
    log_path: "/var/log/kern.log",
    date_format: "syslog",
    patterns: &[r"kernel: .*IN=\S+ .*SRC=<HOST> DST=\S+ .*PROTO="],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

    #[test]
    fn netfilter_portscan_ufw_block_tcp() {
        assert_filter_matches(
            "netfilter-portscan",
            "Feb  3 10:58:43 server1 kernel: [465839.855234] [UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:aa:bb:cc:52:54:00:dd:ee:ff:08:00 SRC=192.168.1.100 DST=10.0.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54321 DF PROTO=TCP SPT=44356 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0",
            "192.168.1.100",
        );
    }

    #[test]
    fn netfilter_portscan_iptables_drop_tcp() {
        assert_filter_matches(
            "netfilter-portscan",
            "Mar 15 14:22:07 fw01 kernel: iptables-DROP: IN=ens3 OUT= MAC=00:16:3e:aa:bb:cc:00:16:3e:dd:ee:ff:08:00 SRC=203.0.113.45 DST=198.51.100.10 LEN=44 TOS=0x00 PREC=0x00 TTL=241 ID=62233 PROTO=TCP SPT=6000 DPT=23 WINDOW=65535 RES=0x00 SYN URGP=0",
            "203.0.113.45",
        );
    }

    #[test]
    fn netfilter_portscan_nftables_drop_udp() {
        assert_filter_matches(
            "netfilter-portscan",
            "Aug  5 21:00:44 firewall kernel: nft-drop: IN=enp1s0 OUT= MAC=00:0c:29:aa:bb:cc:00:50:56:dd:ee:ff:08:00 SRC=10.20.30.40 DST=10.20.30.1 LEN=329 TOS=0x00 PREC=0x00 TTL=64 ID=48372 PROTO=UDP SPT=5353 DPT=5353 LEN=309",
            "10.20.30.40",
        );
    }

    #[test]
    fn netfilter_portscan_icmp() {
        assert_filter_matches(
            "netfilter-portscan",
            "Sep 17 11:22:33 router kernel: [234567.890123] DROPPED: IN=wan0 OUT= MAC=00:1a:2b:3c:4d:5e:6f:70:80:90:a0:b0:08:00 SRC=198.51.100.1 DST=203.0.113.5 LEN=84 TOS=0x00 PREC=0x00 TTL=53 ID=0 DF PROTO=ICMP TYPE=8 CODE=0 ID=1234 SEQ=1",
            "198.51.100.1",
        );
    }

    #[test]
    fn netfilter_portscan_ipv6_tcp() {
        assert_filter_matches(
            "netfilter-portscan",
            "Nov 14 16:45:22 server2 kernel: ip6-drop: IN=eth0 OUT= MAC=33:33:00:00:00:01:00:11:22:33:44:55:86:dd SRC=2001:db8::1 DST=2001:db8::2 LEN=60 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=TCP SPT=54321 DPT=80 WINDOW=64240 RES=0x00 SYN URGP=0",
            "2001:db8::1",
        );
    }

    #[test]
    fn netfilter_portscan_no_match_output_chain() {
        // OUTPUT chain: IN= is empty — should not match
        assert_filter_no_match(
            "netfilter-portscan",
            "Feb 12 22:10:30 myhost kernel: OUTPUT_DROP: IN= OUT=ens3 SRC=10.0.0.5 DST=1.2.3.4 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=55555 DF PROTO=TCP SPT=12345 DPT=6667 WINDOW=64240 RES=0x00 SYN URGP=0",
        );
    }
}
