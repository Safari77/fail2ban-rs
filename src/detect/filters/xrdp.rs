use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "xrdp",
    description: "XRDP remote desktop authentication failures",
    log_path: "/var/log/xrdp-sesman.log",
    date_format: "iso8601",
    patterns: &[r"AUTHFAIL: user=\S+ ip=<HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn xrdp_authfail_ipv4_mapped() {
        assert_filter_matches(
            "xrdp",
            "[20220407-12:11:06] [INFO ] AUTHFAIL: user=badtypist ip=::ffff:10.171.161.151 time=1649351466",
            "10.171.161.151",
        );
    }

    #[test]
    fn xrdp_authfail_ip_injection() {
        // user=192.168.0.1 is injected — must extract the real IP from ip= field
        assert_filter_matches(
            "xrdp",
            "[20220407-12:11:24] [INFO ] AUTHFAIL: user=192.168.0.1 ip=::ffff:10.171.161.151 time=1649351484",
            "10.171.161.151",
        );
    }

    #[test]
    fn xrdp_authfail_syslog_format() {
        assert_filter_matches(
            "xrdp",
            "Apr  7 12:11:06 servername xrdp-sesman[41441]: [INFO ] AUTHFAIL: user=badtypist ip=::ffff:10.171.161.151 time=1649351466",
            "10.171.161.151",
        );
    }
}
