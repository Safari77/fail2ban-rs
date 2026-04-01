use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "haproxy",
    description: "HAProxy HTTP authentication failures",
    log_path: "/var/log/haproxy.log",
    date_format: "syslog",
    patterns: &[r"haproxy\[\d+\]: <HOST>:\d+ .*\b401\b"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn haproxy_upstream_nosrv_401() {
        assert_filter_matches(
            "haproxy",
            "Nov 14 22:45:11 test haproxy[760]: 192.168.33.1:58430 [14/Nov/2015:22:45:11.608] main main/<NOSRV> -1/-1/-1/-1/0 401 248 - - PR-- 0/0/0/0/0 0/0 \"GET / HTTP/1.1\"",
            "192.168.33.1",
        );
    }
}
