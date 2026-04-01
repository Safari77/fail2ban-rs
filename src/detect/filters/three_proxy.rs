use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "3proxy",
    description: "3proxy proxy server authentication failures",
    log_path: "/var/log/3proxy.log",
    date_format: "common",
    patterns: &[r"PROXY\.\d+ \d{3}0[1-9] \S+ <HOST>:\d+"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn three_proxy_auth_failure() {
        assert_filter_matches(
            "3proxy",
            "11-06-2013 02:09:40 +0300 PROXY.3128 00004 - 1.2.3.4:28783 0.0.0.0:0 0 0 0 GET http://www.yandex.ua/?ncrnd=2169807731 HTTP/1.1",
            "1.2.3.4",
        );
    }

    #[test]
    fn three_proxy_auth_with_user() {
        assert_filter_matches(
            "3proxy",
            "11-06-2013 02:09:43 +0300 PROXY.3128 00005 ewr 1.2.3.4:28788 0.0.0.0:0 0 0 0 GET http://www.yandex.ua/?ncrnd=2169807731 HTTP/1.1",
            "1.2.3.4",
        );
    }
}
