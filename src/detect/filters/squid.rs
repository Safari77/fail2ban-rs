use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "squid",
    description: "Squid proxy denied requests",
    log_path: "/var/log/squid/access.log",
    date_format: "epoch",
    patterns: &[
        r"\d\s+<HOST>\s+[A-Z_]+_DENIED/\d+",
        r"\d\s+<HOST>\s+NONE/405",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn squid_tcp_denied() {
        assert_filter_matches(
            "squid",
            "1386543323.000      4 91.188.124.227 TCP_DENIED/403 4099 GET http://www.proxy-listen.de/azenv.php - HIER_NONE/- text/html",
            "91.188.124.227",
        );
    }

    #[test]
    fn squid_none_405() {
        assert_filter_matches(
            "squid",
            "1386543500.000      5 175.44.0.184 NONE/405 3364 CONNECT error:method-not-allowed - HIER_NONE/- text/html",
            "175.44.0.184",
        );
    }
}
