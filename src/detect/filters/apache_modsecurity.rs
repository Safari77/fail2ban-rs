use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "apache-modsecurity",
    description: "Apache ModSecurity WAF access denied",
    log_path: "/var/log/apache2/error.log",
    date_format: "common",
    patterns: &[r"client <HOST>.*ModSecurity:.*Access denied with code [45]\d\d"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn apache_modsecurity_403() {
        assert_filter_matches(
            "apache-modsecurity",
            r#"[Mon Dec 23 13:12:31 2013] [error] [client 173.255.225.101] ModSecurity:  [file "/etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_21_protocol_anomalies.conf"] [line "47"] [id "960015"] Access denied with code 403 (phase 2). Operator EQ matched 0 at REQUEST_HEADERS."#,
            "173.255.225.101",
        );
    }

    #[test]
    fn apache_modsecurity_dual_client() {
        // Apache 2.4 with two [client ...] entries — must extract the first
        assert_filter_matches(
            "apache-modsecurity",
            r#"[Sat Sep 28 09:18:06 2018] [error] [client 192.0.2.1:55555] [client 192.0.2.1] ModSecurity: [file "/etc/httpd/modsecurity.d/10_asl_rules.conf"] [line "635"] Access denied with code 403 (phase 2). Pattern match at REQUEST_URI."#,
            "192.0.2.1",
        );
    }

    #[test]
    fn apache_modsecurity_401() {
        assert_filter_matches(
            "apache-modsecurity",
            r"[Sat May 09 00:35:52.389262 2020] [:error] [pid 22406:tid 139985298601728] [client 192.0.2.2:47762] [client 192.0.2.2] ModSecurity: Access denied with code 401 (phase 2). Operator EQ matched 1 at IP:blocked.",
            "192.0.2.2",
        );
    }
}
