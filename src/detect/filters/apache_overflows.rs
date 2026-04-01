use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "apache-overflows",
    description: "Apache buffer overflow and invalid request attempts",
    log_path: "/var/log/apache2/error.log",
    date_format: "common",
    patterns: &[r"client <HOST>.*(?:Invalid (?:method|URI)|request failed:)"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn apache_overflows_invalid_uri() {
        assert_filter_matches(
            "apache-overflows",
            r"[Tue Mar 16 15:39:29 2010] [error] [client 58.179.109.179] Invalid URI in request \xf9h",
            "58.179.109.179",
        );
    }

    #[test]
    fn apache_overflows_uri_too_long() {
        assert_filter_matches(
            "apache-overflows",
            "[Wed Jul 30 11:23:54 2010] [error] [client 10.85.6.69] request failed: URI too long (longer than 8190)",
            "10.85.6.69",
        );
    }
}
