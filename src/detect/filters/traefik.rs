use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "traefik",
    description: "Traefik reverse proxy authentication failures",
    log_path: "/var/log/access.log",
    date_format: "common",
    patterns: &[r#"<HOST> .*" 401 "#],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn traefik_upstream_401() {
        assert_filter_matches(
            "traefik",
            "10.0.0.2 - username [18/Nov/2018:21:34:34 +0000] \"GET /dashboard/ HTTP/2.0\" 401 17 \"-\" \"Mozilla/5.0\" 72 \"Auth\" \"/dashboard/\" 0ms",
            "10.0.0.2",
        );
    }
}
