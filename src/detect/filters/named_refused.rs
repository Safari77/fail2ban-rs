use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "named-refused",
    description: "BIND/named DNS query refused",
    log_path: "/var/log/syslog",
    date_format: "syslog",
    patterns: &[r"named\[\d+\].*client <HOST>#\d+.*(?:denied|REFUSED)"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn named_refused_query_denied() {
        assert_filter_matches(
            "named-refused",
            "Jul 24 14:16:55 raid5 named[3935]: client 194.145.196.18#4795: query 'ricreig.com/NS/IN' denied",
            "194.145.196.18",
        );
    }
}
