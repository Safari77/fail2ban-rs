use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "nsd",
    description: "NSD authoritative DNS rate limit blocks and refused transfers",
    log_path: "/var/log/nsd.log",
    date_format: "epoch",
    patterns: &[
        r"nsd\[\d+\]: info: ratelimit block .* query <HOST>",
        r"nsd\[\d+\]:.*from client <HOST> refused",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn nsd_ratelimit_block() {
        assert_filter_matches(
            "nsd",
            "[1387288694] nsd[7745]: info: ratelimit block example.com. type any target 192.0.2.0/24 query 192.0.2.105 TYPE255",
            "192.0.2.105",
        );
    }
}
