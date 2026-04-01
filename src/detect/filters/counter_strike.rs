use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "counter-strike",
    description: "Counter-Strike game server rcon brute force",
    log_path: "/opt/cstrike/logs/L0101000.log",
    date_format: "common",
    patterns: &[r#"Bad Rcon:.*from "<HOST>:\d+""#],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn counter_strike_bad_rcon() {
        assert_filter_matches(
            "counter-strike",
            r#"L 01/01/2014 - 01:25:17: Bad Rcon: "rcon 1146003691 "284"  sv_contact "HLBrute 1.10"" from "31.29.29.89:57370""#,
            "31.29.29.89",
        );
    }
}
