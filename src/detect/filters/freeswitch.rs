use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "freeswitch",
    description: "FreeSWITCH VoIP SIP authentication failures",
    log_path: "/var/log/freeswitch/freeswitch.log",
    date_format: "iso8601",
    patterns: &[
        r"SIP auth (?:failure|challenge).* from ip <HOST>",
        r"Can.t find user .* from <HOST>",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn freeswitch_auth_failure() {
        assert_filter_matches(
            "freeswitch",
            "2013-12-31 17:39:54.767815 [WARNING] sofia_reg.c:1478 SIP auth failure (INVITE) on sofia profile 'internal' for [000972543480510@192.168.2.51] from ip 5.11.47.236",
            "5.11.47.236",
        );
    }

    #[test]
    fn freeswitch_cant_find_user() {
        assert_filter_matches(
            "freeswitch",
            "2013-12-31 17:39:54.767815 [WARNING] sofia_reg.c:2531 Can't find user [1001@192.168.2.51] from 5.11.47.236",
            "5.11.47.236",
        );
    }
}
