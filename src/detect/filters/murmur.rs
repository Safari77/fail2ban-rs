use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "murmur",
    description: "Mumble/Murmur VoIP server authentication failures",
    log_path: "/var/log/mumble-server/mumble-server.log",
    date_format: "iso8601",
    patterns: &[
        r"Rejected connection from <HOST>:\d+: (?:Invalid server password|Wrong certificate)",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn murmur_invalid_password() {
        assert_filter_matches(
            "murmur",
            "<W>2015-11-29 16:38:01.818 1 => <4:testUsernameOne(-1)> Rejected connection from 192.168.0.1:29530: Invalid server password",
            "192.168.0.1",
        );
    }

    #[test]
    fn murmur_wrong_certificate() {
        assert_filter_matches(
            "murmur",
            "<W>2015-11-29 17:18:20.962 1 => <8:testUsernameTwo(-1)> Rejected connection from 192.168.1.2:29761: Wrong certificate or password for existing user",
            "192.168.1.2",
        );
    }
}
