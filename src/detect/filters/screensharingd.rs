use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "screensharingd",
    description: "macOS Screen Sharing authentication failures",
    log_path: "/var/log/system.log",
    date_format: "syslog",
    patterns: &[r"screensharingd\[\d+\]: Authentication: FAILED.*Viewer Address: <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn screensharingd_auth_failed() {
        assert_filter_matches(
            "screensharingd",
            "Oct 27 2015 12:35:40 test1.beezwax.net screensharingd[1170]: Authentication: FAILED :: User Name: sdfsdfs () mro :: Viewer Address: 192.168.5.247 :: Type: DH",
            "192.168.5.247",
        );
    }
}
