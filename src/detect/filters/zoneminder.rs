use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "zoneminder",
    description: "ZoneMinder video surveillance authentication failures",
    log_path: "/var/log/apache2/error.log",
    date_format: "common",
    patterns: &[
        r"client <HOST>.*Login denied for user",
        r"client <HOST>.*Could not retrieve user .* details",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn zoneminder_login_denied() {
        assert_filter_matches(
            "zoneminder",
            r#"[Mon Mar 28 16:50:49.522240 2016] [:error] [pid 1795] [client 10.1.1.1:50700] WAR [Login denied for user "username1"], referer: https://zoneminder/"#,
            "10.1.1.1",
        );
    }

    #[test]
    fn zoneminder_user_not_found() {
        assert_filter_matches(
            "zoneminder",
            "[Sun Mar 28 16:53:00.472693 2021] [php7:notice] [pid 11328] [client 10.1.1.1:39568] ERR [Could not retrieve user username1 details], referer: https://zm/zm/?view=logout",
            "10.1.1.1",
        );
    }
}
