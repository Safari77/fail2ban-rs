use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "squirrelmail",
    description: "SquirrelMail webmail authentication failures",
    log_path: "/var/lib/squirrelmail/prefs/squirrelmail_access_log",
    date_format: "common",
    patterns: &[r"from <HOST>: Unknown user or password incorrect"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn squirrelmail_login_error() {
        assert_filter_matches(
            "squirrelmail",
            "10/06/2013 15:50:41 [LOGIN_ERROR] dadas (mydomain.org) from 151.64.44.11: Unknown user or password incorrect.",
            "151.64.44.11",
        );
    }
}
