use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "grafana",
    description: "Grafana login failures",
    log_path: "/var/log/grafana/grafana.log",
    date_format: "iso8601",
    patterns: &[
        r"Invalid username or password.*remote_addr=<HOST>",
        r"User not found.*remote_addr=<HOST>",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn invalid_username_or_password() {
        assert_filter_matches(
            "grafana",
            r#"t=2020-10-19T17:44:33+0200 lvl=eror msg="Invalid username or password" logger=context userId=0 orgId=0 uname= error="Invalid Username or Password" remote_addr=182.56.23.12"#,
            "182.56.23.12",
        );
    }

    #[test]
    fn user_not_found() {
        assert_filter_matches(
            "grafana",
            r#"t=2020-10-19T18:44:33+0200 lvl=eror msg="Invalid username or password" logger=context userId=0 orgId=0 uname= error="User not found" remote_addr=182.56.23.13"#,
            "182.56.23.13",
        );
    }
}
