use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "mssql-auth",
    description: "Microsoft SQL Server authentication failures",
    log_path: "/var/opt/mssql/log/errorlog",
    date_format: "iso8601",
    patterns: &[r"Login failed for user .*\[CLIENT: <HOST>\]"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn mssql_auth_login_failed() {
        assert_filter_matches(
            "mssql-auth",
            "2020-02-24 16:05:21.00 Logon       Login failed for user 'Backend'. Reason: Could not find a login matching the name provided. [CLIENT: 192.0.2.1]",
            "192.0.2.1",
        );
    }
}
