use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "oracleims",
    description: "Oracle IMS SMTP authentication failures",
    log_path: "/var/log/oracleims/mail.log",
    date_format: "iso8601",
    patterns: &[r#"\|<HOST>\|\d+".*mi="Bad password""#],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

    #[test]
    fn oracleims_bad_password() {
        assert_filter_matches(
            "oracleims",
            r#"<co ts="2014-06-02T16:06:33.99" pi="72aa.17f0.25622" sc="tcp_local" dr="+" ac="U" tr="TCP|192.245.12.223|25|89.96.245.78|4299" ap="SMTP" mi="Bad password" us="nic@transcend.com" di="535 5.7.8 Bad username or password (Authentication failed)."/>"#,
            "89.96.245.78",
        );
    }

    #[test]
    fn oracleims_no_match_success() {
        assert_filter_no_match(
            "oracleims",
            r#"<co ts="2014-06-02T22:02:13.94" pi="72a9.3b4.3774" sc="tcp_submit" dr="+" ac="U" tr="TCP|192.245.12.223|465|23.122.129.179|60766" ap="SMTP/TLS-128-RC4" mi="Authentication successful - switched to channel tcp_submit" us="jaugustine@example.org" di="235 2.7.0 LOGIN authentication successful."/>"#,
        );
    }
}
