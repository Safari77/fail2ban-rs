use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "domino-smtp",
    description: "IBM/HCL Domino SMTP authentication failures",
    log_path: "/local/notesdata/IBM_TECHNICAL_SUPPORT/console.log",
    date_format: "common",
    patterns: &[
        r"connecting host <HOST>",
        r"smtp.*\[<HOST>\] authentication failure",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn domino_smtp_connecting_host() {
        assert_filter_matches(
            "domino-smtp",
            "03-07-2005 23:07:20   SMTP Server: Authentication failed for user postmaster ; connecting host 1.2.3.4",
            "1.2.3.4",
        );
    }

    #[test]
    fn domino_smtp_auth_failure_brackets() {
        assert_filter_matches(
            "domino-smtp",
            "[28325:00010-3735542592] 22-06-2014 09:56:12   smtp: postmaster [1.2.3.4] authentication failure using internet password",
            "1.2.3.4",
        );
    }
}
