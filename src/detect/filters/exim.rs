use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "exim",
    description: "Exim MTA authentication failures",
    log_path: "/var/log/exim4/mainlog",
    date_format: "iso8601",
    patterns: &[r"authenticator failed for.*\[<HOST>\].*535 Incorrect authentication"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn exim_auth_failed() {
        assert_filter_matches(
            "exim",
            "2013-01-04 17:03:46 login authenticator failed for rrcs-24-106-174-74.se.biz.rr.com ([192.168.2.33]) [24.106.174.74]: 535 Incorrect authentication data (set_id=brian)",
            "24.106.174.74",
        );
    }

    #[test]
    fn exim_auth_failed_simple() {
        assert_filter_matches(
            "exim",
            "2013-06-12 03:57:58 login authenticator failed for (ylmf-pc) [120.196.140.45]: 535 Incorrect authentication data: 1 Time(s)",
            "120.196.140.45",
        );
    }
}
