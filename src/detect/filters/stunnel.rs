use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "stunnel",
    description: "stunnel SSL/TLS tunnel certificate authentication failures",
    log_path: "/var/log/stunnel.log",
    date_format: "iso8601",
    patterns: &[r"SSL_accept from <HOST>:\d+ :.*SSL routines.*peer did not return a certificate"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn stunnel_ssl_accept_failure() {
        assert_filter_matches(
            "stunnel",
            "2011.11.21 14:29:16 LOG3[28228:140093368055552]: SSL_accept from 10.7.41.61:33454 : 140890C7: error:140890C7:SSL routines:SSL3_GET_CLIENT_CERTIFICATE:peer did not return a certificate",
            "10.7.41.61",
        );
    }
}
