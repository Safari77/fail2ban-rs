use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "apache-shellshock",
    description: "Apache Shellshock (CVE-2014-6271) exploit attempts",
    log_path: "/var/log/apache2/error.log",
    date_format: "common",
    patterns: &[r"client <HOST>.*AH01215:.*(?:bash|sh):.*HTTP_"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn apache_shellshock_exploit() {
        assert_filter_matches(
            "apache-shellshock",
            "[Thu Sep 25 09:27:18.813902 2014] [cgi:error] [pid 16860] [client 89.207.132.76:59635] AH01215: /bin/bash: warning: HTTP_TEST: ignoring function definition attempt",
            "89.207.132.76",
        );
    }
}
