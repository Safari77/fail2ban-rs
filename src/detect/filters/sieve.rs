use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "sieve",
    description: "ManageSieve authentication failures",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[r"badlogin:.*\[<HOST>\].*authentication failure"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn sieve_auth_failure() {
        assert_filter_matches(
            "sieve",
            "Dec 1 20:36:56 mail sieve[23713]: badlogin: example.com[1.2.3.4] PLAIN authentication failure",
            "1.2.3.4",
        );
    }
}
