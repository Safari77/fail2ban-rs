use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "suhosin",
    description: "Suhosin PHP security extension alerts",
    log_path: "/var/log/apache2/error.log",
    date_format: "common",
    patterns: &[r"attacker '<HOST>'"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn suhosin_attacker() {
        assert_filter_matches(
            "suhosin",
            "Mar 11 22:52:12   lighttpd[53690]: (mod_fastcgi.c.2676) FastCGI-stderr: ALERT - configured request variable name length limit exceeded - dropped variable 'upqchi07vFfAFuBjnIKGIwiLrHo3Vt68T3yqvhQu2TqetQ78roy7Q6bpTfDUtYFR593/MA' (attacker '198.51.100.167', file '/usr/local/captiveportal/index.php')",
            "198.51.100.167",
        );
    }
}
