use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "apache-noscript",
    description: "Apache requests for non-existent scripts",
    log_path: "/var/log/apache2/error.log",
    date_format: "common",
    patterns: &[
        r"client <HOST>.*script .* not found or unable to stat",
        r"client <HOST>.*File does not exist:.*\.php",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn apache_noscript_not_found() {
        assert_filter_matches(
            "apache-noscript",
            "[Sun Jun 09 07:57:47 2013] [error] [client 192.0.43.10] script '/usr/lib/cgi-bin/gitweb.cgiwp-login.php' not found or unable to stat",
            "192.0.43.10",
        );
    }

    #[test]
    fn apache_noscript_php_file() {
        assert_filter_matches(
            "apache-noscript",
            "[Tue Jul 22 06:48:30 2008] [error] [client 198.51.100.86] File does not exist: /home/southern/public_html/azenv.php",
            "198.51.100.86",
        );
    }
}
