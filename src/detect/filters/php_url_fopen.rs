use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "php-url-fopen",
    description: "PHP remote file inclusion attempts via URL fopen",
    log_path: "/var/log/apache2/access.log",
    date_format: "common",
    patterns: &[r#"<HOST> .*"(?:GET|POST).*\?.*=http://"#],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn php_url_fopen_rfi() {
        assert_filter_matches(
            "php-url-fopen",
            r#"66.185.212.172 - - [26/Mar/2009:08:44:20 -0500] "GET /index.php?n=http://eatmyfood.hostinginfive.com/pizza.htm? HTTP/1.1" 200 114 "-" "Mozilla""#,
            "66.185.212.172",
        );
    }
}
