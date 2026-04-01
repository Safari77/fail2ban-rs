use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "apache-botsearch",
    description: "Apache requests for known exploit and scanner paths",
    log_path: "/var/log/apache2/error.log",
    date_format: "common",
    patterns: &[r"client <HOST>.*File does not exist:.*/(wp-login|xmlrpc|\.env|phpmyadmin)"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

    #[test]
    fn phpmyadmin_not_exist() {
        assert_filter_matches(
            "apache-botsearch",
            "[Sun Jun 09 07:57:47 2013] [error] [client 115.249.248.145] File does not exist: /var/www/phpmyadmin",
            "115.249.248.145",
        );
    }

    #[test]
    fn dotenv_not_exist() {
        assert_filter_matches(
            "apache-botsearch",
            "[Mon Dec 23 13:12:31 2013] [error] [client 10.20.30.40] File does not exist: /var/www/html/.env",
            "10.20.30.40",
        );
    }

    #[test]
    fn no_match_unrelated_path() {
        assert_filter_no_match(
            "apache-botsearch",
            "[Sat Mar 08 02:49:57 2014] [error] [client 92.43.20.165] script '/var/www/forum/mail.php' not found or unable to stat",
        );
    }
}
