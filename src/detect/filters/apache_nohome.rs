use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "apache-nohome",
    description: "Apache requests for non-existent home directories",
    log_path: "/var/log/apache2/error.log",
    date_format: "common",
    patterns: &[r"client <HOST>.*File does not exist:.*~"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn apache_nohome_tilde() {
        assert_filter_matches(
            "apache-nohome",
            "[Sat Jun 01 11:23:08 2013] [error] [client 1.2.3.4] File does not exist: /xxx/~",
            "1.2.3.4",
        );
    }
}
