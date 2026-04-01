use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "monitorix",
    description: "Monitorix system monitoring authentication and access failures",
    log_path: "/var/log/monitorix-httpd",
    date_format: "common",
    patterns: &[
        r"NOTEXIST - \[<HOST>\]",
        r"AUTHERR - \[<HOST>\]",
        r"NOTALLOWED - \[<HOST>\]",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn monitorix_notexist() {
        assert_filter_matches(
            "monitorix",
            "Wed Apr 14 08:54:22 2021 - NOTEXIST - [127.0.0.1] File does not exist: /manager/html",
            "127.0.0.1",
        );
    }

    #[test]
    fn monitorix_notallowed() {
        assert_filter_matches(
            "monitorix",
            "Wed Apr 14 11:24:31 2021 - NOTALLOWED - [127.0.0.1] Access not allowed: /monitorix/",
            "127.0.0.1",
        );
    }

    #[test]
    fn monitorix_autherr() {
        assert_filter_matches(
            "monitorix",
            "Wed Apr 14 11:26:08 2021 - AUTHERR - [127.0.0.1] Authentication error: /monitorix/",
            "127.0.0.1",
        );
    }
}
