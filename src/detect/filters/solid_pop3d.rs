use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "solid-pop3d",
    description: "Solid POP3 daemon authentication failures",
    log_path: "/var/log/mail.log",
    date_format: "syslog",
    patterns: &[r"solid-pop3d\[\d+\]: authentication failed:.* - <HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn solid_pop3d_no_such_user() {
        assert_filter_matches(
            "solid-pop3d",
            "Nov 15 00:34:53 rmc1pt2-2-35-70 solid-pop3d[3822]: authentication failed: no such user: adrian - 123.33.44.45",
            "123.33.44.45",
        );
    }
}
