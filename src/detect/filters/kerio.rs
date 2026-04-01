use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "kerio",
    description: "Kerio Connect SMTP spam attack detection",
    log_path: "/var/log/kerio/mail.log",
    date_format: "common",
    patterns: &[
        r"SMTP Spam attack detected from <HOST>,",
        r"IP address <HOST>",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn kerio_smtp_spam() {
        assert_filter_matches(
            "kerio",
            "[18/Jan/2014 06:41:25] SMTP Spam attack detected from 202.169.236.195, client closed connection before SMTP greeting",
            "202.169.236.195",
        );
    }
}
