use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "wuftpd",
    description: "WU-FTPD authentication failures",
    log_path: "/var/log/auth.log",
    date_format: "syslog",
    patterns: &[r"wu-ftpd\[\d+\]: failed login from .* \[<HOST>\]"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn wuftpd_failed_login() {
        assert_filter_matches(
            "wuftpd",
            "Oct  6 09:59:26 myserver wu-ftpd[18760]: failed login from hj-145-173-a8.bta.net.cn [202.108.145.173]",
            "202.108.145.173",
        );
    }
}
