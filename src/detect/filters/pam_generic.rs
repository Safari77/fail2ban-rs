use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "pam-generic",
    description: "Generic PAM authentication failures",
    log_path: "/var/log/auth.log",
    date_format: "syslog",
    patterns: &[r"pam_unix.*authentication failure;.* rhost=<HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn pam_pure_ftpd() {
        assert_filter_matches(
            "pam-generic",
            "Feb  7 15:10:42 example pure-ftpd: (pam_unix) authentication failure; logname= uid=0 euid=0 tty=pure-ftpd ruser=sample-user rhost=192.168.1.1",
            "192.168.1.1",
        );
    }

    #[test]
    fn pam_sshd() {
        assert_filter_matches(
            "pam-generic",
            "May 12 09:47:54 vaio sshd[16004]: (pam_unix) authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=71.13.115.12  user=root",
            "71.13.115.12",
        );
    }

    #[test]
    fn pam_vsftpd() {
        assert_filter_matches(
            "pam-generic",
            "Jul 19 18:11:26 srv2 vsftpd: pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=an8767 rhost=10.20.30.40",
            "10.20.30.40",
        );
    }

    #[test]
    fn pam_old_format_still_matches() {
        // Pre-0.99.2.0 format — our broader pattern matches it too, which is fine
        // since it's still a real auth failure.
        assert_filter_matches(
            "pam-generic",
            "Nov 25 17:12:13 webmail pop(pam_unix)[4920]: authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=192.168.10.3 user=mailuser",
            "192.168.10.3",
        );
    }
}
