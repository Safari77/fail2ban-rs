use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "selinux-ssh",
    description: "SELinux SSH access denials",
    log_path: "/var/log/audit/audit.log",
    date_format: "epoch",
    patterns: &[r"addr=<HOST>.*terminal=ssh.*res=failed"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn selinux_ssh_failed() {
        assert_filter_matches(
            "selinux-ssh",
            r#"type=USER_ERR msg=audit(1373330717.000:4070): user pid=12000 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:bad_ident acct="?" exe="/usr/sbin/sshd" hostname=173.242.116.187 addr=173.242.116.187 terminal=ssh res=failed'"#,
            "173.242.116.187",
        );
    }
}
