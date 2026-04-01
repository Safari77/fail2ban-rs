use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "proxmox",
    description: "Proxmox VE authentication failures",
    log_path: "/var/log/daemon.log",
    date_format: "syslog",
    patterns: &[r"pvedaemon\[.*authentication failure; rhost=<HOST>"],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn pvedaemon_auth_failure() {
        assert_filter_matches(
            "proxmox",
            "Jan 15 12:36:43 pve1 pvedaemon[1234]: authentication failure; rhost=192.0.2.123 user=root@pam msg=",
            "192.0.2.123",
        );
    }

    #[test]
    fn pvedaemon_auth_failure_v2() {
        assert_filter_matches(
            "proxmox",
            "Mar 10 08:00:01 host pvedaemon[5678]: authentication failure; rhost=192.0.2.124 user=admin@pve",
            "192.0.2.124",
        );
    }
}
