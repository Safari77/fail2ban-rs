//! Built-in filter patterns for common services.
//!
//! Each filter lives in its own sub-module with definition and tests.
//! Used by `fail2ban-rs gen-config --service <name>` to generate jail
//! configurations without manual pattern writing.

/// A built-in filter template for a service.
pub struct FilterTemplate {
    /// Service identifier (e.g. "sshd").
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Default log file path.
    pub log_path: &'static str,
    /// Date format preset.
    pub date_format: &'static str,
    /// Regex patterns with `<HOST>` placeholder.
    pub patterns: &'static [&'static str],
}

mod apache_auth;
mod apache_botsearch;
mod apache_modsecurity;
mod apache_nohome;
mod apache_noscript;
mod apache_overflows;
mod apache_shellshock;
mod asterisk;
mod bitwarden;
mod centreon;
mod counter_strike;
mod courier_auth;
mod courier_smtp;
mod cyrus_imap;
mod directadmin;
mod domino_smtp;
mod dovecot;
mod dropbear;
mod drupal;
mod exim;
mod freeswitch;
mod froxlor_auth;
mod gitlab;
mod grafana;
mod groupoffice;
mod gssftpd;
mod guacamole;
mod haproxy;
mod horde;
mod kerio;
mod lighttpd_auth;
mod monit;
mod monitorix;
mod mssql_auth;
mod murmur;
mod mysqld;
mod nagios;
mod named_refused;
mod netfilter_portscan;
mod nginx_auth;
mod nginx_bad_request;
mod nginx_botsearch;
mod nginx_forbidden;
mod nginx_limit_req;
mod nsd;
mod openhab;
mod openvpn;
mod openwebmail;
mod oracleims;
mod pam_generic;
mod perdition;
mod pf_portscan;
mod pfsense_portscan;
mod php_url_fopen;
mod phpmyadmin_syslog;
mod portsentry;
mod postfix;
mod proftpd;
mod proxmox;
mod pure_ftpd;
mod qmail;
mod roundcube_auth;
mod routeros_auth;
mod scanlogd;
mod screensharingd;
mod selinux_ssh;
mod sendmail_auth;
mod sieve;
mod softethervpn;
mod sogo_auth;
mod solid_pop3d;
mod squid;
mod squirrelmail;
mod sshd;
mod stunnel;
mod suhosin;
mod three_proxy;
mod tine20;
mod traefik;
mod uwimap_auth;
mod vaultwarden;
mod vsftpd;
mod webmin_auth;
mod wuftpd;
mod xinetd_fail;
mod xrdp;
mod znc_adminlog;
mod zoneminder;

/// All built-in filters.
pub const FILTERS: &[FilterTemplate] = &[
    sshd::FILTER,
    nginx_auth::FILTER,
    nginx_botsearch::FILTER,
    postfix::FILTER,
    dovecot::FILTER,
    vsftpd::FILTER,
    asterisk::FILTER,
    mysqld::FILTER,
    apache_auth::FILTER,
    apache_botsearch::FILTER,
    vaultwarden::FILTER,
    bitwarden::FILTER,
    proxmox::FILTER,
    gitlab::FILTER,
    grafana::FILTER,
    haproxy::FILTER,
    drupal::FILTER,
    traefik::FILTER,
    openvpn::FILTER,
    nginx_limit_req::FILTER,
    nginx_forbidden::FILTER,
    nginx_bad_request::FILTER,
    proftpd::FILTER,
    pure_ftpd::FILTER,
    courier_auth::FILTER,
    roundcube_auth::FILTER,
    pam_generic::FILTER,
    apache_modsecurity::FILTER,
    dropbear::FILTER,
    netfilter_portscan::FILTER,
    pf_portscan::FILTER,
    pfsense_portscan::FILTER,
    named_refused::FILTER,
    lighttpd_auth::FILTER,
    phpmyadmin_syslog::FILTER,
    webmin_auth::FILTER,
    squid::FILTER,
    freeswitch::FILTER,
    softethervpn::FILTER,
    guacamole::FILTER,
    mssql_auth::FILTER,
    sogo_auth::FILTER,
    horde::FILTER,
    courier_smtp::FILTER,
    cyrus_imap::FILTER,
    routeros_auth::FILTER,
    znc_adminlog::FILTER,
    screensharingd::FILTER,
    directadmin::FILTER,
    squirrelmail::FILTER,
    monit::FILTER,
    openhab::FILTER,
    nsd::FILTER,
    wuftpd::FILTER,
    portsentry::FILTER,
    kerio::FILTER,
    xrdp::FILTER,
    apache_nohome::FILTER,
    apache_noscript::FILTER,
    apache_overflows::FILTER,
    apache_shellshock::FILTER,
    sendmail_auth::FILTER,
    exim::FILTER,
    centreon::FILTER,
    counter_strike::FILTER,
    domino_smtp::FILTER,
    froxlor_auth::FILTER,
    groupoffice::FILTER,
    gssftpd::FILTER,
    murmur::FILTER,
    nagios::FILTER,
    openwebmail::FILTER,
    php_url_fopen::FILTER,
    qmail::FILTER,
    scanlogd::FILTER,
    selinux_ssh::FILTER,
    sieve::FILTER,
    solid_pop3d::FILTER,
    suhosin::FILTER,
    tine20::FILTER,
    uwimap_auth::FILTER,
    xinetd_fail::FILTER,
    three_proxy::FILTER,
    monitorix::FILTER,
    zoneminder::FILTER,
    perdition::FILTER,
    stunnel::FILTER,
    oracleims::FILTER,
];

/// Look up a filter template by name.
pub fn find(name: &str) -> Option<&'static FilterTemplate> {
    FILTERS.iter().find(|f| f.name == name)
}

/// Generate a TOML jail configuration for a service.
pub fn gen_config(template: &FilterTemplate) -> String {
    use std::fmt::Write;
    let mut out = format!("[jail.{}]\n", template.name);
    let _ = writeln!(out, "# {}", template.description);
    let _ = writeln!(out, "log_path = \"{}\"", template.log_path);
    let _ = writeln!(out, "date_format = \"{}\"", template.date_format);
    out.push_str("filter = [\n");
    for pattern in template.patterns {
        let _ = writeln!(out, "    '{pattern}',");
    }
    out.push_str("]\n");
    out
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls
)]
pub(crate) mod test_util {
    use super::*;
    use crate::detect::matcher::JailMatcher;
    use std::net::IpAddr;

    /// Build a JailMatcher from a named filter and assert it extracts the expected IP.
    pub fn assert_filter_matches(filter_name: &str, line: &str, expected_ip: &str) {
        let f = find(filter_name).unwrap_or_else(|| panic!("filter not found: {filter_name}"));
        let patterns: Vec<String> = f.patterns.iter().map(|p| p.to_string()).collect();
        let m = JailMatcher::new(&patterns).unwrap();
        let result = m.try_match(line);
        let expected: IpAddr = expected_ip.parse().unwrap();
        assert!(
            result.is_some(),
            "filter '{filter_name}' should match line: {line}"
        );
        assert_eq!(
            result.unwrap().ip,
            expected,
            "filter '{filter_name}' extracted wrong IP from: {line}"
        );
    }

    /// Assert that a line does NOT match a filter.
    pub fn assert_filter_no_match(filter_name: &str, line: &str) {
        let f = find(filter_name).unwrap();
        let patterns: Vec<String> = f.patterns.iter().map(|p| p.to_string()).collect();
        let m = JailMatcher::new(&patterns).unwrap();
        assert!(
            m.try_match(line).is_none(),
            "filter '{filter_name}' should NOT match line: {line}"
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod tests {
    use super::*;
    use crate::detect::pattern::expand_host;

    #[test]
    fn find_sshd() {
        let f = find("sshd").unwrap();
        assert_eq!(f.name, "sshd");
        assert!(!f.patterns.is_empty());
    }

    #[test]
    fn find_nonexistent() {
        assert!(find("nonexistent").is_none());
    }

    #[test]
    fn all_filters_have_host() {
        for f in FILTERS {
            for pattern in f.patterns {
                assert!(
                    pattern.contains("<HOST>"),
                    "filter {} pattern missing <HOST>: {}",
                    f.name,
                    pattern
                );
            }
        }
    }

    #[test]
    fn all_patterns_compile() {
        for f in FILTERS {
            for pattern in f.patterns {
                let expanded = expand_host(pattern);
                assert!(
                    expanded.is_ok(),
                    "filter {} pattern failed to expand: {} — {}",
                    f.name,
                    pattern,
                    expanded.unwrap_err()
                );
                let expanded = expanded.unwrap();
                let re = regex::Regex::new(&expanded);
                assert!(
                    re.is_ok(),
                    "filter {} expanded pattern failed to compile: {} — {}",
                    f.name,
                    expanded,
                    re.unwrap_err()
                );
            }
        }
    }

    #[test]
    fn gen_config_sshd() {
        let f = find("sshd").unwrap();
        let toml = gen_config(f);
        assert!(toml.contains("[jail.sshd]"));
        assert!(toml.contains("/var/log/auth.log"));
        assert!(toml.contains("syslog"));
        assert!(toml.contains("<HOST>"));
    }

    #[test]
    fn gen_config_all_services() {
        for f in FILTERS {
            let toml = gen_config(f);
            assert!(
                toml.contains(&format!("[jail.{}]", f.name)),
                "gen_config missing jail header for {}",
                f.name
            );
        }
    }

    #[test]
    fn filter_count() {
        assert_eq!(FILTERS.len(), 88, "expected 88 built-in filters");
    }
}
