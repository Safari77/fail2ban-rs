use super::*;

#[test]
fn no_jails_error() {
    let toml = "[global]\n";
    assert!(Config::parse(toml).is_err());
}

#[test]
fn no_enabled_jails_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    enabled = false
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn missing_host_placeholder_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    enabled = true
    log_path = "/var/log/auth.log"
    filter = ['Failed password for .*']
    "#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn zero_max_retry_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    enabled = true
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    max_retry = 0
    "#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn zero_find_time_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    find_time = 0
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("find_time"), "got: {err}");
}

#[test]
fn negative_find_time_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    find_time = -10
    "#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn zero_ban_time_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ban_time = 0
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("ban_time"), "got: {err}");
}

#[test]
fn permanent_ban_time_ok() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ban_time = -1
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].ban_time, -1);
}

#[test]
fn empty_filter_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = []
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("no filter"), "got: {err}");
}

// ---------------------------------------------------------------------------
// Global / logging validation
// ---------------------------------------------------------------------------

#[test]
fn zero_channel_size_error() {
    let toml = r#"
    [global]
    channel_size = 0

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("channel_size"), "got: {err}");
}

#[test]
fn unknown_logging_level_error() {
    let toml = r#"
    [global]

    [logging]
    level = "verbose"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("logging.level"), "got: {err}");
}

#[test]
fn unknown_logging_format_error() {
    let toml = r#"
    [global]

    [logging]
    format = "yaml"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("logging.format"), "got: {err}");
}

#[test]
fn unknown_logging_destination_error() {
    let toml = r#"
    [global]

    [logging]
    destination = "datadog"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(
        err.to_string().contains("logging.destination"),
        "got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Timing / bantime validation
// ---------------------------------------------------------------------------

#[test]
fn ban_time_below_negative_one_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ban_time = -2
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("ban_time"), "got: {err}");
}

#[test]
fn zero_bantime_maxtime_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    bantime_maxtime = 0
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("bantime_maxtime"), "got: {err}");
}

#[test]
fn zero_bantime_multiplier_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    bantime_multipliers = [1, 2, 0, 8]
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(
        err.to_string().contains("bantime_multipliers"),
        "got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Network validation
// ---------------------------------------------------------------------------

#[test]
fn zero_port_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    port = ["0"]
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("port"), "got: {err}");
}

#[test]
fn max_port_ok() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    port = ["65535"]
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].port, vec!["65535".to_string()]);
}

#[test]
fn invalid_ignoreip_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ignoreip = ["not-an-ip"]
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("ignoreip"), "got: {err}");
}

#[test]
fn bare_ip_ignoreip_ok() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ignoreip = ["192.168.1.10", "::1", "10.0.0.0/8"]
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].ignoreip.len(), 3);
}

#[test]
fn webhook_without_scheme_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    webhook = "example.com/hook"
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("webhook"), "got: {err}");
}

#[test]
fn webhook_https_ok() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    webhook = "https://example.com/hook"
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(
        config.jail["sshd"].webhook.as_deref(),
        Some("https://example.com/hook")
    );
}

// ---------------------------------------------------------------------------
// Pattern compilation validation
// ---------------------------------------------------------------------------

#[test]
fn invalid_filter_regex_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST> (unclosed']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("filter regex"), "got: {err}");
}

#[test]
fn invalid_ignoreregex_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ignoreregex = ['(unclosed']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("ignoreregex"), "got: {err}");
}

// ---------------------------------------------------------------------------
// MaxMind field / global path coupling
// ---------------------------------------------------------------------------

#[test]
fn maxmind_field_without_global_path_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    maxmind = ["asn"]
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("maxmind_asn"), "got: {err}");
}

#[test]
fn maxmind_field_with_global_path_ok() {
    let toml = r#"
    [global]
    maxmind_asn = "/var/lib/GeoLite2-ASN.mmdb"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    maxmind = ["asn"]
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].maxmind.len(), 1);
}

// ---------------------------------------------------------------------------
// ipset backend settings
// ---------------------------------------------------------------------------

/// Parse a single-jail config whose jail carries `extra` lines appended after
/// the standard keys (a `backend = ...` line or a `[jail.<name>.backend.*]`
/// table).
fn parse_jail(name: &str, extra: &str) -> crate::error::Result<Config> {
    let toml = format!(
        "[global]\n\n[jail.{name}]\nlog_path = \"/var/log/auth.log\"\nfilter = ['from <HOST>']\n{extra}\n"
    );
    Config::parse(&toml)
}

/// Parse a jail using the ipset backend with the given settings table body.
fn parse_ipset_jail(name: &str, settings: &str) -> crate::error::Result<Config> {
    parse_jail(name, &format!("[jail.{name}.backend.ipset]\n{settings}"))
}

#[test]
fn test_ipset_jail_name_at_the_length_limit_validates() {
    let name = "a".repeat(26);
    parse_jail(&name, "backend = \"ipset\"").expect("26 characters is the documented maximum");
}

#[test]
fn test_ipset_jail_name_over_the_length_limit_errors() {
    let name = "a".repeat(27);
    let err = parse_jail(&name, "backend = \"ipset\"")
        .expect_err("27 characters overflows ipset's set-name cap");
    let msg = err.to_string();
    assert!(msg.contains(&name), "error must name the jail: {msg}");
    assert!(msg.contains("26"), "error must state the limit: {msg}");
}

#[test]
fn test_long_jail_name_is_still_fine_for_other_backends() {
    let name = "a".repeat(27);
    parse_jail(&name, "backend = \"nftables\"").expect("the limit is ipset-specific");
}

#[test]
fn test_ipset_maxelem_zero_errors() {
    let err = parse_ipset_jail("sshd", "maxelem = 0").expect_err("a set must hold something");
    assert!(err.to_string().contains("maxelem"), "got: {err}");
}

#[test]
fn test_ipset_maxelem_one_validates() {
    parse_ipset_jail("sshd", "maxelem = 1").expect("one entry is a legal capacity");
}

#[test]
fn test_ipset_maxelem_at_u32_max_validates() {
    parse_ipset_jail("sshd", "maxelem = 4294967295").expect("u32::MAX is a legal capacity");
}

#[test]
fn test_ipset_empty_chain_errors() {
    let err = parse_ipset_jail("sshd", "chain = \"\"").expect_err("an empty chain is a typo");
    assert!(err.to_string().contains("chain"), "got: {err}");
}

#[test]
fn test_ipset_chain_with_shell_metacharacters_errors() {
    // Argv construction already makes this inert; the check is fail-fast UX.
    let err = parse_ipset_jail("sshd", "chain = \"INPUT; rm -rf /\"")
        .expect_err("only [A-Za-z0-9_-] is accepted");
    assert!(err.to_string().contains("chain"), "got: {err}");
}

#[test]
fn test_ipset_chain_with_leading_hyphen_errors() {
    // "-F" is charset-clean but would reach iptables looking like a flag;
    // insertion failure there is non-fatal, so it must die at load instead.
    for chain in ["-F", "-INPUT", "--flush"] {
        let err = parse_ipset_jail("sshd", &format!("chain = \"{chain}\""))
            .expect_err("a leading hyphen must be rejected");
        assert!(err.to_string().contains("chain"), "got: {err}");
    }
}

#[test]
fn test_ipset_chain_with_interior_hyphen_still_validates() {
    parse_ipset_jail("sshd", "chain = \"DOCKER-USER\"")
        .expect("interior hyphens stay allowed — only the leading position is refused");
}

#[test]
fn test_ipset_over_long_chain_errors() {
    let chain = "c".repeat(29);
    let err = parse_ipset_jail("sshd", &format!("chain = \"{chain}\""))
        .expect_err("29 characters exceeds the chain-name cap");
    assert!(err.to_string().contains("chain"), "got: {err}");
}

#[test]
fn test_ipset_chain_at_the_length_limit_validates() {
    let chain = "c".repeat(28);
    parse_ipset_jail("sshd", &format!("chain = \"{chain}\"")).expect("28 characters is allowed");
}

#[test]
fn test_ipset_hyphenated_and_underscored_chains_validate() {
    for chain in ["DOCKER-USER", "f2b_input"] {
        parse_ipset_jail("sshd", &format!("chain = \"{chain}\""))
            .unwrap_or_else(|e| panic!("{chain} must validate: {e}"));
    }
}

#[test]
fn test_bare_ipset_backend_validates_with_defaults() {
    let config = parse_jail("sshd", "backend = \"ipset\"").expect("defaults must validate");
    match &config.jail["sshd"].backend {
        Backend::Ipset { maxelem, chain } => {
            assert_eq!(*maxelem, 65_536);
            assert_eq!(chain, "INPUT");
        }
        other => panic!("expected Ipset backend, got: {other:?}"),
    }
}
