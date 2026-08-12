use super::*;

use crate::config::Config;

/// Parse a jail whose backend is described by `snippet`, returning the
/// resulting [`Backend`] or the load error.
fn parse_backend(snippet: &str) -> crate::error::Result<Backend> {
    let toml = format!(
        "[global]\n\n[jail.sshd]\nlog_path = \"/var/log/auth.log\"\nfilter = ['from <HOST>']\n{snippet}\n"
    );
    Config::parse(&toml).map(|c| c.jail["sshd"].backend.clone())
}

/// Unwrap an ipset backend's settings, panicking with the actual variant.
fn ipset_settings(backend: &Backend) -> (u32, String) {
    match backend {
        Backend::Ipset { maxelem, chain } => (*maxelem, chain.clone()),
        other => panic!("expected Ipset backend, got: {other:?}"),
    }
}

#[test]
fn test_bare_ipset_string_uses_both_defaults() {
    let backend = parse_backend("backend = \"ipset\"").unwrap();
    assert_eq!(ipset_settings(&backend), (65_536, "INPUT".to_string()));
}

#[test]
fn test_ipset_table_with_only_maxelem_defaults_the_chain() {
    let backend = parse_backend("[jail.sshd.backend.ipset]\nmaxelem = 200000").unwrap();
    assert_eq!(ipset_settings(&backend), (200_000, "INPUT".to_string()));
}

#[test]
fn test_ipset_table_with_only_chain_defaults_maxelem() {
    let backend = parse_backend("[jail.sshd.backend.ipset]\nchain = \"DOCKER-USER\"").unwrap();
    assert_eq!(
        ipset_settings(&backend),
        (65_536, "DOCKER-USER".to_string())
    );
}

#[test]
fn test_ipset_table_with_both_knobs() {
    let backend =
        parse_backend("[jail.sshd.backend.ipset]\nmaxelem = 1024\nchain = \"f2b_input\"").unwrap();
    assert_eq!(ipset_settings(&backend), (1024, "f2b_input".to_string()));
}

#[test]
fn test_empty_ipset_table_uses_both_defaults() {
    let backend = parse_backend("[jail.sshd.backend.ipset]").unwrap();
    assert_eq!(ipset_settings(&backend), (65_536, "INPUT".to_string()));
}

#[test]
fn test_unknown_key_in_ipset_table_is_named_in_the_error() {
    let err = parse_backend("[jail.sshd.backend.ipset]\nipsettype = \"hash:net\"")
        .expect_err("unknown ipset key must fail the load");
    let msg = err.to_string();
    assert!(msg.contains("ipsettype"), "error must name the key: {msg}");
}

#[test]
fn test_unknown_backend_name_lists_valid_variants() {
    let err = parse_backend("backend = \"ipsett\"").expect_err("typo must fail the load");
    let msg = err.to_string();
    assert!(msg.contains("ipsett"), "got: {msg}");
    for variant in VARIANTS {
        assert!(msg.contains(variant), "error must list {variant}: {msg}");
    }
}

#[test]
fn test_unknown_backend_name_in_table_form_lists_valid_variants() {
    let err = parse_backend("[jail.sshd.backend.ipsett]\nmaxelem = 10")
        .expect_err("a typo'd table key must fail the load");
    let msg = err.to_string();
    assert!(msg.contains("ipsett"), "got: {msg}");
    for variant in VARIANTS {
        assert!(msg.contains(variant), "error must list {variant}: {msg}");
    }
}

#[test]
fn test_nftables_string_still_deserializes() {
    let backend = parse_backend("backend = \"nftables\"").unwrap();
    assert!(matches!(backend, Backend::Nftables), "got: {backend:?}");
}

#[test]
fn test_iptables_string_still_deserializes() {
    let backend = parse_backend("backend = \"iptables\"").unwrap();
    assert!(matches!(backend, Backend::Iptables), "got: {backend:?}");
}

#[test]
fn test_omitted_backend_defaults_to_nftables() {
    let backend = parse_backend("").unwrap();
    assert!(matches!(backend, Backend::Nftables), "got: {backend:?}");
}

#[test]
fn test_script_table_still_deserializes() {
    let backend = parse_backend(
        "[jail.sshd.backend.script]\nban_cmd = \"ban <IP>\"\nunban_cmd = \"unban <IP>\"",
    )
    .unwrap();
    match backend {
        Backend::Script { ban_cmd, unban_cmd } => {
            assert_eq!(ban_cmd, "ban <IP>");
            assert_eq!(unban_cmd, "unban <IP>");
        }
        other => panic!("expected Script backend, got: {other:?}"),
    }
}

#[test]
fn test_script_table_missing_unban_cmd_errors() {
    let err = parse_backend("[jail.sshd.backend.script]\nban_cmd = \"ban <IP>\"")
        .expect_err("a script backend without unban_cmd must fail");
    assert!(err.to_string().contains("unban_cmd"), "got: {err}");
}

#[test]
fn test_unknown_key_in_script_table_is_named_in_the_error() {
    let err = parse_backend(
        "[jail.sshd.backend.script]\nban_cmd = \"b\"\nunban_cmd = \"u\"\nreload_cmd = \"r\"",
    )
    .expect_err("unknown script key must fail the load");
    assert!(err.to_string().contains("reload_cmd"), "got: {err}");
}

#[test]
fn test_bare_script_string_points_at_the_table_form() {
    let err = parse_backend("backend = \"script\"")
        .expect_err("the script backend has mandatory settings");
    assert!(err.to_string().contains("ban_cmd"), "got: {err}");
}

#[test]
fn test_settingless_backend_in_table_form_errors() {
    let err = parse_backend("[jail.sshd.backend.nftables]")
        .expect_err("nftables takes no settings table");
    let msg = err.to_string();
    assert!(msg.contains("nftables"), "got: {msg}");
    assert!(msg.contains("takes no settings"), "got: {msg}");
}

#[test]
fn test_two_backend_tables_error() {
    let err = parse_backend(
        "[jail.sshd.backend.ipset]\nmaxelem = 10\n\n[jail.sshd.backend.script]\nban_cmd = \"b\"\nunban_cmd = \"u\"",
    )
    .expect_err("a jail selects exactly one backend");
    assert!(err.to_string().contains("extra key"), "got: {err}");
}

#[test]
fn test_empty_backend_table_errors() {
    let err = parse_backend("[jail.sshd.backend]").expect_err("an empty backend table is a typo");
    assert!(
        err.to_string().contains("empty backend table"),
        "got: {err}"
    );
}

#[test]
fn test_ipset_backend_round_trips_through_serialization() {
    let original = Backend::Ipset {
        maxelem: 4096,
        chain: "DOCKER-USER".to_string(),
    };
    let encoded = toml::to_string(&original).expect("serialize backend");
    let decoded: Backend = toml::from_str(&encoded).expect("deserialize backend");
    assert_eq!(ipset_settings(&decoded), (4096, "DOCKER-USER".to_string()));
}
