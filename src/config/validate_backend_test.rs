use super::*;

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

// ---------------------------------------------------------------------------
// Backend-reserved jail names (generated firewall names must not collide)
// ---------------------------------------------------------------------------

/// Parse a jail named `name` using the bare `backend`.
fn parse_backend_jail(name: &str, backend: &str) -> crate::error::Result<Config> {
    parse_jail(name, &format!("backend = \"{backend}\""))
}

#[test]
fn test_nftables_jail_named_chain_errors() {
    let err = parse_backend_jail("chain", "nftables").expect_err("f2b-chain is the legacy chain");
    let msg = err.to_string();
    assert!(msg.contains("'chain'"), "error must name the jail: {msg}");
    assert!(
        msg.contains("legacy chain"),
        "error must explain why: {msg}"
    );
}

/// Parse a config with two enabled jails, each with its own `backend` value.
fn parse_two_jails(a: (&str, &str), b: (&str, &str)) -> crate::error::Result<Config> {
    let jail = |(name, backend): (&str, &str)| {
        format!(
            "[jail.{name}]\nlog_path = \"/var/log/auth.log\"\nfilter = ['from <HOST>']\n\
             backend = \"{backend}\"\n"
        )
    };
    Config::parse(&format!("[global]\n\n{}\n{}", jail(a), jail(b)))
}

/// C3: a name merely ending in the v6 suffix is fine when nothing collides.
#[test]
fn test_jail_name_ending_in_v6_suffix_alone_validates() {
    parse_backend_jail("smtp465", "ipset").expect("no jail 'smtp46' exists");
    parse_backend_jail("nginx-ipv6", "ipset").expect("no collision");
    parse_backend_jail("sshd-v6", "nftables").expect("no jail 'sshd' exists");
}

#[test]
fn test_nftables_jail_name_containing_v6_mid_name_validates() {
    parse_backend_jail("sshd-v6x", "nftables").expect("only the suffix collides");
    parse_backend_jail("chains", "nftables").expect("only the exact name is reserved");
}

#[test]
fn test_ipset_jail_pair_foo_and_foo6_errors() {
    let err = parse_two_jails(("web", "ipset"), ("web6", "ipset"))
        .expect_err("web6's inet set is web's inet6 set");
    let msg = err.to_string();
    assert!(msg.contains("'web'") && msg.contains("'web6'"), "{msg}");
    assert!(msg.contains("'6'"), "error must name the suffix: {msg}");
}

#[test]
fn test_nftables_jail_pair_foo_and_foo_v6_errors() {
    let err = parse_two_jails(("sshd", "nftables"), ("sshd-v6", "nftables"))
        .expect_err("sshd-v6's IPv4 set is sshd's IPv6 set");
    let msg = err.to_string();
    assert!(msg.contains("'sshd'") && msg.contains("'sshd-v6'"), "{msg}");
    assert!(msg.contains("'-v6'"), "error must name the suffix: {msg}");
}

#[test]
fn test_jail_pair_across_backends_validates() {
    parse_two_jails(("foo", "ipset"), ("foo6", "nftables")).expect("separate namespaces");
    parse_two_jails(("foo", "nftables"), ("foo-v6", "ipset")).expect("separate namespaces");
}

#[test]
fn test_jail_pair_with_disabled_twin_validates() {
    let toml = "[global]\n\n[jail.web]\nlog_path = \"/x\"\nfilter = ['from <HOST>']\n\
                backend = \"ipset\"\n\n[jail.web6]\nenabled = false\nlog_path = \"/x\"\n\
                filter = ['from <HOST>']\nbackend = \"ipset\"\n";
    Config::parse(toml).expect("a disabled jail creates no sets");
}

#[test]
fn test_ipset_jail_named_chain_validates() {
    parse_backend_jail("chain", "ipset").expect("the legacy chain is nftables-only");
}

#[test]
fn test_iptables_and_script_reserved_names_validate() {
    parse_backend_jail("chain", "iptables").expect("iptables has no legacy chain");
    parse_backend_jail("web-v6", "iptables").expect("iptables uses one chain per jail");
    let script = "[jail.web6.backend.script]\nban_cmd = \"true\"\nunban_cmd = \"true\"";
    parse_jail("web6", script).expect("script backend creates no named sets");
}

#[test]
fn test_disabled_jail_with_reserved_name_validates() {
    let toml = "[global]\n\n[jail.sshd]\nlog_path = \"/var/log/auth.log\"\nfilter = ['from <HOST>']\n\n\
                [jail.chain]\nenabled = false\nlog_path = \"/x\"\nfilter = ['from <HOST>']\n";
    Config::parse(toml).expect("a disabled jail creates no firewall state");
}
