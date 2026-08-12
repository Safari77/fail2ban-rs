//! Ban, unban, query, and teardown behavior of the ipset backend.
//!
//! Split from `ipset_test.rs`, which owns the fake-binary harness these tests
//! reuse, to keep both files under the project's 500-line limit.

use super::*;

use super::ipset_test::{FakeSpec, fake, fake_ok, missing_binaries, v4, v6};

// --- ban ----------------------------------------------------------------

#[tokio::test]
async fn test_ban_adds_a_permanent_entry_to_the_v4_set() {
    let f = fake_ok();
    f.backend.ban(&v4(), "sshd").await.expect("ban");

    let ipset = f.ipset();
    assert_eq!(ipset.len(), 1, "exactly one invocation: {ipset:?}");
    assert_eq!(
        ipset[0],
        vec!["-exist", "add", "f2b-sshd", "203.0.113.5", "timeout", "0"]
    );
    assert!(f.iptables().is_empty(), "ban must not touch iptables");
}

#[tokio::test]
async fn test_ban_routes_a_v6_address_to_the_v6_set() {
    let f = fake_ok();
    f.backend.ban(&v6(), "sshd").await.expect("ban");

    assert_eq!(
        f.ipset()[0],
        vec!["-exist", "add", "f2b-sshd6", "2001:db8::1", "timeout", "0"]
    );
}

#[tokio::test]
async fn test_ban_with_timeout_emits_the_remaining_seconds() {
    let f = fake_ok();
    f.backend
        .ban_with_timeout(&v4(), "sshd", Some(1_060), 1_000)
        .await
        .expect("ban");

    let args = &f.ipset()[0];
    assert_eq!(args[4], "timeout");
    assert_eq!(args[5], "60");
}

#[tokio::test]
async fn test_ban_with_an_expired_timeout_emits_one_second() {
    let f = fake_ok();
    f.backend
        .ban_with_timeout(&v4(), "sshd", Some(500), 1_000)
        .await
        .expect("ban");

    assert_eq!(f.ipset()[0][5], "1");
}

#[tokio::test]
async fn test_ban_clamps_a_far_future_expiry_to_the_kernel_ceiling() {
    let f = fake_ok();
    let now = 1_000_i64;
    // ~1000 days out, far beyond ipset's 24.85-day ceiling.
    f.backend
        .ban_with_timeout(&v4(), "sshd", Some(now + 86_400_000), now)
        .await
        .expect("ban");

    assert_eq!(f.ipset()[0][5], "2147483");
}

#[tokio::test]
async fn test_ban_at_the_kernel_ceiling_boundary_is_not_clamped() {
    let f = fake_ok();
    let now = 0_i64;
    f.backend
        .ban_with_timeout(&v4(), "sshd", Some(now + 2_147_483), now)
        .await
        .expect("ban");

    assert_eq!(f.ipset()[0][5], "2147483");
}

#[tokio::test]
async fn test_ban_one_second_past_the_kernel_ceiling_still_clamps() {
    let f = fake_ok();
    let now = 0_i64;
    f.backend
        .ban_with_timeout(&v4(), "sshd", Some(now + 2_147_484), now)
        .await
        .expect("ban");

    assert_eq!(f.ipset()[0][5], "2147483");
}

#[tokio::test]
async fn test_ban_with_no_expiry_emits_an_explicit_zero_timeout() {
    let f = fake_ok();
    f.backend
        .ban_with_timeout(&v4(), "sshd", None, 1_000)
        .await
        .expect("ban");

    assert_eq!(f.ipset()[0][5], "0");
}

#[tokio::test]
async fn test_ban_propagates_a_nonzero_exit() {
    let f = fake(&FakeSpec {
        ipset_exit: 1,
        ipset_output: "ipset v7.15: Hash is full, cannot add more elements",
        ipset_fd: 2,
        ..FakeSpec::default()
    });
    let err = f
        .backend
        .ban(&v4(), "sshd")
        .await
        .expect_err("a failed ban must roll back, not be recorded");
    assert!(err.to_string().contains("exit"), "got: {err}");
    assert!(err.to_string().contains("Hash is full"), "got: {err}");
}

#[tokio::test]
async fn test_ban_errors_when_the_ipset_binary_is_missing() {
    let err = missing_binaries()
        .ban(&v4(), "sshd")
        .await
        .expect_err("a missing binary must surface as an error");
    assert!(
        err.to_string().contains("ipset command failed"),
        "got: {err}"
    );
}

// --- unban --------------------------------------------------------------

#[tokio::test]
async fn test_unban_deletes_the_entry_from_the_v4_set() {
    let f = fake_ok();
    let ip: IpAddr = "198.51.100.9".parse().unwrap();
    f.backend.unban(&ip, "sshd").await.expect("unban");

    let ipset = f.ipset();
    assert_eq!(ipset.len(), 1);
    assert_eq!(ipset[0], vec!["-exist", "del", "f2b-sshd", "198.51.100.9"]);
}

#[tokio::test]
async fn test_unban_routes_a_v6_address_to_the_v6_set() {
    let f = fake_ok();
    f.backend.unban(&v6(), "sshd").await.expect("unban");

    assert_eq!(
        f.ipset()[0],
        vec!["-exist", "del", "f2b-sshd6", "2001:db8::1"]
    );
}

#[tokio::test]
async fn test_unban_tolerates_an_already_absent_entry() {
    let f = fake(&FakeSpec {
        ipset_exit: 1,
        ..FakeSpec::default()
    });
    f.backend
        .unban(&v4(), "sshd")
        .await
        .expect("removing an absent ban must not be a hard error");
}

#[tokio::test]
async fn test_unban_tolerates_a_missing_binary() {
    // Even a spawn failure (not just a nonzero exit) must stay non-fatal —
    // the trait contract is "removing an absent ban is never a hard error",
    // and a broken binary path degrades the same way a stale entry does.
    missing_binaries()
        .unban(&v4(), "sshd")
        .await
        .expect("a missing binary must not make unban a hard error");
}

// --- is_banned ----------------------------------------------------------

#[tokio::test]
async fn test_is_banned_is_true_on_a_zero_exit() {
    let f = fake(&FakeSpec {
        ipset_output: "203.0.113.5 is in set f2b-sshd.",
        ..FakeSpec::default()
    });
    assert!(f.backend.is_banned(&v4(), "sshd").await.expect("query"));

    let ipset = f.ipset();
    assert_eq!(ipset.len(), 1);
    assert_eq!(ipset[0], vec!["test", "f2b-sshd", "203.0.113.5"]);
}

#[tokio::test]
async fn test_is_banned_never_silences_ipset() {
    // The "is NOT in set" message is part of the contract, so -q/--quiet must
    // never be passed.
    let f = fake_ok();
    f.backend.is_banned(&v4(), "sshd").await.expect("query");
    f.backend.ban(&v4(), "sshd").await.expect("ban");
    f.backend.unban(&v4(), "sshd").await.expect("unban");

    let flat = f.ipset().concat();
    assert!(
        !flat.iter().any(|a| a == "-q" || a == "--quiet"),
        "{flat:?}"
    );
}

#[tokio::test]
async fn test_is_banned_is_false_when_ipset_reports_the_entry_absent() {
    let f = fake(&FakeSpec {
        ipset_exit: 1,
        ipset_output: "203.0.113.5 is NOT in set f2b-sshd.",
        ipset_fd: 2,
        ..FakeSpec::default()
    });
    assert!(!f.backend.is_banned(&v4(), "sshd").await.expect("query"));
}

#[tokio::test]
async fn test_is_banned_reads_the_absent_message_from_stdout_too() {
    let f = fake(&FakeSpec {
        ipset_exit: 1,
        ipset_output: "203.0.113.5 is NOT in set f2b-sshd.",
        ipset_fd: 1,
        ..FakeSpec::default()
    });
    assert!(!f.backend.is_banned(&v4(), "sshd").await.expect("query"));
}

#[tokio::test]
async fn test_is_banned_errors_when_the_set_does_not_exist() {
    // Mapping this to "not banned" would make reconcile re-apply every active
    // ban on every tick against a broken ipset.
    let f = fake(&FakeSpec {
        ipset_exit: 1,
        ipset_output: "ipset v7.15: The set with the given name does not exist",
        ipset_fd: 2,
        ..FakeSpec::default()
    });
    let err = f
        .backend
        .is_banned(&v4(), "sshd")
        .await
        .expect_err("an unusable query must be an error");
    assert!(err.to_string().contains("does not exist"), "got: {err}");
}

#[tokio::test]
async fn test_is_banned_matching_is_case_sensitive() {
    // The spec is explicit: ipset emits no localized strings, so matching
    // must not be case-insensitive — a differently-cased message must not be
    // read as "absent" and must surface as an error instead.
    let f = fake(&FakeSpec {
        ipset_exit: 1,
        ipset_output: "203.0.113.5 IS NOT IN SET f2b-sshd.",
        ipset_fd: 2,
        ..FakeSpec::default()
    });
    let err = f
        .backend
        .is_banned(&v4(), "sshd")
        .await
        .expect_err("differently-cased message must not match 'is NOT in set'");
    assert!(err.to_string().contains("IS NOT IN SET"), "got: {err}");
}

#[tokio::test]
async fn test_is_banned_matches_the_absent_message_even_embedded_in_more_text() {
    // The mapping is a substring test over combined stdout+stderr, not an
    // exact-message match — a real ipset build prefixing/suffixing extra
    // text around the documented phrase must still read as "not banned".
    let f = fake(&FakeSpec {
        ipset_exit: 1,
        ipset_output: "ipset v7.15: 203.0.113.5 is NOT in set f2b-sshd. (cached)",
        ipset_fd: 2,
        ..FakeSpec::default()
    });
    assert!(!f.backend.is_banned(&v4(), "sshd").await.expect("query"));
}

#[tokio::test]
async fn test_is_banned_errors_on_a_nonzero_exit_with_no_output() {
    let f = fake(&FakeSpec {
        ipset_exit: 1,
        ..FakeSpec::default()
    });
    f.backend
        .is_banned(&v4(), "sshd")
        .await
        .expect_err("an unexplained failure must not read as 'not banned'");
}

#[tokio::test]
async fn test_is_banned_queries_the_v6_set_for_a_v6_address() {
    let f = fake_ok();
    f.backend.is_banned(&v6(), "sshd").await.expect("query");

    assert_eq!(f.ipset()[0], vec!["test", "f2b-sshd6", "2001:db8::1"]);
}

#[tokio::test]
async fn test_is_banned_errors_when_the_ipset_binary_is_missing() {
    let err = missing_binaries()
        .is_banned(&v4(), "sshd")
        .await
        .expect_err("a missing binary must surface as an error");
    assert!(
        err.to_string().contains("ipset command failed"),
        "got: {err}"
    );
}

// --- teardown -----------------------------------------------------------

#[tokio::test]
async fn test_teardown_removes_rules_before_flushing_and_destroying_sets() {
    let f = fake_ok();
    f.backend.teardown("sshd").await.expect("teardown");

    assert_eq!(
        f.iptables()[0],
        vec![
            "-D",
            "INPUT",
            "-m",
            "set",
            "--match-set",
            "f2b-sshd",
            "src",
            "-j",
            "DROP"
        ]
    );
    assert_eq!(f.ip6tables()[0][5], "f2b-sshd6");

    let ipset = f.ipset();
    assert_eq!(ipset.len(), 4, "flush+destroy per family: {ipset:?}");
    assert_eq!(ipset[0], vec!["flush", "f2b-sshd"]);
    assert_eq!(ipset[1], vec!["destroy", "f2b-sshd"]);
    assert_eq!(ipset[2], vec!["flush", "f2b-sshd6"]);
    assert_eq!(ipset[3], vec!["destroy", "f2b-sshd6"]);
}

#[tokio::test]
async fn test_teardown_deletes_exactly_the_rule_init_inserted() {
    let f = fake(&FakeSpec {
        chain: "DOCKER-USER",
        ..FakeSpec::default()
    });
    let ports = ["22".to_string(), "2222".to_string()];
    f.backend.init("sshd", &ports, "tcp").await.expect("init");
    f.backend.teardown("sshd").await.expect("teardown");

    for rules in [f.iptables(), f.ip6tables()] {
        assert_eq!(rules.len(), 2, "one -I then one -D: {rules:?}");
        let mut deleted = rules[1].clone();
        assert_eq!(deleted[0], "-D");
        deleted[0] = "-I".to_string();
        assert_eq!(rules[0], deleted, "-D must mirror -I exactly");
    }
}

#[tokio::test]
async fn test_teardown_after_reinit_with_changed_ports_uses_the_latest_rule() {
    // A reload can call `init` again with a different port set on an
    // already-initialized backend. `teardown` must reconstruct the rule from
    // the most recent `init`, not the first, or the `-D` will not match any
    // rule actually present in the chain.
    let f = fake_ok();
    f.backend
        .init("sshd", &["22".to_string()], "tcp")
        .await
        .expect("first init");
    f.backend
        .init("sshd", &["8080".to_string(), "8443".to_string()], "tcp")
        .await
        .expect("second init with changed ports");
    f.backend.teardown("sshd").await.expect("teardown");

    let rules = f.iptables();
    assert_eq!(rules.len(), 3, "two -I then one -D: {rules:?}");
    let teardown_rule = &rules[2];
    assert_eq!(teardown_rule[0], "-D");
    assert!(
        teardown_rule.contains(&"8080,8443".to_string()),
        "teardown must reconstruct the second init's ports, not the first: {teardown_rule:?}"
    );
    assert!(
        !teardown_rule.iter().any(|a| a == "22"),
        "the stale first-init port must not appear: {teardown_rule:?}"
    );
}

#[tokio::test]
async fn test_teardown_without_a_prior_init_uses_the_portless_rule() {
    let f = fake_ok();
    f.backend.teardown("sshd").await.expect("teardown");

    let flat = f.iptables().concat().join(" ");
    assert!(!flat.contains("multiport"), "got: {flat}");
}

#[tokio::test]
async fn test_teardown_ignores_failures_on_every_step() {
    let f = fake(&FakeSpec {
        ipset_exit: 1,
        ipt_exit: 1,
        ..FakeSpec::default()
    });
    f.backend
        .teardown("sshd")
        .await
        .expect("teardown must swallow per-command failures");

    assert_eq!(f.ipset().len(), 4, "every step must still be attempted");
}

#[tokio::test]
async fn test_teardown_full_matches_teardown() {
    let f = fake_ok();
    f.backend
        .teardown_full("sshd")
        .await
        .expect("teardown_full");

    let ipset = f.ipset();
    assert_eq!(ipset.len(), 4);
    assert_eq!(ipset[0], vec!["flush", "f2b-sshd"]);
    assert_eq!(ipset[3], vec!["destroy", "f2b-sshd6"]);
    assert_eq!(f.iptables().len(), 1);
    assert_eq!(f.ip6tables().len(), 1);
}

#[test]
fn test_backend_name_is_ipset() {
    let backend = missing_binaries();
    assert_eq!(backend.name(), "ipset");
}
