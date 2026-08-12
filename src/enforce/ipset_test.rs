//! Fake-binary harness plus the ipset backend's pure helpers and `init`.
//!
//! The harness (`FakeSpec`/`Fake`/`fake`) is shared with `ipset_ops_test.rs`.

use super::*;

use std::fs;

/// Separator the fake binaries write between invocations in their log file.
/// Mirrors the technique used in `nftables_test.rs`.
const SEP: &str = "===";

/// First arg the fake binary treats as a no-op warm-up: it exits 0 without
/// touching the log. Used by [`wait_until_executable`] to probe exec-readiness.
const WARMUP_ARG: &str = "__f2b_warmup__";

/// Block until a freshly written fake binary can be executed.
///
/// Tests run multithreaded and spawn child processes via `fork`+`exec`. If
/// another thread forks while this file's writable fd is still open, the child
/// transiently inherits it and any `exec` races with `ETXTBSY`. Probe with a
/// no-op invocation until it clears.
fn wait_until_executable(path: &std::path::Path) {
    for _ in 0..200 {
        match std::process::Command::new(path).arg(WARMUP_ARG).status() {
            Err(e) if e.raw_os_error() == Some(26) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            _ => return,
        }
    }
}

/// Write an executable shell script standing in for a firewall binary.
///
/// Every invocation appends its argv (one arg per line) to `log_path` followed
/// by a `===` separator, prints `output` on file descriptor `fd` (1 = stdout,
/// 2 = stderr), then exits with `exit_code`.
fn write_fake_bin(
    path: &std::path::Path,
    log_path: &std::path::Path,
    exit_code: i32,
    output: &str,
    fd: u8,
) {
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"{warmup}\" ]; then exit 0; fi\nfor a in \"$@\"; do\n  printf '%s\\n' \"$a\"\ndone >> \"{log}\"\nprintf '{sep}\\n' >> \"{log}\"\nprintf '%s' \"{output}\" >&{fd}\nexit {code}\n",
        warmup = WARMUP_ARG,
        log = log_path.display(),
        sep = SEP,
        output = output,
        fd = fd,
        code = exit_code,
    );
    fs::write(path, script).expect("write fake binary script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(path).expect("stat fake binary").permissions();
        perm.set_mode(0o755);
        fs::set_permissions(path, perm).expect("chmod fake binary");
    }
    wait_until_executable(path);
}

/// Parse a log file into one `Vec<String>` of args per invocation. Returns an
/// empty list when the binary was never invoked (log file absent).
fn read_invocations(log_path: &std::path::Path) -> Vec<Vec<String>> {
    let Ok(content) = fs::read_to_string(log_path) else {
        return Vec::new();
    };
    content
        .split(&format!("{SEP}\n"))
        .filter(|block| !block.is_empty())
        .map(|block| block.lines().map(str::to_string).collect())
        .collect()
}

/// How the three fake binaries should behave for one test.
pub(super) struct FakeSpec {
    /// Maximum set size handed to the backend.
    pub(super) maxelem: u32,
    /// iptables chain handed to the backend.
    pub(super) chain: &'static str,
    /// Exit code of the fake `ipset`.
    pub(super) ipset_exit: i32,
    /// Text the fake `ipset` prints.
    pub(super) ipset_output: &'static str,
    /// File descriptor the fake `ipset` prints on (1 = stdout, 2 = stderr).
    pub(super) ipset_fd: u8,
    /// Exit code of the fake `iptables`/`ip6tables`.
    pub(super) ipt_exit: i32,
}

impl Default for FakeSpec {
    fn default() -> Self {
        Self {
            maxelem: 65_536,
            chain: "INPUT",
            ipset_exit: 0,
            ipset_output: "",
            ipset_fd: 1,
            ipt_exit: 0,
        }
    }
}

/// Three fake binaries plus their invocation logs.
pub(super) struct Fake {
    pub(super) backend: IpsetBackend,
    ipset_log: std::path::PathBuf,
    iptables_log: std::path::PathBuf,
    ip6tables_log: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Fake {
    /// Argv of every `ipset` invocation, in order.
    pub(super) fn ipset(&self) -> Vec<Vec<String>> {
        read_invocations(&self.ipset_log)
    }

    /// Argv of every `iptables` invocation, in order.
    pub(super) fn iptables(&self) -> Vec<Vec<String>> {
        read_invocations(&self.iptables_log)
    }

    /// Argv of every `ip6tables` invocation, in order.
    pub(super) fn ip6tables(&self) -> Vec<Vec<String>> {
        read_invocations(&self.ip6tables_log)
    }
}

/// Build a backend wired to three fake binaries behaving per `spec`.
pub(super) fn fake(spec: &FakeSpec) -> Fake {
    let dir = tempfile::tempdir().expect("tempdir");
    let ipset_path = dir.path().join("ipset");
    let iptables_path = dir.path().join("iptables");
    let ip6tables_path = dir.path().join("ip6tables");
    let ipset_log = dir.path().join("ipset.log");
    let iptables_log = dir.path().join("iptables.log");
    let ip6tables_log = dir.path().join("ip6tables.log");
    write_fake_bin(
        &ipset_path,
        &ipset_log,
        spec.ipset_exit,
        spec.ipset_output,
        spec.ipset_fd,
    );
    write_fake_bin(&iptables_path, &iptables_log, spec.ipt_exit, "", 1);
    write_fake_bin(&ip6tables_path, &ip6tables_log, spec.ipt_exit, "", 1);
    Fake {
        backend: IpsetBackend::new(
            ipset_path,
            iptables_path,
            ip6tables_path,
            spec.maxelem,
            spec.chain.to_string(),
        ),
        ipset_log,
        iptables_log,
        ip6tables_log,
        _dir: dir,
    }
}

/// A backend where every invocation succeeds, with default settings.
pub(super) fn fake_ok() -> Fake {
    fake(&FakeSpec::default())
}

/// A backend pointed at paths that do not exist.
pub(super) fn missing_binaries() -> IpsetBackend {
    IpsetBackend::new(
        std::path::PathBuf::from("/nonexistent/ipset-for-tests-xyz"),
        std::path::PathBuf::from("/nonexistent/iptables-for-tests-xyz"),
        std::path::PathBuf::from("/nonexistent/ip6tables-for-tests-xyz"),
        65_536,
        "INPUT".to_string(),
    )
}

pub(super) fn v4() -> IpAddr {
    "203.0.113.5".parse().expect("v4 literal")
}

pub(super) fn v6() -> IpAddr {
    "2001:db8::1".parse().expect("v6 literal")
}

// --- pure helpers -------------------------------------------------------

#[test]
fn test_set_name_appends_six_for_the_v6_family() {
    assert_eq!(set_name("sshd", false), "f2b-sshd");
    assert_eq!(set_name("sshd", true), "f2b-sshd6");
}

#[test]
fn test_create_args_v4_are_exact() {
    assert_eq!(
        create_args("f2b-sshd", "inet", 65_536),
        vec![
            "-exist", "create", "f2b-sshd", "hash:ip", "family", "inet", "timeout", "0", "maxelem",
            "65536",
        ]
    );
}

#[test]
fn test_create_args_carry_the_configured_maxelem() {
    let args = create_args("f2b-sshd", "inet6", 200_000);
    assert_eq!(args[5], "inet6");
    assert_eq!(args[8], "maxelem");
    assert_eq!(args[9], "200000");
}

#[test]
fn test_match_rule_args_without_ports_match_all_traffic() {
    let args = match_rule_args("-I", "INPUT", "f2b-sshd", &RuleSpec::default());
    assert_eq!(
        args,
        vec![
            "-I",
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
}

#[test]
fn test_match_rule_args_with_ports_scope_to_a_multiport_match() {
    let spec = RuleSpec {
        ports: vec!["22".to_string(), "2222".to_string()],
        protocol: "tcp".to_string(),
    };
    let args = match_rule_args("-I", "DOCKER-USER", "f2b-sshd", &spec);
    assert_eq!(
        args,
        vec![
            "-I",
            "DOCKER-USER",
            "-p",
            "tcp",
            "-m",
            "multiport",
            "--dports",
            "22,2222",
            "-m",
            "set",
            "--match-set",
            "f2b-sshd",
            "src",
            "-j",
            "DROP",
        ]
    );
}

#[test]
fn test_delete_rule_args_differ_from_insert_only_by_the_flag() {
    let spec = RuleSpec {
        ports: vec!["80".to_string()],
        protocol: "tcp".to_string(),
    };
    let insert = match_rule_args("-I", "INPUT", "f2b-web", &spec);
    let mut delete = match_rule_args("-D", "INPUT", "f2b-web", &spec);
    assert_eq!(delete[0], "-D");
    delete[0] = "-I".to_string();
    assert_eq!(insert, delete);
}

#[test]
fn test_timeout_secs_uses_the_remaining_duration() {
    assert_eq!(timeout_secs(Some(1_060), 1_000), 60);
}

#[test]
fn test_timeout_secs_clamps_an_expired_ban_up_to_one() {
    // 0 means *permanent* to ipset, so a past expiry must never emit it.
    assert_eq!(timeout_secs(Some(500), 1_000), 1);
}

#[test]
fn test_timeout_secs_clamps_to_the_kernel_ceiling() {
    assert_eq!(timeout_secs(Some(i64::MAX), 0), MAX_TIMEOUT_SECS);
    assert_eq!(timeout_secs(Some(10_000_000_000), 1_000), MAX_TIMEOUT_SECS);
}

#[test]
fn test_timeout_secs_at_the_kernel_ceiling_is_not_clamped() {
    // Exactly at the ceiling must pass through unchanged, not be treated as
    // "over" — only exceeding 2_147_483 is a syntax error to ipset.
    assert_eq!(timeout_secs(Some(MAX_TIMEOUT_SECS), 0), MAX_TIMEOUT_SECS);
}

#[test]
fn test_timeout_secs_one_second_past_the_ceiling_clamps() {
    assert_eq!(
        timeout_secs(Some(MAX_TIMEOUT_SECS + 1), 0),
        MAX_TIMEOUT_SECS
    );
}

#[test]
fn test_timeout_secs_is_zero_for_a_permanent_ban() {
    assert_eq!(timeout_secs(None, 1_000), 0);
}

// --- init ---------------------------------------------------------------

#[tokio::test]
async fn test_init_without_ports_creates_both_sets_and_both_rules() {
    let f = fake_ok();
    f.backend.init("sshd", &[], "tcp").await.expect("init");

    let ipset = f.ipset();
    assert_eq!(ipset.len(), 2, "two creates expected: {ipset:?}");
    assert_eq!(
        ipset[0],
        vec![
            "-exist", "create", "f2b-sshd", "hash:ip", "family", "inet", "timeout", "0", "maxelem",
            "65536",
        ]
    );
    assert_eq!(
        ipset[1],
        vec![
            "-exist",
            "create",
            "f2b-sshd6",
            "hash:ip",
            "family",
            "inet6",
            "timeout",
            "0",
            "maxelem",
            "65536",
        ]
    );

    let v4_rules = f.iptables();
    assert_eq!(v4_rules.len(), 1, "one -I expected: {v4_rules:?}");
    assert_eq!(
        v4_rules[0],
        vec![
            "-I",
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
    let v6_rules = f.ip6tables();
    assert_eq!(v6_rules.len(), 1, "one -I expected: {v6_rules:?}");
    assert_eq!(v6_rules[0][5], "f2b-sshd6");
}

#[tokio::test]
async fn test_init_emits_the_configured_maxelem() {
    let f = fake(&FakeSpec {
        maxelem: 200_000,
        ..FakeSpec::default()
    });
    f.backend.init("sshd", &[], "tcp").await.expect("init");

    let ipset = f.ipset();
    assert_eq!(ipset[0][8], "maxelem");
    assert_eq!(ipset[0][9], "200000");
    assert_eq!(ipset[1][9], "200000");
}

#[tokio::test]
async fn test_init_with_ports_scopes_both_rules_to_a_multiport_match() {
    let f = fake_ok();
    f.backend
        .init("sshd", &["22".to_string(), "2222".to_string()], "tcp")
        .await
        .expect("init");

    let expected_head = [
        "-I",
        "INPUT",
        "-p",
        "tcp",
        "-m",
        "multiport",
        "--dports",
        "22,2222",
    ];
    for rules in [f.iptables(), f.ip6tables()] {
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0][..8], expected_head[..]);
        assert_eq!(rules[0][8], "-m");
        assert_eq!(rules[0][9], "set");
    }
}

#[tokio::test]
async fn test_init_without_ports_emits_no_protocol_args() {
    let f = fake_ok();
    f.backend.init("sshd", &[], "udp").await.expect("init");

    let flat = f.iptables().concat().join(" ");
    for absent in ["-p", "udp", "multiport", "--dports"] {
        assert!(!flat.contains(absent), "unexpected {absent} in: {flat}");
    }
}

#[tokio::test]
async fn test_init_inserts_into_the_configured_chain_on_both_families() {
    let f = fake(&FakeSpec {
        chain: "DOCKER-USER",
        ..FakeSpec::default()
    });
    f.backend.init("sshd", &[], "tcp").await.expect("init");

    assert_eq!(f.iptables()[0][1], "DOCKER-USER");
    assert_eq!(f.ip6tables()[0][1], "DOCKER-USER");
}

#[tokio::test]
async fn test_init_aborts_before_any_rule_when_set_creation_fails() {
    let f = fake(&FakeSpec {
        ipset_exit: 1,
        ipset_output: "ipset v7.15: Kernel error received: Invalid argument",
        ipset_fd: 2,
        ..FakeSpec::default()
    });
    let err = f
        .backend
        .init("sshd", &[], "tcp")
        .await
        .expect_err("a failed create must be fatal");
    assert!(err.to_string().contains("ipset exit"), "got: {err}");
    assert!(err.to_string().contains("Kernel error"), "got: {err}");

    assert_eq!(f.ipset().len(), 1, "init must stop at the first failure");
    assert!(f.iptables().is_empty(), "no rule may be inserted");
    assert!(f.ip6tables().is_empty(), "no rule may be inserted");
}

#[tokio::test]
async fn test_init_tolerates_a_failed_rule_insertion() {
    let f = fake(&FakeSpec {
        ipt_exit: 1,
        ..FakeSpec::default()
    });
    f.backend
        .init("sshd", &[], "tcp")
        .await
        .expect("a failed -I must not take the daemon down");

    assert_eq!(f.ipset().len(), 2, "both sets must still be created");
    assert_eq!(f.iptables().len(), 1);
    assert_eq!(f.ip6tables().len(), 1);
}

#[tokio::test]
async fn test_init_errors_when_the_ipset_binary_is_missing() {
    let err = missing_binaries()
        .init("sshd", &[], "tcp")
        .await
        .expect_err("a missing binary must surface as an error");
    assert!(
        err.to_string().contains("ipset command failed"),
        "got: {err}"
    );
}
