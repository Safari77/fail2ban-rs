//! Fake firewall binaries shared by the backend unit tests.
//!
//! Each fake is a `/bin/sh` script that logs its argv (one arg per line,
//! followed by a [`SEP`] line) so tests can assert on exactly what the backend
//! constructed without root or a real netfilter stack.

use std::fs;
use std::path::Path;

use crate::enforce::cmd::XTABLES_WAIT;

/// Separator a fake binary writes after each invocation in its log file.
pub(crate) const SEP: &str = "===";

/// First arg a fake binary treats as a no-op warm-up: it exits 0 without
/// touching the log. Used by [`wait_until_executable`] to probe readiness.
pub(crate) const WARMUP_ARG: &str = "__f2b_warmup__";

/// `ETXTBSY` ("Text file busy") errno on Linux and macOS.
const ETXTBSY: i32 = 26;

/// Script header: shebang, warm-up short-circuit, and argv logging to `log`.
///
/// A leading [`XTABLES_WAIT`] flag is logged, then shifted off so the body
/// (and any `fail_glob`) sees the operation flag as `$1`.
///
/// Callers append the body (output, exit code) after this prelude.
pub(crate) fn logging_prelude(log: &Path) -> String {
    format!(
        "#!/bin/sh\nif [ \"$1\" = \"{WARMUP_ARG}\" ]; then exit 0; fi\nfor a in \"$@\"; do\n  printf '%s\\n' \"$a\"\ndone >> \"{log}\"\nprintf '{SEP}\\n' >> \"{log}\"\nif [ \"$1\" = \"{XTABLES_WAIT}\" ]; then shift; fi\n",
        log = log.display(),
    )
}

/// Block until a freshly written fake binary can be executed.
///
/// Tests run multithreaded and spawn children via `fork`+`exec`. If another
/// thread forks while this file's writable fd is still open, the child
/// transiently inherits that fd and any `exec` of the file races with
/// `ETXTBSY`. The window closes once that child execs (std opens files
/// `O_CLOEXEC`), so probe with a no-op invocation until it clears.
pub(crate) fn wait_until_executable(path: &Path) {
    for _ in 0..200 {
        match std::process::Command::new(path).arg(WARMUP_ARG).status() {
            Err(e) if e.raw_os_error() == Some(ETXTBSY) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            // Success or any other error: the file is settled; a real problem
            // (e.g. a bad script) surfaces in the test itself.
            _ => return,
        }
    }
}

/// Write `script` to `path`, mark it executable, and wait until it can run.
pub(crate) fn install_script(path: &Path, script: &str) {
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

/// Write a fake binary that logs argv, prints `output` on fd `fd`
/// (1 = stdout, 2 = stderr), and exits with `exit_code`.
pub(crate) fn write_fake_bin(path: &Path, log: &Path, exit_code: i32, output: &str, fd: u8) {
    let script = format!(
        "{}printf '%s' \"{output}\" >&{fd}\nexit {exit_code}\n",
        logging_prelude(log)
    );
    install_script(path, &script);
}

/// Parse a log file into one `Vec<String>` of args per invocation.
///
/// Returns an empty list if the binary was never invoked (log file absent).
pub(crate) fn read_invocations(log: &Path) -> Vec<Vec<String>> {
    let Ok(content) = fs::read_to_string(log) else {
        return Vec::new();
    };
    content
        .split(&format!("{SEP}\n"))
        .filter(|block| !block.is_empty())
        .map(|block| block.lines().map(str::to_string).collect())
        .collect()
}

/// Parse an `iptables`/`ip6tables` fake's log like [`read_invocations`],
/// asserting every invocation leads with [`XTABLES_WAIT`] (so no call can
/// fail fast on xtables lock contention) and stripping that flag.
pub(crate) fn read_xtables_invocations(log: &Path) -> Vec<Vec<String>> {
    read_invocations(log)
        .into_iter()
        .map(|mut argv| {
            assert_eq!(
                argv.first().map(String::as_str),
                Some(XTABLES_WAIT),
                "iptables invoked without {XTABLES_WAIT}: {argv:?}"
            );
            argv.remove(0);
            argv
        })
        .collect()
}

/// Script body emulating an iptables rule table.
///
/// Each distinct rule (argv minus the leading operation flag) keeps a copy
/// count in a file next to `log`: `-C` succeeds iff a copy exists, `-I`/`-A`
/// add one, `-D` removes one (exit 1 when none is left). Other operations
/// (`-N`, `-F`, `-X`, ...) fall through to the caller's trailing body.
pub(crate) fn rule_table_body(log: &Path) -> String {
    format!(
        "op=\"$1\"; shift\nkey=$(printf '%s' \"$*\" | cksum | cut -d' ' -f1)\ncnt=\"{log}.rule.$key\"\nn=$(cat \"$cnt\" 2>/dev/null || echo 0)\ncase \"$op\" in\n  -C) [ \"$n\" -gt 0 ] && exit 0; exit 1 ;;\n  -I|-A) echo $((n+1)) > \"$cnt\" ;;\n  -D) [ \"$n\" -gt 0 ] || exit 1; echo $((n-1)) > \"$cnt\" ;;\nesac\n",
        log = log.display(),
    )
}

/// Pre-populate a rule-table fake at `bin` with `copies` of the rule `args`
/// (argv without the operation flag), then clear its invocation log so the
/// seeding does not show up in assertions.
pub(crate) fn seed_rule(bin: &Path, log: &Path, args: &[String], copies: u32) {
    for _ in 0..copies {
        let status = std::process::Command::new(bin)
            .arg("-I")
            .args(args)
            .status()
            .expect("run fake binary to seed a rule");
        assert!(status.success(), "seeding a rule must succeed");
    }
    if log.exists() {
        fs::remove_file(log).expect("clear seeding invocations");
    }
}
