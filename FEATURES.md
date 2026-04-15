# Features

## Matching

- Two-phase log matching — Aho-Corasick pre-filter rejects non-matching lines in nanoseconds, then only tries relevant regexes.
- Positional IP extraction — identifies the correct host IP by its position in the pattern, even when other IPs appear in URLs or log fields.
- Ignore regex — lines matching ignoreregex are suppressed even when a failregex matches.
- Four timestamp formats — syslog, ISO 8601 (zero-alloc byte scanner), unix epoch, and common log format.

## Banning

- Configurable thresholds — max retries, find time window, and ban duration per jail.
- Escalating bans — repeat offenders get progressively longer bans with configurable multipliers and a maximum cap.
- Permanent bans — set ban time to -1 for indefinite bans.
- IP allowlist — never ban IPs or CIDRs in the ignore list; auto-detects local machine IPs by default.
- Manual ban and unban — issue bans and unbans via CLI for any jail.

## Firewall

- nftables backend — creates per-jail chains and IP sets.
- iptables backend — per-jail chains with individual rules.
- Script backend — user-defined ban and unban shell commands for custom firewalls.
- Absolute path resolution — firewall commands resolved to full paths to prevent PATH hijack.

## Persistence

- WAL-backed storage — bans persisted immediately via write-ahead log for crash recovery.
- Expired ban cleanup — stale bans purged on startup instead of being restored.
- Automatic migration — old state.bin files backed up and new format used transparently.

## Log Sources

- File watcher — tails log files, detects rotation via inode/size/hash, and reopens automatically.
- Systemd journal — reads from journald with configurable match filters per jail.
- Invalid UTF-8 tolerance — lines with encoding errors are skipped without stopping the watcher.
- Line size limit — lines over 64 KB are bounded in both file and journal watchers.

## GeoIP

- MaxMind lookup — country, city, and ASN info on ban events using local GeoLite2 databases.
- Per-jail field selection — choose which databases to query (asn, country, city) per jail.
- Startup validation — invalid field names rejected, world-writable database files refused.
- Compile-time opt-out — GeoIP can be disabled entirely at build time.

## CLI

- Status, stats, list-bans — query the running daemon via Unix socket.
- List-bans table and JSON — sorted table with relative time remaining, or JSONL output.
- Dry-run — analyze a log file without banning, showing jail config, thresholds, and per-IP failure counts.
- Regex tester — test a pattern against a log line with match explanation and hints on failure.
- Config generator — generate jail TOML for 88 built-in services (sshd, nginx, apache, postfix, dovecot, vaultwarden, grafana, and more).
- List-filters — show all 88 available built-in filter templates.
- List-maxmind — show configured MaxMind database paths and load status.
- Live reload — reload configuration without restarting the daemon; active bans preserved across reloads with automatic rollback on failure.

## Configuration

- TOML config — single config file with global settings and per-jail sections.
- Duration strings — ban_time, find_time accept human-readable values like "10m", "1h", "7d".
- Startup validation — jail names, ports, protocols, and ban factors validated before the daemon starts.
- Backward-compatible renames — state_file still works as an alias for state_dir.
- Per-jail reban control — skip re-issuing bans on restart when firewall state persists independently.

## Notifications

- Webhook — POST JSON to a URL on every ban event with IP, jail, ban time, and timestamp.
- Remote logging — structured log forwarding via the Tell SDK.

## Logging

- Native journald output — per-line syslog severity, structured fields, no duplicate timestamps; works correctly with journalctl severity filtering and color-coding.
- Output format — logfmt (default) or JSON, configurable via the [logging] format option.
- Configurable severity threshold via [logging] level; legacy global.log_level still accepted.
- Stderr fallback — when the journal socket is unavailable, logs go to stderr without double-rendering.

## Deployment

- Single static binary — no runtime dependencies beyond the firewall tooling.
- Clean shutdown — responds to both SIGINT and SIGTERM, tearing down firewall rules before exit.
- Systemd hardening — service unit with capability, filesystem, and syscall restrictions.
- macOS development config — rootless testing without firewall privileges.
