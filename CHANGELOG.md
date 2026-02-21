# Changelog

## v0.1.1

New:
- matcher: AC-guided regex selection replaces RegexSet, skips impossible patterns via deduplicated prefix mapping
- matcher: token-scan IP extraction using find() instead of captures(), avoids PikeVM overhead
- date: zero-alloc byte scanner for ISO 8601 replaces regex + chrono
- state: xxh3_64 integrity checksum replaces crc32, reuses existing xxhash dep
- config: jail name, port, protocol, and bantime_factor validation
- security: input fuzzing test suite covering injection, spoofing, overflow, and ReDoS vectors
- benches: criterion benchmark suite for matching pipeline with Python fail2ban comparison script
- readme: performance benchmarks section with per-stage ns/line measurements

Fix:
- control: restrict Unix socket and parent directory permissions to owner+group
- executor: exact token matching for is_banned checks in iptables and nftables backends
- duration: checked multiplication prevents overflow on large duration values
- pattern: prefer longer literal prefixes for better AC selectivity

Infra:
- deps: drop crc32fast, add criterion as dev-dependency

Breaking:
- state: format bumped to v3 (xxh3_64 checksum), v1/v2 state files must be discarded
