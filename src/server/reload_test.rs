use super::*;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use tokio::sync::mpsc;

use crate::config::{Config, JailConfig};
use crate::enforce::FirewallCmd;
use crate::track::state::BanRecord;

/// Spawn a mock executor that auto-responds Ok(()) to InitJail,
/// TeardownJail, and Ban commands.
fn spawn_mock_executor(
    mut rx: mpsc::Receiver<FirewallCmd>,
) -> tokio::task::JoinHandle<Vec<String>> {
    tokio::spawn(async move {
        let mut log = Vec::new();
        while let Some(cmd) = rx.recv().await {
            match cmd {
                FirewallCmd::InitJail { jail_id, done, .. } => {
                    log.push(format!("init:{jail_id}"));
                    let _ = done.send(Ok(()));
                }
                FirewallCmd::TeardownJail { jail_id, done } => {
                    log.push(format!("teardown:{jail_id}"));
                    let _ = done.send(Ok(()));
                }
                FirewallCmd::Ban {
                    ip, jail_id, done, ..
                } => {
                    log.push(format!("ban:{ip}:{jail_id}"));
                    if let Some(done) = done {
                        let _ = done.send(Ok(()));
                    }
                }
                FirewallCmd::Unban { ip, jail_id } => {
                    log.push(format!("unban:{ip}:{jail_id}"));
                }
            }
        }
        log
    })
}

/// Build a minimal `Config` with one enabled jail named `sshd`.
fn minimal_config() -> Config {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());
    Config {
        global: crate::config::GlobalConfig::default(),
        logging: crate::config::LoggingConfig::default(),
        jail: jails,
    }
}

/// Build a minimal `JailConfig` with a valid filter.
fn test_jail_config() -> JailConfig {
    JailConfig {
        enabled: true,
        log_path: "/tmp/test.log".into(),
        date_format: crate::detect::date::DateFormat::Syslog,
        filter: vec!["from <HOST>".to_string()],
        max_retry: 3,
        find_time: 600,
        ban_time: 60,
        port: vec!["22".to_string()],
        protocol: "tcp".to_string(),
        bantime_increment: false,
        bantime_factor: 1.0,
        bantime_multipliers: vec![],
        bantime_maxtime: 604_800,
        backend: crate::config::Backend::Nftables,
        log_backend: crate::config::LogBackend::default(),
        journalmatch: vec![],
        ignoreregex: vec![],
        ignoreip: vec![],
        ignoreself: false,
        reban_on_restart: true,
        webhook: None,
        maxmind: vec![],
    }
}

#[tokio::test]
async fn test_init_firewalls_success() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_mock_executor(rx);

    let config = minimal_config();
    let result = init_firewalls(&tx, config.enabled_jails()).await;

    drop(tx);
    let log = handle.await.unwrap();

    assert!(result.is_ok());
    assert_eq!(log.len(), 1);
    assert_eq!(log[0], "init:sshd");
}

#[tokio::test]
async fn test_init_firewalls_fails_on_channel_closed() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    // Drop the receiver immediately so the channel is closed.
    drop(rx);

    let config = minimal_config();
    let result = init_firewalls(&tx, config.enabled_jails()).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, crate::error::Error::ChannelClosed),
        "expected ChannelClosed, got: {err}"
    );
}

#[tokio::test]
async fn test_teardown_firewalls_success() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_mock_executor(rx);

    let names = vec!["sshd"];
    teardown_firewalls(&tx, names.into_iter()).await;

    drop(tx);
    let log = handle.await.unwrap();

    assert_eq!(log.len(), 1);
    assert_eq!(log[0], "teardown:sshd");
}

#[tokio::test]
async fn test_reapply_bans_skips_disabled_jails() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_mock_executor(rx);

    // Config only has "sshd" enabled.
    let config = minimal_config();

    // Ban record references a jail not in the config.
    let bans = vec![BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        jail_id: "nginx".to_string(),
        banned_at: 1000,
        expires_at: Some(9999),
    }];

    let result = reapply_bans(&tx, &bans, &config).await;

    drop(tx);
    let log = handle.await.unwrap();

    assert!(result.is_ok());
    assert!(
        log.is_empty(),
        "no ban commands should be sent for disabled jail"
    );
}

#[tokio::test]
async fn test_reapply_bans_sends_ban_commands() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_mock_executor(rx);

    let config = minimal_config();

    let bans = vec![
        BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            jail_id: "sshd".to_string(),
            banned_at: 1000,
            expires_at: Some(9999),
        },
        BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            jail_id: "sshd".to_string(),
            banned_at: 2000,
            expires_at: None,
        },
    ];

    let result = reapply_bans(&tx, &bans, &config).await;

    drop(tx);
    let log = handle.await.unwrap();

    assert!(result.is_ok());
    assert_eq!(log.len(), 2);
    assert_eq!(log[0], "ban:1.2.3.4:sshd");
    assert_eq!(log[1], "ban:5.6.7.8:sshd");
}

#[test]
fn test_build_watcher_plan_invalid_regex() {
    let mut config = minimal_config();
    // Set an invalid regex as the filter pattern.
    config.jail.get_mut("sshd").unwrap().filter = vec!["[invalid regex".to_string()];

    let result = build_watcher_plan(&config);
    assert!(
        result.is_err(),
        "invalid regex in filter should produce an error"
    );
}
