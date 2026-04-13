//! Config reload logic — firewall init/teardown, watcher lifecycle, ban
//! reapplication.

use std::collections::HashMap;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::Config;
use crate::detect::date::DateParser;
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;
use crate::detect::watcher::Failure;
use crate::enforce::{self, FirewallCmd};
use crate::logging::Logger;
use crate::track::TrackerCmd;
use crate::track::state::BanRecord;

/// Shared mutable state needed during config reload.
pub(super) struct ReloadContext<'a> {
    pub(super) config_path: &'a std::path::Path,
    pub(super) executor_tx: &'a mpsc::Sender<FirewallCmd>,
    pub(super) config: &'a mut Config,
    pub(super) watcher_cancel: &'a mut CancellationToken,
    pub(super) failure_tx: &'a mpsc::Sender<Failure>,
    pub(super) logger: Option<&'a Logger>,
}

/// Pre-compiled watcher plan for a single jail.
pub(super) struct WatcherPlan {
    pub(super) name: String,
    pub(super) jail: crate::config::JailConfig,
    pub(super) matcher: JailMatcher,
    pub(super) date_parser: DateParser,
    pub(super) ignore_list: IgnoreList,
}

/// Build watcher plans for all enabled jails.
pub(super) fn build_watcher_plan(config: &Config) -> crate::error::Result<Vec<WatcherPlan>> {
    config
        .enabled_jails()
        .map(|(name, jail)| {
            let matcher = if jail.ignoreregex.is_empty() {
                JailMatcher::new(&jail.filter)?
            } else {
                JailMatcher::with_ignoreregex(&jail.filter, &jail.ignoreregex)?
            };
            let date_parser = DateParser::new(jail.date_format)?;
            let ignore_list = IgnoreList::new(&jail.ignoreip, jail.ignoreself)?;
            Ok(WatcherPlan {
                name: name.to_string(),
                jail: jail.clone(),
                matcher,
                date_parser,
                ignore_list,
            })
        })
        .collect()
}

/// Spawn watcher tasks for each plan under the given cancellation token.
pub(super) fn spawn_watchers(
    watcher_plan: Vec<WatcherPlan>,
    failure_tx: &mpsc::Sender<Failure>,
    cancel: &CancellationToken,
) {
    for plan in watcher_plan {
        let tx = failure_tx.clone();
        let cancel = cancel.child_token();

        if plan.jail.log_backend == crate::config::LogBackend::Systemd {
            let journalmatch = plan.jail.journalmatch.clone();
            tokio::spawn(async move {
                crate::detect::journal::run(
                    plan.name,
                    journalmatch,
                    plan.matcher,
                    plan.date_parser,
                    plan.ignore_list,
                    tx,
                    cancel,
                )
                .await;
            });
            continue;
        }

        let log_path = plan.jail.log_path.clone();
        tokio::spawn(async move {
            crate::detect::watcher::run(
                plan.name,
                log_path,
                plan.matcher,
                plan.date_parser,
                plan.ignore_list,
                tx,
                cancel,
            )
            .await;
        });
    }
}

/// Reload the full daemon configuration: validate, swap firewalls, restart
/// watchers, and update the tracker.
pub(super) async fn reload_config(
    config_path: &std::path::Path,
    executor_tx: &mpsc::Sender<FirewallCmd>,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    current_config: &mut Config,
    watcher_cancel: &mut CancellationToken,
    failure_tx: &mpsc::Sender<Failure>,
    logger: Option<&Logger>,
) -> crate::error::Result<()> {
    let new_config = Config::from_file(config_path)?;
    let new_watcher_plan = build_watcher_plan(&new_config)?;
    let active_bans = query_active_bans(tracker_cmd_tx).await?;

    teardown_firewalls(
        executor_tx,
        current_config.enabled_jails().map(|(name, _)| name),
    )
    .await;
    if let Err(e) = init_firewalls(executor_tx, new_config.enabled_jails()).await {
        let rollback_err =
            rollback_firewalls(executor_tx, current_config, &new_config, &active_bans).await;
        let message = if let Some(rollback_err) = rollback_err {
            format!("{e}; rollback failed: {rollback_err}")
        } else {
            e.to_string()
        };
        return Err(crate::error::Error::firewall(message));
    }

    if let Err(e) = reapply_bans(executor_tx, &active_bans, &new_config).await {
        let rollback_err =
            rollback_firewalls(executor_tx, current_config, &new_config, &active_bans).await;
        let message = if let Some(rollback_err) = rollback_err {
            format!("{e}; rollback failed: {rollback_err}")
        } else {
            e.to_string()
        };
        return Err(crate::error::Error::firewall(message));
    }

    // Cancel old watchers only after the new config is known-good.
    watcher_cancel.cancel();
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let new_cancel = CancellationToken::new();
    spawn_watchers(new_watcher_plan, failure_tx, &new_cancel);
    *watcher_cancel = new_cancel;

    // Update tracker jail configs.
    let jail_configs: HashMap<String, _> = new_config
        .jail
        .iter()
        .filter(|(_, j)| j.enabled)
        .map(|(name, cfg)| (name.clone(), cfg.clone()))
        .collect();
    let jail_count = jail_configs.len();

    let _ = tracker_cmd_tx
        .send(TrackerCmd::UpdateConfig {
            global: new_config.global.clone(),
            jails: jail_configs,
        })
        .await;

    if let Some(t) = logger {
        t.log_reload(jail_count);
    }

    *current_config = new_config;

    Ok(())
}

/// Send `InitJail` commands for each enabled jail.
pub(super) async fn init_firewalls<'a>(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    jails: impl Iterator<Item = (&'a str, &'a crate::config::JailConfig)>,
) -> crate::error::Result<()> {
    for (name, jail) in jails {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let cmd = enforce::FirewallCmd::InitJail {
            jail_id: name.to_string(),
            ports: jail.port.clone(),
            protocol: jail.protocol.clone(),
            done: done_tx,
        };
        if executor_tx.send(cmd).await.is_err() {
            return Err(crate::error::Error::ChannelClosed);
        }
        match done_rx.await {
            Ok(Ok(())) => info!(jail = %name, "firewall initialized"),
            Ok(Err(e)) => {
                error!(jail = %name, error = %e, "firewall init failed");
                return Err(e);
            }
            Err(_) => return Err(crate::error::Error::ChannelClosed),
        }
    }

    Ok(())
}

/// Send `TeardownJail` commands for each jail name.
pub(super) async fn teardown_firewalls<'a>(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    jail_names: impl Iterator<Item = &'a str>,
) {
    for name in jail_names {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let cmd = enforce::FirewallCmd::TeardownJail {
            jail_id: name.to_string(),
            done: done_tx,
        };
        if executor_tx.send(cmd).await.is_err() {
            break;
        }
        match done_rx.await {
            Ok(Ok(())) => info!(jail = %name, "firewall torn down"),
            Ok(Err(e)) => {
                tracing::warn!(
                    jail = %name,
                    error = %e,
                    "teardown failed"
                );
            }
            Err(_) => break,
        }
    }
}

/// Query the tracker for all currently active bans.
pub(super) async fn query_active_bans(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
) -> crate::error::Result<Vec<BanRecord>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    tracker_cmd_tx
        .send(TrackerCmd::QueryBans { respond: tx })
        .await
        .map_err(|_| crate::error::Error::ChannelClosed)?;
    rx.await.map_err(|_| crate::error::Error::ChannelClosed)
}

/// Re-issue ban commands for active bans in jails that are still enabled.
pub(super) async fn reapply_bans(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    active_bans: &[BanRecord],
    config: &Config,
) -> crate::error::Result<()> {
    let enabled_jails: std::collections::HashSet<&str> =
        config.enabled_jails().map(|(name, _)| name).collect();

    for ban in active_bans {
        if !enabled_jails.contains(ban.jail_id.as_str()) {
            continue;
        }
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let cmd = FirewallCmd::Ban {
            ip: ban.ip,
            jail_id: ban.jail_id.clone(),
            banned_at: ban.banned_at,
            expires_at: ban.expires_at,
            done: Some(done_tx),
        };
        executor_tx
            .send(cmd)
            .await
            .map_err(|_| crate::error::Error::ChannelClosed)?;
        match done_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(crate::error::Error::ChannelClosed),
        }
    }

    Ok(())
}

/// Roll back to `current_config` firewalls after a failed reload attempt.
pub(super) async fn rollback_firewalls(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    current_config: &Config,
    attempted_config: &Config,
    active_bans: &[BanRecord],
) -> Option<crate::error::Error> {
    teardown_firewalls(
        executor_tx,
        attempted_config.enabled_jails().map(|(name, _)| name),
    )
    .await;
    teardown_firewalls(
        executor_tx,
        current_config.enabled_jails().map(|(name, _)| name),
    )
    .await;
    if let Err(e) = init_firewalls(executor_tx, current_config.enabled_jails()).await {
        return Some(e);
    }
    if let Err(e) = reapply_bans(executor_tx, active_bans, current_config).await {
        return Some(e);
    }
    None
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "reload_test.rs"]
mod reload_test;
