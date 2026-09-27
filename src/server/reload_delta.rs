//! Firewall side of a config reload: diff old/new jail sets into a
//! [`FirewallDelta`] and apply it through the executor, rolling back
//! already-committed changes when a later step fails.

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use crate::config::{Backend, Config, JailConfig};
use crate::enforce::FirewallCmd;
use crate::error::{Error, Result};
use crate::track::TrackerCmd;
use crate::track::state::BanRecord;

/// The firewall lifecycle actions a reload must perform, computed by diffing
/// the old and new enabled-jail sets.
///
/// The delta key is *jail name plus firewall-rule config*: a jail present in
/// both configs with the same backend, ports, and protocol is `kept` (its
/// kernel state is never touched); a jail whose rule config changed appears in
/// both `removed` and `added`, and is applied as one transactional executor
/// `ReplaceJail` (never a separate teardown then init).
pub(super) struct FirewallDelta {
    /// Jails whose backend must be built + initialized. Includes rule-config
    /// changes, which also appear in `removed` and are applied as replacements.
    pub(super) added: Vec<String>,
    /// Jails whose current firewall state goes away. Pure removals (not also
    /// in `added`) are torn down; the rest are replaced in place.
    pub(super) removed: Vec<String>,
    /// Jails whose firewall state is left completely untouched.
    pub(super) kept: Vec<String>,
}

impl FirewallDelta {
    /// Diff the enabled jails of `old` and `new` into add/remove/keep buckets.
    pub(super) fn compute(old: &Config, new: &Config) -> Self {
        let old_jails: HashMap<&str, &JailConfig> = old.enabled_jails().collect();
        let new_jails: HashMap<&str, &JailConfig> = new.enabled_jails().collect();

        let mut delta = Self {
            added: Vec::new(),
            removed: Vec::new(),
            kept: Vec::new(),
        };
        for (&name, &new_cfg) in &new_jails {
            delta.classify_new(name, new_cfg, &old_jails);
        }
        for &name in old_jails.keys() {
            if !new_jails.contains_key(name) {
                delta.removed.push(name.to_string());
            }
        }
        delta
    }

    /// Bucket a jail that is enabled in the new config.
    fn classify_new(
        &mut self,
        name: &str,
        new_cfg: &JailConfig,
        old_jails: &HashMap<&str, &JailConfig>,
    ) {
        match old_jails.get(name) {
            None => self.added.push(name.to_string()),
            Some(old_cfg) if firewall_rule_config_differs(old_cfg, new_cfg) => {
                self.removed.push(name.to_string());
                self.added.push(name.to_string());
            }
            Some(_) => self.kept.push(name.to_string()),
        }
    }

    /// Jails whose backend is replaced in place (in both `added` and `removed`).
    pub(super) fn replacements(&self) -> impl Iterator<Item = &str> {
        self.added
            .iter()
            .map(String::as_str)
            .filter(|name| self.removed.iter().any(|r| r == name))
    }

    /// Newly added jails (in `added` only).
    fn additions(&self) -> impl Iterator<Item = &str> {
        self.added
            .iter()
            .map(String::as_str)
            .filter(|name| !self.removed.iter().any(|r| r == name))
    }

    /// Dropped jails (in `removed` only).
    fn pure_removals(&self) -> impl Iterator<Item = &str> {
        self.removed
            .iter()
            .map(String::as_str)
            .filter(|name| !self.added.iter().any(|a| a == name))
    }
}

/// Whether two jail configs differ in a way that changes firewall rules.
///
/// Ports and protocol are passed to every native backend's `init` method, so
/// either change requires removing the old rules before creating new ones.
fn firewall_rule_config_differs(old: &JailConfig, new: &JailConfig) -> bool {
    old.port != new.port
        || old.protocol != new.protocol
        || backend_differs(&old.backend, &new.backend)
}

/// Whether two backend configs differ enough to require a rebuild.
///
/// Any type change (e.g. nftables → iptables/script) differs; two scripts
/// differ only if their ban/unban commands changed. Two ipset backends differ
/// if either knob changed — `ipset -exist create` only suppresses the
/// already-exists error when every create parameter is identical, so a changed
/// `maxelem` must destroy and recreate the set rather than fail on next init.
/// Identical backends are left untouched so the jail counts as `kept`.
pub(super) fn backend_differs(a: &Backend, b: &Backend) -> bool {
    match (a, b) {
        (Backend::Nftables, Backend::Nftables) | (Backend::Iptables, Backend::Iptables) => false,
        (
            Backend::Ipset {
                maxelem: a_max,
                chain: a_chain,
            },
            Backend::Ipset {
                maxelem: b_max,
                chain: b_chain,
            },
        ) => a_max != b_max || a_chain != b_chain,
        (
            Backend::Script {
                ban_cmd: a_ban,
                unban_cmd: a_unban,
            },
            Backend::Script {
                ban_cmd: b_ban,
                unban_cmd: b_unban,
            },
        ) => a_ban != b_ban || a_unban != b_unban,
        _ => true,
    }
}

/// Shared inputs for applying (and rolling back) one delta.
struct DeltaPlan<'a> {
    tracker_tx: &'a mpsc::Sender<TrackerCmd>,
    old_config: &'a Config,
    new_config: &'a Config,
}

/// Fallible changes committed (or possibly committed) so far, for
/// reverse-order rollback.
#[derive(Default)]
struct Committed {
    replacements: Vec<String>,
    additions: Vec<String>,
}

/// Apply a firewall delta in place while retaining enough information to roll
/// back any backend replacements or additions if a later fallible step fails.
///
/// Replacements, additions, and their rollbacks are routed through the
/// tracker ([`TrackerCmd::ForwardFirewall`]), which seeds each command with
/// the jail's bans *at enqueue time* and orders it with its own bans and
/// unbans — so no stale snapshot can re-ban an IP that was unbanned
/// meanwhile. Pure removals go straight to the executor once every fallible
/// step has been acknowledged.
pub(super) async fn apply_firewall_delta(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    tracker_tx: &mpsc::Sender<TrackerCmd>,
    delta: &FirewallDelta,
    old_config: &Config,
    new_config: &Config,
) -> Result<()> {
    for name in &delta.kept {
        info!(phase = "reload", jail = %name, action = "kept", "firewall state left untouched");
    }
    let plan = DeltaPlan {
        tracker_tx,
        old_config,
        new_config,
    };
    let mut committed = Committed::default();
    if let Err(e) = apply_fallible(&plan, delta, &mut committed).await {
        rollback_firewall_changes(&plan, &committed).await;
        return Err(e);
    }
    // Pure removals are best-effort and happen only after every fallible
    // replacement/addition has committed, so a failed reload never needs to
    // recreate an intentionally removed jail.
    for name in delta.pure_removals() {
        send_remove_jail(executor_tx, name).await;
    }
    Ok(())
}

/// Run the replacements and additions (each seeding its jail's current
/// bans), recording each committed step in `committed`.
async fn apply_fallible(
    plan: &DeltaPlan<'_>,
    delta: &FirewallDelta,
    committed: &mut Committed,
) -> Result<()> {
    for name in delta.replacements() {
        let (Some(old_jail), Some(new_jail)) = (
            plan.old_config.jail.get(name),
            plan.new_config.jail.get(name),
        ) else {
            continue;
        };
        forward_replace_jail(plan.tracker_tx, name, old_jail, new_jail)
            .await
            .commit(name, "replaced", &mut committed.replacements)?;
    }
    for name in delta.additions() {
        let Some(jail) = plan.new_config.jail.get(name) else {
            continue;
        };
        forward_add_jail(plan.tracker_tx, name, jail).await.commit(
            name,
            "added",
            &mut committed.additions,
        )?;
    }
    Ok(())
}

/// Undo already-committed fallible changes in reverse order. Rollback errors
/// are logged because the original reload error remains the primary result.
///
/// Rollbacks travel the same tracker → executor path as the steps they undo,
/// so even a step that timed out (and may still run) is undone after it.
/// Both undo operations are idempotent: removing a never-added jail is a
/// no-op, and reverse-replacing rebuilds the old backend either way.
async fn rollback_firewall_changes(plan: &DeltaPlan<'_>, committed: &Committed) {
    for name in committed.additions.iter().rev() {
        let jail_id = name.clone();
        let step = forward_and_ack(plan.tracker_tx, name, move |_bans, done| {
            FirewallCmd::RemoveJail { jail_id, done }
        });
        log_rollback(name, step.await);
    }
    for name in committed.replacements.iter().rev() {
        let (Some(old_jail), Some(new_jail)) = (
            plan.old_config.jail.get(name),
            plan.new_config.jail.get(name),
        ) else {
            continue;
        };
        log_rollback(
            name,
            forward_replace_jail(plan.tracker_tx, name, new_jail, old_jail).await,
        );
    }
}

/// Log a rollback step that did not succeed.
fn log_rollback(name: &str, step: Step) {
    let error = match step {
        Step::Acked(Ok(())) => return,
        Step::Acked(Err(e)) => e,
        Step::TimedOut => ack_timeout_error(),
    };
    error!(phase = "reload", jail = %name, error = %error, "firewall rollback failed");
}

/// Upper bound on one reload/shutdown executor round trip (send + ack).
///
/// Reload runs inline on the daemon's main loop, so an executor that never
/// acknowledges must not wedge it forever. One jail step runs a handful of
/// firewall commands, each bounded by the 30s per-command timeout; 120s
/// leaves room for ~4 slow commands (plus queued work ahead of this one)
/// before the step is failed.
#[cfg(not(test))]
pub(super) const RELOAD_ACK_TIMEOUT: Duration = Duration::from_secs(120);
/// Shortened in unit tests so the never-acking executor path runs quickly.
#[cfg(test)]
pub(super) const RELOAD_ACK_TIMEOUT: Duration = Duration::from_millis(500);

/// The error reported when a round trip exceeds [`RELOAD_ACK_TIMEOUT`].
fn ack_timeout_error() -> Error {
    Error::firewall(format!(
        "firewall executor did not acknowledge within {}s",
        RELOAD_ACK_TIMEOUT.as_secs_f64()
    ))
}

/// Send a command built around a fresh ack channel and wait (bounded by
/// [`RELOAD_ACK_TIMEOUT`]) for the ack.
///
/// A closed executor channel or a dropped ack both map to
/// [`Error::ChannelClosed`]; no ack in time is a firewall error.
pub(super) async fn send_and_ack(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    build: impl FnOnce(oneshot::Sender<Result<()>>) -> FirewallCmd,
) -> Result<()> {
    let (done_tx, done_rx) = oneshot::channel();
    let round_trip = async {
        executor_tx
            .send(build(done_tx))
            .await
            .map_err(|_| Error::ChannelClosed)?;
        done_rx.await.map_err(|_| Error::ChannelClosed)?
    };
    match tokio::time::timeout(RELOAD_ACK_TIMEOUT, round_trip).await {
        Ok(result) => result,
        Err(_) => Err(ack_timeout_error()),
    }
}

/// Outcome of one reload step routed through the tracker.
#[must_use]
enum Step {
    /// The executor answered (success, or a failure it already rolled back).
    Acked(Result<()>),
    /// No answer within [`RELOAD_ACK_TIMEOUT`]: the command may still run.
    TimedOut,
}

impl Step {
    /// Record the step in `committed` if it applied — or, on a timeout, may
    /// still apply — and return its result.
    fn commit(self, name: &str, action: &'static str, committed: &mut Vec<String>) -> Result<()> {
        match self {
            Self::Acked(result) => {
                let result = log_step(name, action, result);
                if result.is_ok() {
                    committed.push(name.to_string());
                }
                result
            }
            Self::TimedOut => {
                error!(
                    phase = "reload",
                    jail = %name,
                    action,
                    "firewall step unacknowledged; treating it as possibly applied for rollback"
                );
                committed.push(name.to_string());
                Err(ack_timeout_error())
            }
        }
    }
}

/// Hand a firewall command builder to the tracker, which seeds it with the
/// jail's current bans and enqueues it on the executor channel; wait
/// (bounded by [`RELOAD_ACK_TIMEOUT`]) for the executor's ack.
async fn forward_and_ack(
    tracker_tx: &mpsc::Sender<TrackerCmd>,
    jail_id: &str,
    build: impl FnOnce(Vec<BanRecord>, oneshot::Sender<Result<()>>) -> FirewallCmd + Send + 'static,
) -> Step {
    let (done_tx, done_rx) = oneshot::channel();
    let cmd = TrackerCmd::ForwardFirewall {
        jail_id: jail_id.to_string(),
        build: Box::new(move |bans| build(bans, done_tx)),
    };
    let round_trip = async {
        tracker_tx
            .send(cmd)
            .await
            .map_err(|_| Error::ChannelClosed)?;
        done_rx.await.map_err(|_| Error::ChannelClosed)?
    };
    match tokio::time::timeout(RELOAD_ACK_TIMEOUT, round_trip).await {
        Ok(result) => Step::Acked(result),
        Err(_) => Step::TimedOut,
    }
}

/// Log one reload step's outcome and pass the result through.
fn log_step(name: &str, action: &'static str, result: Result<()>) -> Result<()> {
    match &result {
        Ok(()) => info!(phase = "reload", jail = %name, action, "firewall jail updated"),
        Err(e) => {
            error!(phase = "reload", jail = %name, action, error = %e, "firewall jail update failed");
        }
    }
    result
}

/// Register + initialize one added jail's firewall and seed its stored bans.
async fn forward_add_jail(
    tracker_tx: &mpsc::Sender<TrackerCmd>,
    name: &str,
    jail: &JailConfig,
) -> Step {
    let (jail_id, backend) = (name.to_string(), jail.backend.clone());
    let (ports, protocol) = (jail.port.clone(), jail.protocol.clone());
    forward_and_ack(tracker_tx, name, move |active_bans, done| {
        FirewallCmd::AddJail {
            jail_id,
            backend,
            ports,
            protocol,
            active_bans,
            done,
        }
    })
    .await
}

/// Replace an existing jail's backend and seed all of its active bans. The
/// executor owns the rollback transaction so no ban command can interleave.
async fn forward_replace_jail(
    tracker_tx: &mpsc::Sender<TrackerCmd>,
    name: &str,
    from: &JailConfig,
    to: &JailConfig,
) -> Step {
    let jail_id = name.to_string();
    let backend = to.backend.clone();
    let (old_ports, old_protocol) = (from.port.clone(), from.protocol.clone());
    let (new_ports, new_protocol) = (to.port.clone(), to.protocol.clone());
    forward_and_ack(tracker_tx, name, move |active_bans, done| {
        FirewallCmd::ReplaceJail {
            jail_id,
            backend,
            old_ports,
            old_protocol,
            new_ports,
            new_protocol,
            active_bans,
            done,
        }
    })
    .await
}

/// Tear down + deregister one removed jail's firewall (best-effort).
async fn send_remove_jail(executor_tx: &mpsc::Sender<FirewallCmd>, name: &str) {
    let result = send_and_ack(executor_tx, |done| FirewallCmd::RemoveJail {
        jail_id: name.to_string(),
        done,
    })
    .await;
    match result {
        Ok(()) => {
            info!(phase = "reload", jail = %name, action = "removed", "firewall jail removed");
        }
        Err(e) => warn!(phase = "reload", jail = %name, error = %e, "firewall jail remove failed"),
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "reload_delta_test.rs"]
pub(super) mod reload_delta_test;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "reload_forward_test.rs"]
pub(super) mod reload_forward_test;
