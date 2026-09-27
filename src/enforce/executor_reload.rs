//! Reload-lifecycle firewall handlers: add a jail, transactionally replace
//! its backend, or remove it.

use std::collections::HashMap;
use std::hash::BuildHasher;

use tokio::sync::oneshot;
use tracing::{debug, error, warn};

use crate::config::Backend;
use crate::enforce::{FirewallBackend, FirewallCmd, create_backend};
use crate::error::{Error, Result};
use crate::track::state::BanRecord;

use super::send_done;

/// Rules each registered jail backend is actually running with, keyed by jail.
///
/// A `ReplaceJail` carries the rules its *sender* believes are live, but a
/// reload rollback's reverse replace cannot know whether the forward replace
/// committed or was itself rolled back inside the executor. Restoring the
/// previous backend therefore uses the rules recorded here.
pub(super) type RunningRules = HashMap<String, JailRules>;

/// Dispatch the reload-lifecycle commands: add a jail, transactionally replace
/// its backend (never a remove-then-add), or remove it.
pub(super) async fn handle_reload_cmd<S: BuildHasher>(
    cmd: FirewallCmd,
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    running: &mut RunningRules,
) {
    match cmd {
        FirewallCmd::AddJail {
            jail_id,
            backend,
            ports,
            protocol,
            active_bans,
            done,
        } => {
            let job = AddJob {
                jail_id,
                rules: JailRules::new(ports, protocol),
                active_bans,
            };
            add_jail(backends, running, &backend, &job, done).await;
        }
        replace @ FirewallCmd::ReplaceJail { .. } => {
            dispatch_replace(replace, backends, running).await;
        }
        FirewallCmd::RemoveJail { jail_id, done } => {
            running.remove(&jail_id);
            remove_jail(backends, &jail_id, done).await;
        }
        other => warn!(?other, "unexpected command on reload dispatch"),
    }
}

/// Parameters of one jail addition.
pub(super) struct AddJob {
    /// Jail being added.
    pub(super) jail_id: String,
    /// Rules to initialize the new backend with.
    pub(super) rules: JailRules,
    /// The jail's stored bans (as of when the command was enqueued) to seed.
    pub(super) active_bans: Vec<BanRecord>,
}

/// Unpack a `ReplaceJail` command and run the replacement transaction.
async fn dispatch_replace<S: BuildHasher>(
    cmd: FirewallCmd,
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    running: &mut RunningRules,
) {
    let FirewallCmd::ReplaceJail {
        jail_id,
        backend,
        old_ports,
        old_protocol,
        new_ports,
        new_protocol,
        active_bans,
        done,
    } = cmd
    else {
        return;
    };
    let claimed_old = JailRules::new(old_ports, old_protocol);
    let job = ReplaceJob {
        old_rules: running_rules(running, &jail_id, claimed_old),
        jail_id,
        new_rules: JailRules::new(new_ports, new_protocol),
        active_bans,
    };
    replace_jail(backends, running, &backend, &job, done).await;
}

/// The rules the jail's registered backend is running with, falling back to
/// the command's `claimed` old rules when none were recorded.
pub(super) fn running_rules(
    running: &RunningRules,
    jail_id: &str,
    claimed: JailRules,
) -> JailRules {
    match running.get(jail_id) {
        Some(live) if *live != claimed => {
            debug!(jail = %jail_id, "replace uses recorded live rules, not the command's old rules");
            live.clone()
        }
        _ => claimed,
    }
}

/// Register a jail's backend, initialize its kernel state, and seed its
/// stored bans, replying on `done`.
///
/// The backend is inserted only after a successful `init`, so a failed
/// initialization never leaves a half-registered jail behind.
async fn add_jail<S: BuildHasher>(
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    running: &mut RunningRules,
    backend: &Backend,
    job: &AddJob,
    done: oneshot::Sender<Result<()>>,
) {
    debug!(jail = %job.jail_id, "firewall adding jail");
    let result = match create_backend(backend) {
        Ok(created) => register_jail(backends, created, job).await,
        Err(e) => Err(e),
    };
    if let Err(ref e) = result {
        error!(jail = %job.jail_id, error = %e, "firewall add jail failed");
    } else {
        running.insert(job.jail_id.clone(), job.rules.clone());
    }
    send_done(done, result, &job.jail_id);
}

/// Run `init`, reapply the job's bans (per-ban failures are logged and
/// tolerated), then insert the backend into the map.
pub(super) async fn register_jail<S: BuildHasher>(
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    created: Box<dyn FirewallBackend>,
    job: &AddJob,
) -> Result<()> {
    let jail_id = job.jail_id.as_str();
    created
        .init(jail_id, &job.rules.ports, &job.rules.protocol)
        .await?;
    reapply_backend_bans(created.as_ref(), jail_id, &job.active_bans).await;
    backends.insert(jail_id.to_string(), created);
    Ok(())
}

/// Firewall rule parameters a backend is initialized with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct JailRules {
    /// Ports the jail's rules match (empty = all ports).
    pub(super) ports: Vec<String>,
    /// Protocol the jail's rules match.
    pub(super) protocol: String,
}

impl JailRules {
    /// Bundle a jail's ports and protocol.
    pub(super) fn new(ports: Vec<String>, protocol: String) -> Self {
        Self { ports, protocol }
    }
}

/// Parameters of one backend replacement transaction.
pub(super) struct ReplaceJob {
    /// Jail whose backend is replaced.
    pub(super) jail_id: String,
    /// Rules the previous backend is running with (used for rollback) — the
    /// executor's recorded [`RunningRules`] entry when one exists.
    pub(super) old_rules: JailRules,
    /// Rules to initialize the replacement with.
    pub(super) new_rules: JailRules,
    /// Snapshot of the jail's active bans to seed whichever backend ends up live.
    pub(super) active_bans: Vec<BanRecord>,
}

/// Replace one backend as a transaction, restoring the previous backend when
/// replacement fails at any step; replies on `done`.
async fn replace_jail<S: BuildHasher>(
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    running: &mut RunningRules,
    backend: &Backend,
    job: &ReplaceJob,
    done: oneshot::Sender<Result<()>>,
) {
    debug!(jail = %job.jail_id, "firewall replacing jail backend");
    let result = match create_backend(backend) {
        Ok(replacement) => replace_tracked(backends, running, replacement, job).await,
        Err(e) => Err(e),
    };
    if let Err(ref e) = result {
        error!(jail = %job.jail_id, error = %e, "firewall replace jail failed");
    }
    send_done(done, result, &job.jail_id);
}

/// Run the replacement transaction and record which rules are live after it:
/// the new rules on success, otherwise the previous backend's restored rules.
pub(super) async fn replace_tracked<S: BuildHasher>(
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    running: &mut RunningRules,
    replacement: Box<dyn FirewallBackend>,
    job: &ReplaceJob,
) -> Result<()> {
    let result = replace_jail_with_backend(backends, replacement, job).await;
    let live = if result.is_ok() {
        &job.new_rules
    } else {
        &job.old_rules
    };
    running.insert(job.jail_id.clone(), live.clone());
    result
}

/// Transaction core split out so rollback behavior can be tested with fully
/// deterministic in-memory backends.
///
/// On any failure the previous backend is rebuilt with its old rules and bans
/// and re-registered, so the jail never enters a no-backend state.
pub(super) async fn replace_jail_with_backend<S: BuildHasher>(
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    replacement: Box<dyn FirewallBackend>,
    job: &ReplaceJob,
) -> Result<()> {
    let jail_id = job.jail_id.as_str();
    let Some(previous) = backends.remove(jail_id) else {
        return Err(Error::firewall(format!(
            "cannot replace jail '{jail_id}': no backend is registered"
        )));
    };

    if let Err(e) = previous.teardown(jail_id).await {
        // Teardown may have removed part of the old state; rebuild it.
        let restored = rebuild_backend(previous.as_ref(), job, &job.old_rules).await;
        backends.insert(jail_id.to_string(), previous);
        return Err(with_restore_error(e, restored));
    }

    if let Err(e) = rebuild_backend(replacement.as_ref(), job, &job.new_rules).await {
        return Err(rollback_replacement(backends, previous, replacement.as_ref(), job, e).await);
    }
    backends.insert(jail_id.to_string(), replacement);
    Ok(())
}

/// Clean up a failed replacement, then rebuild and re-register the previous
/// backend. Returns the error to report (including any restore failure).
async fn rollback_replacement<S: BuildHasher>(
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    previous: Box<dyn FirewallBackend>,
    replacement: &dyn FirewallBackend,
    job: &ReplaceJob,
    error: Error,
) -> Error {
    let jail_id = job.jail_id.as_str();
    // Initialization may have created only part of a backend's state.
    // Remove that state before rebuilding the previous backend.
    if let Err(e) = replacement.teardown(jail_id).await {
        warn!(jail = %jail_id, error = %e, "replacement cleanup failed");
    }
    let restored = rebuild_backend(previous.as_ref(), job, &job.old_rules).await;
    // Keep the old backend registered even when restoration reports an error:
    // later bans then fail (or succeed) per-ban against it, and the periodic
    // and post-reload reconciles re-apply missing bans through it. Without a
    // registered backend reconcile could only log and skip the jail.
    backends.insert(jail_id.to_string(), previous);
    with_restore_error(error, restored)
}

/// Initialize a backend with `rules` and reapply the job's bans. Only an
/// `init` failure is an error; per-ban failures are logged and tolerated.
async fn rebuild_backend(
    backend: &dyn FirewallBackend,
    job: &ReplaceJob,
    rules: &JailRules,
) -> Result<()> {
    backend
        .init(&job.jail_id, &rules.ports, &rules.protocol)
        .await?;
    reapply_backend_bans(backend, &job.jail_id, &job.active_bans).await;
    Ok(())
}

/// Fold a rollback failure into the primary error, if there was one.
fn with_restore_error(primary: Error, restored: Result<()>) -> Error {
    match restored {
        Ok(()) => primary,
        Err(restore_error) => Error::firewall(format!(
            "backend replacement failed: {primary}; rollback failed: {restore_error}"
        )),
    }
}

/// Reapply a jail's bans to a freshly initialized backend.
///
/// Per-ban failures are logged and counted, never fatal: one bad entry must
/// not abort a whole backend replacement, and the post-reload reconcile heals
/// what is missing. Returns the number of bans that failed.
pub(super) async fn reapply_backend_bans(
    backend: &dyn FirewallBackend,
    jail_id: &str,
    active_bans: &[BanRecord],
) -> usize {
    let now = chrono::Utc::now().timestamp();
    let mut failed = 0usize;
    for ban in active_bans.iter().filter(|b| b.jail_id == jail_id) {
        if let Err(e) = backend
            .ban_with_timeout(&ban.ip, jail_id, ban.expires_at, now)
            .await
        {
            failed += 1;
            warn!(ip = %ban.ip, jail = %jail_id, error = %e, "ban reapply failed");
        }
    }
    if failed > 0 {
        warn!(jail = %jail_id, failed, "some bans could not be reapplied");
    }
    failed
}

/// Tear down a jail's kernel state and remove its backend, replying on `done`.
///
/// The teardown removes the jail's own chain/set (and every banned element);
/// shared infrastructure is left in place for the still-active jails.
async fn remove_jail<S: BuildHasher>(
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    jail_id: &str,
    done: oneshot::Sender<Result<()>>,
) {
    debug!(jail = %jail_id, "firewall removing jail");
    let result = match backends.get(jail_id) {
        Some(backend) => backend.teardown(jail_id).await,
        None => Ok(()),
    };
    backends.remove(jail_id);
    if let Err(ref e) = result {
        debug!(jail = %jail_id, error = %e, "firewall remove jail teardown error");
    }
    send_done(done, result, jail_id);
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "executor_reload_test.rs"]
mod executor_reload_test;
