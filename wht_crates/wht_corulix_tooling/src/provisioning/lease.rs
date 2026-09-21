// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! `ManagedExecutionLease` -- binds one live managed process to every
//! `CORULIX_MANAGED` component it consumes, so
//! [`crate::provisioning::uninstall::uninstall`] can discover and stop
//! active executions *before* quarantining a component's install root
//! (Phase 7B-B1-R3/R3-A, §2-7 and §14-16).
//!
//! Authority for this binding lives here, in `wht_corulix_tooling`, never in
//! `wht_corulix_lsp` or `wht_corulix_engine` -- a provider crate never
//! constructs, registers, or inspects a lease directly; it only supplies the
//! component ids to [`crate::ManagedProcess::spawn`], which registers the
//! lease itself, atomically, before returning
//! (`PROCESS_STARTED_WITHOUT_DISCOVERABLE_LEASE_WINDOW=0`, R3-A §4). This is
//! a second, narrower registry alongside `crate::provisioning::lock_component`'s
//! per-component provisioning lock: that lock serializes *mutation* of a
//! component's install directory; this registry tracks *live use* of an
//! already-installed component so uninstall knows whether stopping a
//! process is required before it may mutate anything.
//!
//! # Lifecycle
//!
//! ```text
//! STARTING -> ACTIVE -> STOPPING -> STOPPED
//! ```
//!
//! [`ManagedExecutionLease::register`] starts a lease in `Starting` --
//! deliberately, not `Active`, since the process has been spawned but has
//! not yet completed its own protocol handshake (e.g. LSP `initialize`).
//! [`request_stop_for_component`] blocks quarantine for a lease in *either*
//! `Starting` or `Active` -- a session mid-handshake is exactly as unsafe to
//! quarantine out from under as a fully-ready one. The owning session calls
//! [`ManagedExecutionLease::mark_active`] once its own handshake completes
//! (purely a reporting call -- Tooling does not gate on it, so a caller
//! that never calls it simply stays `Starting`, which is still safely
//! blocking). On a stop request, the session transitions to `Stopping`
//! while it performs its own graceful (then, if needed, forced) shutdown,
//! then calls [`ManagedExecutionLease::acknowledge_stopped`], which sets
//! `Stopped`.
//!
//! # Lease state is not process-state authority
//!
//! A lease's `Stopped` flag is a *cooperative* signal, not proof. Before
//! [`crate::provisioning::uninstall::uninstall`] treats a component as safe
//! to quarantine, it independently re-verifies process-group absence via
//! [`verify_process_absent`] against the pid recorded at registration --
//! never the lease's self-reported state alone
//! (`FALSE_STOPPED_LEASE_DELETE_COUNT=0`). If that independent check cannot
//! produce a definitive answer (e.g. no platform-specific absence-check
//! primitive, or a permission error), the result is
//! [`ProcessAbsence::Uncertain`], which fails closed
//! (`UNKNOWN_PROCESS_STATE_DELETE_COUNT=0`) rather than guessing.
//!
//! Conversely, a lease that still claims `Active`/`Starting` but whose
//! recorded process has already exited on its own (crash, unhandled
//! signal) reconciles automatically: [`verify_process_absent`] reports
//! [`ProcessAbsence::Absent`] regardless of what the lease's own state
//! field says, so a crashed provider does not block uninstall forever
//! (`STALE_LEASE_RECONCILIATION=PASS`). Dropping a
//! [`ManagedExecutionLease`] without an explicit
//! [`ManagedExecutionLease::release`] (a panicking or early-returning
//! owner) still deregisters it, so a crashed owner can never leave a
//! permanently-stuck phantom lease.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{sync::Notify, time::Instant};

use crate::platform;

/// Lifecycle state of one registered lease. See the module docs for the
/// full state machine and what each transition means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    Starting,
    Active,
    Stopping,
    Stopped,
}

/// Identity of the process a lease was registered for, captured once at
/// registration and never updated -- exactly what a later, independent
/// [`verify_process_absent`] call re-checks against, regardless of what the
/// lease's own [`LeaseState`] claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
}

/// Which managed root a lease's process belongs to -- the answer to "which
/// installation is this execution scoped to?" (P17-W-R3-C5,
/// `TS6_LEASE_STOP_ROOT_SCOPING_DEFECT`).
///
/// Required, never `Option`, on [`ManagedLeaseBinding`]: a lease that could
/// not declare an owning root cannot be safely matched by any
/// component-scoped stop request without reintroducing exactly the defect
/// this type exists to make unrepresentable -- a same-named component in an
/// unrelated root would be indistinguishable from the intended target.
/// [`request_stop_for_component`] therefore requires a [`RootIdentity`] in
/// its [`ComponentLeaseScope`] and can never fall back to matching every
/// root that happens to have a same-named component.
///
/// Deliberately a *distinct* type from
/// [`ManagedLeaseBinding::managed_root_identity`], not a reuse of it: that
/// field is `Option<String>` and answers a narrower, genuinely different
/// question -- whether this process also consumes `<root>/scratch` for its
/// entire run (see that field's own doc). Many leases legitimately have no
/// opinion on scratch consumption (`managed_root_identity: None`) while
/// every lease unconditionally belongs to exactly one owning root. Merging
/// the two into one optional field would make the owning-root axis
/// optional too, which is precisely the fail-open shape this fix must not
/// reintroduce (`UNTRUSTED_ROOT_IDENTITY_INJECTION=NO` requires the axis to
/// be structurally mandatory, not merely conventionally populated).
///
/// The underlying value is the same stable, order-independent digest
/// [`crate::provisioning::ownership::root_identity`] already computes and
/// [`ManagedLeaseBinding::managed_root_identity`]/`ownership`'s own records
/// use as a plain `String` -- [`RootIdentity::of`] is a thin, single-purpose
/// wrapper around that one hash authority, not a second algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RootIdentity(String);

impl RootIdentity {
    /// Derives the owning-root identity for `root` from Corulix's own
    /// managed-root digest authority
    /// ([`crate::provisioning::ownership::root_identity`]). This is the only
    /// production constructor: a [`RootIdentity`] is always derived from a
    /// real managed-root path Corulix itself resolved, never from
    /// ambient/untrusted input (workspace config, AI/MCP request fields,
    /// `PATH`, environment) -- `MANAGED_ROOT_IDENTITY_AUTHORITY=CORULIX_INTERNAL`.
    #[must_use]
    pub fn of(root: &std::path::Path) -> Self {
        Self(super::ownership::root_identity(root))
    }

    /// Test-only escape hatch for unit tests in this crate that need two
    /// (or more) distinguishable root identities but have no real managed
    /// root path to hash -- e.g. the cross-root isolation regression below.
    /// Never available outside `#[cfg(test)]`: production code must always
    /// go through [`Self::of`], which ties every `RootIdentity` back to a
    /// real Corulix-resolved managed-root path.
    #[cfg(test)]
    pub(crate) fn for_test(label: &str) -> Self {
        Self(format!("test-root::{label}"))
    }
}

/// Everything a caller declares about one process's managed-state
/// consumption, in one value. Replaces the earlier
/// `(primary_component_id, dependency_component_ids)` tuple so a third,
/// genuinely different axis -- *which managed root's* execution state this
/// process consumes -- could be added without a second registry
/// (`P15_NEW_GOPLS_LOCK_SUBSYSTEM_COUNT=0`).
///
/// The two axes are independent and both are load-bearing:
///
/// - `primary_component_id`/`dependency_component_ids` scope the lease to
///   *components*, which is what [`crate::provisioning::uninstall::uninstall`]
///   and `full_uninstall`'s per-component preflight match on.
/// - `managed_root_identity` scopes it to one managed root's *root-level*
///   execution scratch (`<root>/scratch`), which is what
///   `full_uninstall`'s scratch stage matches on. A process can genuinely
///   have the second without the first: the Engine's Go semantic session
///   resolves `gopls` and `go` `HOST_ONLY` on a host with no managed Go
///   component at all, yet its `GOCACHE`/`GOMODCACHE`/`GOPATH` are
///   Corulix-owned scratch under the managed root
///   (`wht_corulix_engine::semantic::ensure_go_lsp_session`). Before this
///   axis existed such a session was invisible to every uninstall path,
///   which is exactly the Phase 15 defect this closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLeaseBinding {
    /// Which managed root this process's execution belongs to. Required
    /// (see [`RootIdentity`]'s own doc for why this can never be
    /// `Option`) -- this is the field [`request_stop_for_component`]'s
    /// [`ComponentLeaseScope`] matches against, and it is the fix for
    /// `TS6_LEASE_STOP_ROOT_SCOPING_DEFECT` (P17-W-R3-C5): before this
    /// field existed, component-scoped stop matched by component id alone,
    /// process-wide, with no way to distinguish `ROOT_A`'s
    /// `typescript-language-server` from `ROOT_B`'s.
    pub owning_root: RootIdentity,
    pub primary_component_id: &'static str,
    pub dependency_component_ids: Vec<&'static str>,
    /// `Some(ownership::root_identity(<managed root>))` if this process
    /// consumes that root's root-level managed execution scratch for its
    /// entire run. `None` means "this process is scoped to components
    /// only" -- deliberately *not* matched by
    /// [`request_stop_for_managed_root`]/[`process_identities_for_managed_root`],
    /// because a lease with no declared root cannot be attributed to one
    /// root without wrongly blocking every *other* root's cleanup in the
    /// same process (Corulix must stay correct for independent
    /// installations, `CORULIX_SINGLE_MACHINE_ASSUMPTION=NO`). Every
    /// production process that actually writes `<root>/scratch` declares
    /// it: the long-lived LSP sessions here, and the bounded one-shot
    /// governed executions through
    /// [`crate::provisioning::acquire_managed_execution_scratch_guard`]'s
    /// root lock instead.
    pub managed_root_identity: Option<String>,
}

impl ManagedLeaseBinding {
    /// A component-scoped-only binding: this process consumes the named
    /// managed components but declares no managed-root execution scratch.
    /// Correct for every provider whose caches live *inside* a component's
    /// own install root (covered by that component's `owned_paths`), and
    /// wrong for one whose caches live under `<root>/scratch` -- those must
    /// set [`Self::managed_root_identity`] instead.
    #[must_use]
    pub fn for_components(
        owning_root: RootIdentity,
        primary_component_id: &'static str,
        dependency_component_ids: Vec<&'static str>,
    ) -> Self {
        Self {
            owning_root,
            primary_component_id,
            dependency_component_ids,
            managed_root_identity: None,
        }
    }

    /// The same binding, additionally declaring that this process consumes
    /// `<managed root>/scratch` for its entire run.
    #[must_use]
    pub fn in_managed_root(mut self, root_identity: String) -> Self {
        self.managed_root_identity = Some(root_identity);
        self
    }
}

struct LeaseEntry {
    owning_root: RootIdentity,
    primary_component_id: &'static str,
    dependency_component_ids: Vec<&'static str>,
    managed_root_identity: Option<String>,
    process: ProcessIdentity,
    state: Arc<StdMutex<LeaseState>>,
    stop_requested: Arc<Notify>,
}

type LeaseRegistry = StdMutex<HashMap<u64, LeaseEntry>>;
static LEASES: OnceLock<LeaseRegistry> = OnceLock::new();
static NEXT_LEASE_ID: OnceLock<AtomicU64> = OnceLock::new();

fn registry() -> &'static LeaseRegistry {
    LEASES.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn next_id() -> u64 {
    NEXT_LEASE_ID
        .get_or_init(|| AtomicU64::new(1))
        .fetch_add(1, Ordering::SeqCst)
}

fn set_state(state: &StdMutex<LeaseState>, value: LeaseState) {
    *state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = value;
}

fn get_state(state: &StdMutex<LeaseState>) -> LeaseState {
    *state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A handle a provider crate holds for the lifetime of its own managed
/// process. See the module docs for the full registration/stop/acknowledge
/// protocol. Never `Clone` -- one lease has exactly one owner, which is
/// what makes `Drop`-based deregistration unambiguous.
pub struct ManagedExecutionLease {
    id: u64,
    state: Arc<StdMutex<LeaseState>>,
    stop_requested: Arc<Notify>,
    released: bool,
}

impl ManagedExecutionLease {
    /// Registers a new lease in [`LeaseState::Starting`], atomically with
    /// respect to any concurrent [`request_stop_for_component`] call: by
    /// the time this returns, the lease is already discoverable in the
    /// registry, so there is no window in which the process is running but
    /// the lease cannot yet be found
    /// (`PROCESS_STARTED_WITHOUT_DISCOVERABLE_LEASE_WINDOW=0`). Callers must
    /// register *before* releasing control of the process to any other task
    /// (see `ManagedProcess::spawn`, the sole real caller).
    #[must_use]
    pub fn register(binding: ManagedLeaseBinding, process: ProcessIdentity) -> Self {
        let id = next_id();
        let state = Arc::new(StdMutex::new(LeaseState::Starting));
        let stop_requested = Arc::new(Notify::new());
        registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                id,
                LeaseEntry {
                    owning_root: binding.owning_root,
                    primary_component_id: binding.primary_component_id,
                    dependency_component_ids: binding.dependency_component_ids,
                    managed_root_identity: binding.managed_root_identity,
                    process,
                    state: state.clone(),
                    stop_requested: stop_requested.clone(),
                },
            );
        Self {
            id,
            state,
            stop_requested,
            released: false,
        }
    }

    /// Reports that this lease's owning session has completed its own
    /// readiness handshake. Purely informational -- [`request_stop_for_component`]
    /// already blocks on `Starting` exactly as it does on `Active`, so a
    /// caller that never calls this is still safe, just less precisely
    /// observable.
    pub fn mark_active(&self) {
        set_state(&self.state, LeaseState::Active);
    }

    /// Snapshots this lease's current lifecycle state. Test/observability
    /// use -- production control flow never branches on this (the state
    /// machine is driven entirely by [`Self::mark_active`],
    /// [`Self::wait_for_stop_request`], and [`Self::acknowledge_stopped`]).
    #[must_use]
    pub fn state(&self) -> LeaseState {
        get_state(&self.state)
    }

    /// Awaits a stop signal raised by [`request_stop_for_component`],
    /// transitioning to [`LeaseState::Stopping`] once observed. The owning
    /// session should race this against its own protocol work and, once it
    /// resolves, perform its normal shutdown and call
    /// [`Self::acknowledge_stopped`].
    pub async fn wait_for_stop_request(&self) {
        self.stop_requested.notified().await;
        set_state(&self.state, LeaseState::Stopping);
    }

    /// Marks this lease's process as confirmed stopped. Idempotent; safe to
    /// call even if no stop was requested (e.g. the session is shutting
    /// down on its own initiative, not because of an uninstall request).
    pub fn acknowledge_stopped(&self) {
        set_state(&self.state, LeaseState::Stopped);
    }

    /// Deregisters this lease. Also runs (idempotently) on `Drop`, so a
    /// panicking or early-returning owner never leaves a phantom lease.
    pub fn release(mut self) {
        self.release_inner();
    }

    /// A cheap, `Clone`+`Send`+`Sync`+`'static` handle sharing this lease's
    /// stop-signal/state without sharing ownership -- for a caller (e.g.
    /// `wht_corulix_lsp::LspSession`) that needs to hand the "wait for a
    /// stop request" capability to a background task while the
    /// `ManagedExecutionLease` itself stays wherever its owning
    /// `ManagedProcess` lives (so the process can still be reached and
    /// physically stopped from that same background task). Registry
    /// deregistration remains solely this value's `Drop`/`release`
    /// responsibility -- a [`LeaseWaiter`] can never deregister anything.
    #[must_use]
    pub fn waiter(&self) -> LeaseWaiter {
        LeaseWaiter {
            state: self.state.clone(),
            stop_requested: self.stop_requested.clone(),
        }
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

impl Drop for ManagedExecutionLease {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// See [`ManagedExecutionLease::waiter`].
#[derive(Clone)]
pub struct LeaseWaiter {
    state: Arc<StdMutex<LeaseState>>,
    stop_requested: Arc<Notify>,
}

impl LeaseWaiter {
    /// Same semantics as [`ManagedExecutionLease::wait_for_stop_request`].
    pub async fn wait_for_stop_request(&self) {
        self.stop_requested.notified().await;
        set_state(&self.state, LeaseState::Stopping);
    }

    /// Same semantics as [`ManagedExecutionLease::mark_active`].
    pub fn mark_active(&self) {
        set_state(&self.state, LeaseState::Active);
    }

    /// Same semantics as [`ManagedExecutionLease::acknowledge_stopped`].
    pub fn acknowledge_stopped(&self) {
        set_state(&self.state, LeaseState::Stopped);
    }

    /// Same semantics as [`ManagedExecutionLease::state`].
    #[must_use]
    pub fn state(&self) -> LeaseState {
        get_state(&self.state)
    }
}

/// Outcome of [`request_stop_for_component`] -- the ACTIVE EXECUTION
/// DISCOVERY + MANAGED PROCESS SHUTDOWN stage `uninstall()` runs before
/// quarantine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// No live lease names this component (as primary or dependency).
    /// Nothing to stop; quarantine may proceed immediately.
    NoActiveLease,
    /// Every lease naming this component confirmed stopped within `timeout`.
    Stopped,
    /// At least one lease was signalled but did not confirm stopped within
    /// `timeout`. The caller must treat the component as still busy and
    /// must not quarantine it.
    TimedOut,
}

/// Explicit, mandatory scope for a component-level stop/query: *which
/// managed root* and *which component within it*. No implicit ambient
/// "current root" and no way to construct a scope that omits the root --
/// this is the type-level fix for `TS6_LEASE_STOP_ROOT_SCOPING_DEFECT`
/// (P17-W-R3-C5): the old `request_stop_for_component(component_id: &str,
/// ..)` matched by component id alone, process-wide, so a same-named
/// component in a completely unrelated managed root was indistinguishable
/// from the intended target. Every field is borrowed, not owned, since a
/// scope is constructed immediately before one call and never stored.
#[derive(Debug, Clone, Copy)]
pub struct ComponentLeaseScope<'a> {
    pub root: &'a RootIdentity,
    pub component_id: &'a str,
}

/// Signals every live lease whose declared [`RootIdentity`] matches
/// `scope.root` *and* which names `scope.component_id` (as primary or
/// dependency) whose current state is `Starting` or `Active`, then polls up
/// to `timeout` for every signalled lease to reach `Stopped`. A lease
/// already `Stopping`/`Stopped` when discovered is included in the wait but
/// not re-signalled. A lease bound to a *different* root is never matched,
/// signalled, or waited on, regardless of how its component id compares --
/// `COMPONENT_SCOPED_STOP_CAN_NEVER_CROSS_MANAGED_ROOT=YES`.
pub async fn request_stop_for_component(
    scope: ComponentLeaseScope<'_>,
    timeout: Duration,
) -> StopOutcome {
    request_stop_matching(
        &|entry: &LeaseEntry| {
            &entry.owning_root == scope.root
                && (entry.primary_component_id == scope.component_id
                    || entry.dependency_component_ids.contains(&scope.component_id))
        },
        timeout,
    )
    .await
}

/// The root-scoped counterpart of [`request_stop_for_component`], with
/// identical semantics and the identical implementation below it: signals
/// every live lease that declared `managed_root_identity ==
/// Some(root_identity)` and polls up to `timeout` for each to confirm
/// stopped. `full_uninstall`'s `<root>/scratch` stage uses this exactly as
/// its per-component preflight uses the component variant -- one registry,
/// one stop protocol, one absence primitive, two match predicates.
///
/// A lease that declared no root (`None`) is deliberately never matched
/// here; see [`ManagedLeaseBinding::managed_root_identity`] for why
/// attributing it to *this* root would be wrong rather than merely
/// conservative.
pub async fn request_stop_for_managed_root(root_identity: &str, timeout: Duration) -> StopOutcome {
    request_stop_matching(
        &|entry: &LeaseEntry| entry.managed_root_identity.as_deref() == Some(root_identity),
        timeout,
    )
    .await
}

/// Shared body of [`request_stop_for_component`] and
/// [`request_stop_for_managed_root`] -- the stop protocol exists once, so
/// the two scopes can never drift into two subtly different shutdown
/// contracts.
async fn request_stop_matching(
    matches: &(dyn Fn(&LeaseEntry) -> bool + Sync),
    timeout: Duration,
) -> StopOutcome {
    let matching: Vec<(Arc<Notify>, Arc<StdMutex<LeaseState>>)> = {
        let guard = registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .values()
            .filter(|entry| matches(entry))
            .map(|entry| (entry.stop_requested.clone(), entry.state.clone()))
            .collect()
    };
    if matching.is_empty() {
        return StopOutcome::NoActiveLease;
    }
    for (notify, state) in &matching {
        if get_state(state) != LeaseState::Stopped {
            notify.notify_one();
        }
    }
    let deadline = Instant::now() + timeout;
    loop {
        let all_stopped = matching
            .iter()
            .all(|(_, state)| get_state(state) == LeaseState::Stopped);
        if all_stopped {
            return StopOutcome::Stopped;
        }
        if Instant::now() >= deadline {
            return StopOutcome::TimedOut;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Whether a process this crate previously registered a lease for is still
/// running, independent of what the lease's own [`LeaseState`] claims. This
/// is the primitive that makes lease state non-authoritative over OS
/// reality (module docs, "Lease state is not process-state authority").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAbsence {
    /// Independently confirmed: the process (and its whole group, on
    /// platforms where that distinction exists) is gone.
    Absent,
    /// Independently confirmed: still running.
    Present,
    /// Could not be determined on this platform/permission context. Callers
    /// must fail closed on this, never treat it as either verdict.
    Uncertain,
}

/// Deliberately `#[cfg(test)]`-only: the real `EPERM` branch
/// [`platform::test_alive`] can return (a process owned by a different real
/// OS user) cannot be deterministically forced in an unprivileged,
/// single-user test sandbox without a cross-user/privileged fixture. No
/// runtime flag/env var/user-reachable configuration exists for this --
/// only a test in this crate can call [`set_probe_override`], and
/// production code never consults anything but the real OS probe
/// (`PRODUCTION_PROCESS_PROBE_AUTHORITY=OS` holds unconditionally outside
/// `#[cfg(test)]` builds). Process-wide, exactly like `full_uninstall`'s own
/// `INJECTED_FAULT` seam -- and, exactly like that seam, this is a single
/// static shared by every test in this *crate* (not merely this module):
/// `wht_corulix_tooling`'s tests all compile into one test binary, and
/// `cargo test`'s default concurrent execution means a test in
/// `provisioning::uninstall` setting this override can be observed by a
/// concurrently-running test in this module that never touched it itself
/// (P17-W-R3-C3, `CANONICAL_DEFAULT_PARALLEL_TEST_GATE_FLAKINESS` --
/// `verify_process_absent_reports_present_then_absent_across_a_real_spawn`
/// was observed flaking under default-parallelism `cargo test --workspace`
/// for exactly this reason: `provisioning::uninstall`'s own tests already
/// serialized around a *module-local* lock, but this module's own direct
/// [`verify_process_absent`] callers acquired no lock at all against the
/// same crate-wide static). [`probe_override_test_lock`] is the one lock
/// every test in this crate that either calls [`set_probe_override`] or
/// (directly or transitively, e.g. via `uninstall`/`full_uninstall`) calls
/// [`verify_process_absent`] must hold for the entire window in which the
/// override could matter -- not merely around the single call that sets
/// it.
#[cfg(test)]
static INJECTED_PROBE_OVERRIDE: std::sync::OnceLock<std::sync::Mutex<Option<ProcessAbsence>>> =
    std::sync::OnceLock::new();

/// The one crate-wide serialization point for [`INJECTED_PROBE_OVERRIDE`].
/// `tokio::sync::Mutex` (not `std::sync::Mutex`) because callers must be
/// able to hold this guard across `.await` points spanning a real child
/// spawn/kill/wait -- not merely around the single synchronous
/// [`set_probe_override`] call. Plain (non-`tokio::test`) tests use
/// [`tokio::sync::Mutex::blocking_lock`] instead of `.await`ing this
/// directly.
#[cfg(test)]
static PROBE_OVERRIDE_TEST_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) async fn probe_override_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    PROBE_OVERRIDE_TEST_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

#[cfg(test)]
pub(crate) fn set_probe_override(result: Option<ProcessAbsence>) {
    let cell = INJECTED_PROBE_OVERRIDE.get_or_init(|| std::sync::Mutex::new(None));
    *cell
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = result;
}

/// Independently re-verifies whether `process` is still alive, via
/// `platform::test_alive` -- the same absence-check primitive
/// [`crate::provisioning::uninstall::uninstall`] uses before any
/// destructive mutation, regardless of what a lease claims about itself.
#[must_use]
pub fn verify_process_absent(process: ProcessIdentity) -> ProcessAbsence {
    #[cfg(test)]
    if let Some(cell) = INJECTED_PROBE_OVERRIDE.get()
        && let Some(overridden) = *cell
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        return overridden;
    }
    match platform::test_alive(process.pid) {
        Some(true) => ProcessAbsence::Present,
        Some(false) => ProcessAbsence::Absent,
        None => ProcessAbsence::Uncertain,
    }
}

/// Every live lease's recorded [`ProcessIdentity`] whose declared
/// [`RootIdentity`] matches `scope.root` and which names
/// `scope.component_id` as primary or dependency. `uninstall()` uses this to
/// independently re-verify absence rather than trusting
/// `StopOutcome::Stopped` alone -- root-scoped for the same reason
/// [`request_stop_for_component`] is: an unrelated root's process must never
/// be attributed to, and so never block, this root's uninstall decision.
pub(crate) fn process_identities_for_component(
    scope: ComponentLeaseScope<'_>,
) -> Vec<ProcessIdentity> {
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
        .filter(|entry| {
            &entry.owning_root == scope.root
                && (entry.primary_component_id == scope.component_id
                    || entry.dependency_component_ids.contains(&scope.component_id))
        })
        .map(|entry| entry.process)
        .collect()
}

/// Every live lease's recorded [`ProcessIdentity`] that declared
/// `managed_root_identity == Some(root_identity)`. The root-scoped
/// counterpart of `process_identities_for_component`, and used the same
/// way: `full_uninstall`'s `<root>/scratch` stage independently
/// re-verifies each of these is actually gone via [`verify_process_absent`]
/// before a single scratch byte is renamed, never trusting a cooperative
/// `StopOutcome::Stopped` alone.
/// `pub`, unlike its per-component sibling, because a *real* E2E in another
/// crate must be able to name the exact pids the lifecycle is about in order
/// to prove `P15_POST_GOPLS_FULL_UNINSTALL_ORPHAN_PROCESS_COUNT=0` and
/// `P15_GOPLS_DELETE_BEFORE_REAP_COUNT=0` against real processes rather than
/// asserting them from this crate's own internal view. It is a read-only
/// observation of already-public [`ProcessIdentity`] values: it grants no
/// mutation, forces no outcome, and bypasses no gate.
#[must_use]
pub fn process_identities_for_managed_root(root_identity: &str) -> Vec<ProcessIdentity> {
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
        .filter(|entry| entry.managed_root_identity.as_deref() == Some(root_identity))
        .map(|entry| entry.process)
        .collect()
}

/// Number of currently-registered leases naming `component_id` as primary
/// or dependency. Test-only diagnostic for asserting registration/release
/// behavior directly, without going through a full stop-request round trip.
#[cfg(test)]
pub(crate) fn active_lease_count_for_component(component_id: &str) -> usize {
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
        .filter(|entry| {
            entry.primary_component_id == component_id
                || entry.dependency_component_ids.contains(&component_id)
        })
        .count()
}

/// Total number of currently-registered leases across every component --
/// the real, production-reachable accessor `POST_FULL_UNINSTALL_ACTIVE_LEASE_COUNT`
/// and any other caller needing a real (not `#[cfg(test)]`-gated) process-
/// lifetime lease count should use. Distinct from
/// `active_lease_count_for_component`, which is test-only and scoped to
/// one component id.
#[must_use]
pub fn active_lease_count() -> usize {
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_pid() -> u32 {
        // A pid that is (almost certainly) not a live process/group on this
        // host -- used where the test only cares about registration
        // bookkeeping, not real absence-verification semantics.
        999_999
    }

    #[tokio::test]
    async fn stop_request_against_no_lease_is_noop() {
        let root = RootIdentity::for_test("stop_request_against_no_lease_is_noop");
        let outcome = request_stop_for_component(
            ComponentLeaseScope {
                root: &root,
                component_id: "nothing-leased",
            },
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(outcome, StopOutcome::NoActiveLease);
    }

    #[tokio::test]
    async fn new_lease_starts_in_starting_and_blocks_a_stop_request_like_active_does() {
        // Component ids are process-wide (the registry is a static), so
        // every test in this module uses an id unique to itself -- a
        // literal like "rust-analyzer" shared with another concurrently-
        // running test would let the two interfere with each other's
        // lifecycle assertions.
        let root = RootIdentity::for_test(
            "new_lease_starts_in_starting_and_blocks_a_stop_request_like_active_does",
        );
        let lease = ManagedExecutionLease::register(
            ManagedLeaseBinding::for_components(
                root.clone(),
                "test-fixture-starting-blocks-stop",
                vec!["test-fixture-starting-blocks-stop-dep"],
            ),
            ProcessIdentity { pid: fake_pid() },
        );
        assert_eq!(get_state(&lease.state), LeaseState::Starting);
        assert_eq!(
            active_lease_count_for_component("test-fixture-starting-blocks-stop"),
            1
        );
        assert_eq!(
            active_lease_count_for_component("test-fixture-starting-blocks-stop-dep"),
            1
        );

        let stop_task = tokio::spawn({
            let root = root.clone();
            async move {
                request_stop_for_component(
                    ComponentLeaseScope {
                        root: &root,
                        component_id: "test-fixture-starting-blocks-stop",
                    },
                    Duration::from_secs(5),
                )
                .await
            }
        });

        lease.wait_for_stop_request().await;
        assert_eq!(get_state(&lease.state), LeaseState::Stopping);
        lease.acknowledge_stopped();
        assert_eq!(get_state(&lease.state), LeaseState::Stopped);
        lease.release();

        let outcome = stop_task
            .await
            .unwrap_or_else(|error| unreachable!("stop task must not panic: {error:?}"));
        assert_eq!(outcome, StopOutcome::Stopped);
    }

    #[tokio::test]
    async fn mark_active_transitions_from_starting() {
        let root = RootIdentity::for_test("mark_active_transitions_from_starting");
        let lease = ManagedExecutionLease::register(
            ManagedLeaseBinding::for_components(root, "ts7", Vec::new()),
            ProcessIdentity { pid: fake_pid() },
        );
        assert_eq!(get_state(&lease.state), LeaseState::Starting);
        lease.mark_active();
        assert_eq!(get_state(&lease.state), LeaseState::Active);
        lease.release();
    }

    #[tokio::test]
    async fn dependency_component_id_also_matches_a_stop_request() {
        let root = RootIdentity::for_test("dependency_component_id_also_matches_a_stop_request");
        let lease = ManagedExecutionLease::register(
            ManagedLeaseBinding::for_components(
                root.clone(),
                "test-fixture-dependency-match-primary",
                vec!["test-fixture-dependency-match-dep"],
            ),
            ProcessIdentity { pid: fake_pid() },
        );
        let stop_task = tokio::spawn(async move {
            request_stop_for_component(
                ComponentLeaseScope {
                    root: &root,
                    component_id: "test-fixture-dependency-match-dep",
                },
                Duration::from_secs(5),
            )
            .await
        });
        lease.wait_for_stop_request().await;
        lease.acknowledge_stopped();
        lease.release();
        let outcome = stop_task
            .await
            .unwrap_or_else(|error| unreachable!("stop task must not panic: {error:?}"));
        assert_eq!(outcome, StopOutcome::Stopped);
    }

    #[tokio::test]
    async fn stop_request_times_out_if_never_acknowledged() {
        let root = RootIdentity::for_test("stop_request_times_out_if_never_acknowledged");
        let lease = ManagedExecutionLease::register(
            ManagedLeaseBinding::for_components(root.clone(), "hanging-provider", Vec::new()),
            ProcessIdentity { pid: fake_pid() },
        );
        let outcome = request_stop_for_component(
            ComponentLeaseScope {
                root: &root,
                component_id: "hanging-provider",
            },
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(outcome, StopOutcome::TimedOut);
        lease.release();
    }

    #[tokio::test]
    async fn dropping_a_lease_without_release_still_deregisters_it() {
        let root = RootIdentity::for_test("dropping_a_lease_without_release_still_deregisters_it");
        {
            let _lease = ManagedExecutionLease::register(
                ManagedLeaseBinding::for_components(root.clone(), "drop-fixture", Vec::new()),
                ProcessIdentity { pid: fake_pid() },
            );
            assert_eq!(active_lease_count_for_component("drop-fixture"), 1);
        }
        assert_eq!(active_lease_count_for_component("drop-fixture"), 0);
        let outcome = request_stop_for_component(
            ComponentLeaseScope {
                root: &root,
                component_id: "drop-fixture",
            },
            Duration::from_millis(20),
        )
        .await;
        assert_eq!(outcome, StopOutcome::NoActiveLease);
    }

    /// THE MANDATORY REGRESSION (P17-W-R3-C5, `CROSS_ROOT_SAME_COMPONENT_ISOLATION`):
    /// two managed roots each hold a live lease for a component with the
    /// *exact same id*. Stopping the component in `ROOT_A` must signal only
    /// `ROOT_A`'s lease -- `ROOT_B`'s lease must never receive a stop
    /// signal at all. Then the reverse: stopping `ROOT_B` must not touch
    /// `ROOT_A`.
    ///
    /// The discriminating assertion is `lease_b_never_signalled` below: it
    /// bounds `lease_b.wait_for_stop_request()` to 200ms and requires it to
    /// still be pending. Under the pre-fix, unscoped
    /// `request_stop_for_component(component_id: &str, ..)`, matching by
    /// component id alone across the whole process-wide registry, `stop_a`'s
    /// very first call would `notify_one()` *both* `lease_a` and `lease_b`'s
    /// stop signals -- so `lease_b`'s wait would resolve immediately instead
    /// of timing out, and this assertion fails. (An earlier draft of this
    /// test asserted `lease_b`'s `LeaseState` stayed `Starting` instead --
    /// that assertion is satisfied by the OLD code too, since the
    /// `Starting -> Stopping` transition only happens inside
    /// `wait_for_stop_request` itself, which nothing was awaiting on
    /// `lease_b`'s side; it is not a valid discriminator and was replaced.)
    /// This is exactly the production defect: `real_ts6_and_typescript_single_flight_e2e`'s
    /// cleanup waking an unrelated shared-root session's lease-stop task.
    /// Verified per §10 of the P17-W-R3-C5 mandate via a byte-exact
    /// revert-and-restore mutation proof (see this pass's final report,
    /// section H, for the exact command transcript).
    #[tokio::test]
    async fn cross_root_same_component_isolation() {
        let root_a = RootIdentity::for_test("cross_root_same_component_isolation::root_a");
        let root_b = RootIdentity::for_test("cross_root_same_component_isolation::root_b");
        const SHARED_COMPONENT_ID: &str = "cross-root-isolation-typescript-language-server";

        let lease_a = ManagedExecutionLease::register(
            ManagedLeaseBinding::for_components(root_a.clone(), SHARED_COMPONENT_ID, Vec::new()),
            ProcessIdentity { pid: fake_pid() },
        );
        let lease_b = ManagedExecutionLease::register(
            ManagedLeaseBinding::for_components(root_b.clone(), SHARED_COMPONENT_ID, Vec::new()),
            ProcessIdentity { pid: fake_pid() },
        );

        // Stop ROOT_A's component. ROOT_B's same-named lease must never
        // observe a stop signal at all -- the direct, fast discriminator.
        let stop_a = tokio::spawn({
            let root_a = root_a.clone();
            async move {
                request_stop_for_component(
                    ComponentLeaseScope {
                        root: &root_a,
                        component_id: SHARED_COMPONENT_ID,
                    },
                    Duration::from_secs(5),
                )
                .await
            }
        });
        lease_a.wait_for_stop_request().await;
        let lease_b_never_signalled =
            tokio::time::timeout(Duration::from_millis(200), lease_b.wait_for_stop_request()).await;
        assert!(
            lease_b_never_signalled.is_err(),
            "ROOT_B's same-named lease must never receive a stop signal from ROOT_A's stop \
             request -- it resolved instead, meaning the stop was not root-scoped"
        );
        lease_a.acknowledge_stopped();
        let outcome_a = stop_a
            .await
            .unwrap_or_else(|error| unreachable!("stop task must not panic: {error:?}"));
        assert_eq!(outcome_a, StopOutcome::Stopped);
        assert_eq!(
            get_state(&lease_b.state),
            LeaseState::Starting,
            "ROOT_B's lease must still be untouched after ROOT_A's stop completed"
        );

        // Now stop ROOT_B's component independently -- it must still work
        // (same-root component stop is unaffected by the fix).
        let stop_b = tokio::spawn({
            let root_b = root_b.clone();
            async move {
                request_stop_for_component(
                    ComponentLeaseScope {
                        root: &root_b,
                        component_id: SHARED_COMPONENT_ID,
                    },
                    Duration::from_secs(5),
                )
                .await
            }
        });
        lease_b.wait_for_stop_request().await;
        lease_b.acknowledge_stopped();
        let outcome_b = stop_b
            .await
            .unwrap_or_else(|error| unreachable!("stop task must not panic: {error:?}"));
        assert_eq!(outcome_b, StopOutcome::Stopped);

        lease_a.release();
        lease_b.release();
    }

    /// The read-side counterpart of [`cross_root_same_component_isolation`]:
    /// `process_identities_for_component` (what `uninstall()`'s independent
    /// absence re-verification iterates over) must never return an
    /// unrelated root's process identity for a same-named component, even
    /// while both leases are simultaneously live and un-stopped.
    #[tokio::test]
    async fn process_identities_for_component_is_root_scoped() {
        let root_a = RootIdentity::for_test("process_identities_for_component_is_root_scoped::a");
        let root_b = RootIdentity::for_test("process_identities_for_component_is_root_scoped::b");
        const SHARED_COMPONENT_ID: &str = "cross-root-query-isolation-rust-analyzer";
        let pid_a = 900_001;
        let pid_b = 900_002;

        let lease_a = ManagedExecutionLease::register(
            ManagedLeaseBinding::for_components(root_a.clone(), SHARED_COMPONENT_ID, Vec::new()),
            ProcessIdentity { pid: pid_a },
        );
        let lease_b = ManagedExecutionLease::register(
            ManagedLeaseBinding::for_components(root_b.clone(), SHARED_COMPONENT_ID, Vec::new()),
            ProcessIdentity { pid: pid_b },
        );

        let identities_for_a = process_identities_for_component(ComponentLeaseScope {
            root: &root_a,
            component_id: SHARED_COMPONENT_ID,
        });
        assert_eq!(identities_for_a, vec![ProcessIdentity { pid: pid_a }]);

        let identities_for_b = process_identities_for_component(ComponentLeaseScope {
            root: &root_b,
            component_id: SHARED_COMPONENT_ID,
        });
        assert_eq!(identities_for_b, vec![ProcessIdentity { pid: pid_b }]);

        lease_a.release();
        lease_b.release();
    }

    #[test]
    fn verify_process_absent_reports_absent_for_a_pid_never_reused_on_this_host() {
        // Not a live process on any real host; on Unix this exercises the
        // real `kill(-pid, 0)` -> ESRCH path end to end. On Windows
        // (P17-W-R3-C3, `WINDOWS_PROCESS_LIVENESS_PROBE_GAP` closed) this
        // exercises the real `OpenProcess` -> `ERROR_INVALID_PARAMETER`
        // path end to end -- `platform::test_alive` is no longer
        // unconditionally `None` on this target.
        //
        // Holds `probe_override_test_lock` (P17-W-R3-C3,
        // `CANONICAL_DEFAULT_PARALLEL_TEST_GATE_FLAKINESS`) for the whole
        // call: without it, a concurrently-running
        // `provisioning::uninstall` test that has set
        // `INJECTED_PROBE_OVERRIDE` (via that module's own
        // `set_probe_override_scoped`) could make this observe the
        // injected value instead of the real OS probe result -- this crate
        // compiles every module's tests into one binary, and `cargo
        // test`'s default concurrency runs them in parallel.
        let _lock = PROBE_OVERRIDE_TEST_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .blocking_lock();
        let verdict = verify_process_absent(ProcessIdentity { pid: fake_pid() });
        assert_eq!(verdict, ProcessAbsence::Absent);
    }

    #[tokio::test]
    async fn verify_process_absent_reports_present_then_absent_across_a_real_spawn()
    -> Result<(), String> {
        // Same crate-wide serialization requirement as the sync test
        // above, held across the entire spawn/kill/wait window this test
        // exercises -- see that test's comment and `probe_override_test_lock`'s
        // own doc for why a lock scoped to `provisioning::uninstall` alone
        // does not protect this module's direct callers.
        let _lock = probe_override_test_lock().await;
        // `test_alive` checks group existence (`kill(-pid, 0)`), which only
        // matches a process that is itself a group leader -- true for this
        // crate's own contained children (`platform::prepare` always sets
        // `process_group(0)`) but not necessarily for an arbitrary pid like
        // this test binary's own. A real spawned-with-`process_group(0)`
        // child is the only reliable "present" fixture.
        //
        // P17-W-R3-C2 (`WINDOWS_PROCESS_FIXTURE_PORTABILITY`): the target
        // is now the cross-platform `wht_corulix_process_fixture` binary
        // in `sleep-ms` mode, never the previous hardcoded `/bin/sleep`
        // (which does not exist on Windows and, unlike every other site in
        // this file, was not even `#[cfg(unix)]`-gated at the spawn call).
        let fixture = crate::fixture_support::fixture_binary_path()?;
        let mut command = tokio::process::Command::new(fixture);
        command.args(["sleep-ms", "5000"]);
        #[cfg(unix)]
        platform::prepare(&mut command);
        let mut child = command
            .spawn()
            .map_err(|error| format!("spawning the process fixture must succeed: {error:?}"))?;
        let pid = child.id().ok_or("just-spawned child must have a pid")?;

        // On Windows (P17-W-R3-C3) `test_alive` answers per-process
        // liveness (`OpenProcess`/`WaitForSingleObject` on this exact
        // pid), not per-group -- but a single-process fixture spawned in
        // `sleep-ms` mode is exactly the case both platforms agree on, so
        // the assertion is unconditional here too.
        let while_running = verify_process_absent(ProcessIdentity { pid });
        assert_eq!(while_running, ProcessAbsence::Present);

        let _ = child.kill().await;
        let _ = child.wait().await;

        let after_exit = verify_process_absent(ProcessIdentity { pid });
        assert_eq!(after_exit, ProcessAbsence::Absent);
        Ok(())
    }
}
