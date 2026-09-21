// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical LSP session lifecycle: spawn (via `wht_corulix_tooling`) ->
//! `initialize` -> `initialized` -> readiness proof -> semantic operations
//! -> `shutdown` -> `exit` -> wait/reap. Owns exactly one language-server
//! process and its [`Transport`]; all semantic operations in
//! `crate::operations` borrow a session rather than talking to the
//! transport directly.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, Notify};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_workspace::WorkspaceRoot;

use crate::{
    error::LspError,
    profile::{LspProviderProfile, ReadinessStrategy},
    readiness::{self, Readiness, ReadinessSink, ReadinessWatch},
    transport::Transport,
    uri,
};

/// Bounded default request timeout. Every operation in `crate::operations`
/// uses this unless a caller-specific override is introduced later.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long [`LspSession::shutdown`] waits for a graceful exit after the
/// `exit` notification before escalating to whole-process-tree
/// termination.
const GRACEFUL_EXIT_WINDOW: Duration = Duration::from_secs(5);

/// A live session with one spawned, initialized language-server process.
///
/// A session binds to exactly **one** [`WorkspaceRoot`] -- selected by the
/// caller from Corulix's existing `WorkspaceContext` (the same
/// root-selection pattern `wht_corulix_engine::CorulixEngine::{parse_relative_file,
/// resolve_confined}` already use), not an arbitrary raw path. This is a
/// deliberate, explicit choice for `MultiRoot` topologies: each member root
/// is its own independent Rust crate/workspace with its own semantic
/// database, so one rust-analyzer process per selected root is the correct
/// model -- conflating unrelated roots into a single `initialize` call
/// would not be "supporting multi-root", it would silently merge distinct
/// semantic universes.
pub struct LspSession {
    transport: Arc<Transport>,
    process: Arc<Mutex<Option<wht_corulix_tooling::ManagedProcess>>>,
    readiness: Mutex<ReadinessWatch>,
    readiness_sink: ReadinessSink,
    readiness_strategy: ReadinessStrategy,
    workspace_root: WorkspaceRoot,
    root_id: WorkspaceRootId,
    open_documents: Mutex<HashSet<String>>,
    diagnostics: Arc<Mutex<HashMap<String, Vec<ls_types::Diagnostic>>>>,
    diagnostics_published: Arc<Notify>,
    pump_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Races `ManagedExecutionLease::wait_for_stop_request` (via the cheap
    /// `LeaseWaiter` clone `ManagedProcess::lease_waiter` hands back) against
    /// this session's own lifetime, so an external
    /// `wht_corulix_tooling::provisioning::uninstall::uninstall` call can
    /// stop this exact session even though nothing else is driving it right
    /// now. `None` when this session's provider never resolved through
    /// `CORULIX_MANAGED` (see `ResolvedLaunch::managed_lease`'s doc) -- a
    /// `HOST_ONLY`/system process is never leased and has no such task.
    lease_stop_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Kept independent of `process` (which is `take()`n once shutdown
    /// actually runs) so [`Self::lease_state`] can still observe the final
    /// `Stopped` transition after the process itself is gone.
    lease_waiter: Option<wht_corulix_tooling::provisioning::lease::LeaseWaiter>,
    lsp_language_id: &'static str,
    /// M09-P8: latches to `true` the first time
    /// [`Self::ensure_root_identity_or_invalidate`] observes a root
    /// identity mismatch. One-way: never reset back to `false`, even if
    /// the pathname is later restored to the original pinned object (an
    /// ABA swap-then-restore) -- this session must never silently resume
    /// trusting a provider process that ran, uninterrupted, through an
    /// observed root swap. A `Mutex` (not an `AtomicBool`) so the
    /// check-then-terminate sequence in that method is one atomic critical
    /// section: two concurrent semantic requests racing the same mismatch
    /// must not both observe "not yet invalidated" and both attempt to
    /// terminate the same already-gone process.
    invalidated: Mutex<bool>,
}

impl LspSession {
    /// Spawns `launch` (an already-resolved [`crate::profile::ResolvedLaunch`]
    /// -- this function performs no resolution of its own; see
    /// [`crate::profile::resolve_launch`] for that) as a managed process via
    /// `wht_corulix_tooling`, then runs the `initialize`/`initialized`
    /// handshake. `root_id` is the caller-selected `WorkspaceRootId`
    /// `workspace_root` corresponds to (see the type-level doc above); every
    /// result this session returns carries this exact id. Does **not** wait
    /// for semantic readiness -- call [`Self::wait_until_ready`] separately,
    /// since readiness can legitimately take much longer than a bounded
    /// spawn/handshake should.
    pub async fn spawn(
        launch: crate::profile::ResolvedLaunch,
        profile: &LspProviderProfile,
        workspace_root: WorkspaceRoot,
        root_id: WorkspaceRootId,
        cancellation: &CancellationToken,
    ) -> Result<Self, LspError> {
        let crate::profile::ResolvedLaunch {
            executable,
            arguments,
            environment,
            managed_lease,
            extra_initialization_options,
        } = launch;
        let spec = wht_corulix_tooling::ManagedProcessSpec {
            executable,
            arguments,
            environment,
            // M09-P8: this field remains set to the pinned root's own
            // canonical path -- not because the pathname is the cwd
            // authority (it is not, on Unix; see below), but because
            // `spawn_with_workspace_root` asserts the two match as a
            // fail-closed consistency check before it ever pins the
            // child's cwd to the root's fd-based identity instead. On
            // non-Unix targets (pre-P9/P10 Windows) this field is still
            // the real, sole cwd authority, unchanged from before.
            working_directory: workspace_root.canonical_path().to_path_buf(),
            max_stderr_bytes: 1024 * 1024,
            argv0: None,
            managed_lease,
        };
        // M09-P8/M09-P10: on Unix, bind the child's cwd to the pinned
        // `WorkspaceRoot` filesystem OBJECT (via the already-certified P7
        // `spawn_with_workspace_root`, which internally calls
        // `WorkspaceRoot::bind_process_cwd`) rather than trusting
        // `spec.working_directory` as a re-resolvable pathname -- this
        // eliminates the exact root-swap TOCTOU window the P8 mandate
        // targets (a normal-directory/symlink/ancestor replacement at the
        // workspace's own canonical pathname, timed between this spawn and
        // any later use of that pathname, can no longer redirect the
        // language-server process's cwd). On Windows, `spawn_with_workspace_root`
        // fails closed before any process is spawned (no `fchdir`-equivalent
        // primitive exists there to preserve object-bound cwd across `exec`)
        // -- an LSP session can never be created against a workspace on
        // Windows via this path, rather than falling back to the
        // pathname-based `ManagedProcess::spawn`.
        let spawn_result =
            wht_corulix_tooling::ManagedProcess::spawn_with_workspace_root(&spec, &workspace_root)
                .await;
        let mut process = spawn_result.map_err(|_| LspError::ProviderSpawnFailed)?;
        let lease_waiter = process.lease_waiter();

        let Some((stdin, stdout)) = process.take_io() else {
            // A live process is already running at this point; terminate it
            // rather than dropping `process` and leaking it (`ManagedProcess`
            // has no `Drop` impl of its own -- see this function's own later
            // doc comment on the `initialize_handshake` failure path for the
            // same reasoning).
            let _ = process.terminate().await;
            return Err(LspError::ProviderSpawnFailed);
        };

        let transport = Arc::new(Transport::spawn(stdin, stdout));
        let process = Arc::new(Mutex::new(Some(process)));
        let (readiness_sink, readiness_watch) = readiness::channel();
        let diagnostics: Arc<Mutex<HashMap<String, Vec<ls_types::Diagnostic>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let diagnostics_published = Arc::new(Notify::new());
        let pump_task = spawn_notification_pump(
            Arc::clone(&transport),
            readiness_sink.clone(),
            Arc::clone(&diagnostics),
            Arc::clone(&diagnostics_published),
            profile.readiness_strategy,
        );
        let lease_stop_task = lease_waiter.as_ref().map(|waiter| {
            spawn_lease_stop_task(Arc::clone(&transport), Arc::clone(&process), waiter.clone())
        });

        let session = Self {
            transport,
            process,
            readiness: Mutex::new(readiness_watch),
            readiness_sink,
            readiness_strategy: profile.readiness_strategy,
            workspace_root,
            root_id,
            open_documents: Mutex::new(HashSet::new()),
            diagnostics,
            diagnostics_published,
            pump_task: Mutex::new(Some(pump_task)),
            lease_stop_task: Mutex::new(lease_stop_task),
            lease_waiter: lease_waiter.clone(),
            lsp_language_id: profile.lsp_language_id,
            invalidated: Mutex::new(false),
        };

        // A process is now genuinely running (`ManagedProcess::spawn`
        // already succeeded above), so any failure from here on must not
        // simply drop `session` and walk away: `LspSession` has no `Drop`
        // impl (dropping a `JoinHandle` does not abort its task, and
        // `ManagedProcess` has no `Drop` impl of its own either), so a bare
        // early return here previously left the spawned process (and its
        // notification-pump/lease-stop background tasks) running forever,
        // uncached and unreachable by any caller -- confirmed empirically:
        // repeated failed `initialize` attempts against a real workspace
        // accumulated multiple orphaned managed `rust-analyzer` processes on
        // a real host. `shutdown` is documented idempotent-safe even against
        // a process that never completed `initialize`, so this is a safe,
        // unconditional cleanup on the failure path
        // (`FAILED_LSP_STARTUP_LEAK_COUNT=0`), not merely a Rust-specific
        // patch -- every language's session goes through this one `spawn`.
        if let Err(error) = session
            .initialize_handshake(profile, extra_initialization_options, cancellation)
            .await
        {
            // Root-cause observability (internal only -- the returned
            // `LspError` shape and every caller's handling of it are
            // unchanged). Distinguishes an early child exit / transport
            // failure during the `initialize` handshake from every other
            // `LspError::ProviderSpawnFailed` cause instrumented elsewhere
            // in this crate.
            tracing::warn!(
                provider_id = profile.provider_id,
                failure_stage = "LSP_INITIALIZATION",
                internal_failure_kind = ?error,
                "LSP initialize handshake failed"
            );
            session.shutdown(cancellation).await;
            return Err(error);
        }
        if let Some(waiter) = &lease_waiter {
            waiter.mark_active();
        }
        Ok(session)
    }

    /// M09-P8 request-boundary / pre-`initialize` root-identity gate.
    /// Called here as the very first step of [`Self::initialize_handshake`]
    /// (Section 14: the process is already spawned with a pinned cwd at
    /// this point, but the `rootUri`/`workspaceFolders` this method is
    /// about to send are still built from `self.workspace_root`'s own
    /// canonical *pathname* -- this closes the one remaining window: has
    /// that pathname been swapped since `self.workspace_root` was
    /// constructed, before this session ever asserts a root identity to
    /// the provider), and again as the first step of every semantic
    /// operation in `crate::operations` (Section 16).
    ///
    /// Fail-closed, sticky (Section 18): a mismatch here permanently
    /// invalidates this exact session (see [`Self::invalidated`]'s own
    /// doc) and terminates/reaps the already-spawned provider via the same
    /// graceful-shutdown-then-terminate sequence every other teardown path
    /// uses, before returning [`LspError::RootIdentityMismatch`] -- no
    /// request is ever sent to a provider whose root identity could not be
    /// reconfirmed. A prior mismatch short-circuits every later call on
    /// this session to [`LspError::SessionInvalidated`] without
    /// re-checking identity, even across an ABA restore -- the caller must
    /// discard this session and construct a fresh one via [`Self::spawn`].
    ///
    /// Windows (pre-P9/P10): no pinned-object identity exists yet to
    /// verify against, so this is a no-op that always succeeds -- matches
    /// this crate's existing, owner-accepted `rootUri`/`workspaceFolders`
    /// whole-session pathname residual on that platform; it does not
    /// regress anything Windows previously had.
    pub(crate) async fn ensure_root_identity_or_invalidate(&self) -> Result<(), LspError> {
        let mut invalidated = self.invalidated.lock().await;
        if *invalidated {
            return Err(LspError::SessionInvalidated);
        }
        #[cfg(unix)]
        let identity_ok = self.workspace_root.verify_current_path_identity();
        #[cfg(not(unix))]
        let identity_ok = true;
        if identity_ok {
            return Ok(());
        }
        *invalidated = true;
        drop(invalidated);
        // A freshly-constructed, never-cancelled token is correct here:
        // this cleanup is unconditional and must not be interrupted by
        // whatever cancellation state the caller's own in-flight operation
        // happens to carry -- see `Self::shutdown`'s own doc for the
        // graceful-then-forced sequence this reuses verbatim.
        self.shutdown(&CancellationToken::new()).await;
        Err(LspError::RootIdentityMismatch)
    }

    async fn initialize_handshake(
        &self,
        profile: &LspProviderProfile,
        extra_initialization_options: Option<serde_json::Value>,
        cancellation: &CancellationToken,
    ) -> Result<(), LspError> {
        self.ensure_root_identity_or_invalidate().await?;
        let root_uri = uri::path_to_file_uri(self.workspace_root.canonical_path())
            .ok_or(LspError::UnrepresentableResult)?;
        let params = ls_types::InitializeParams {
            process_id: Some(std::process::id()),
            capabilities: ls_types::ClientCapabilities {
                experimental: profile.experimental_capability.map(|build| build()),
                // `workspace.configuration`/`workspace.workspaceFolders` and
                // `textDocument.publishDiagnostics` -- proven necessary via a
                // real raw-probe root-cause investigation (Phase 7B-C)
                // against `typescript-language-server`. Without
                // `workspace.configuration`, the server never issues its
                // `workspace/configuration` round-trip at all. Without
                // `textDocument.publishDiagnostics`, the server computes
                // diagnostics but never *sends* the `publishDiagnostics`
                // notification -- confirmed by a raw probe with only the
                // `workspace` half declared: the `workspace/configuration`
                // round-trip completed correctly, yet no
                // `publishDiagnostics` notification ever followed, across
                // three independent transport implementations
                // (`wht_corulix_tooling::ManagedProcess`, bare
                // `tokio::process`, and bare `std::process` with fully
                // blocking OS-thread I/O) -- ruling out `ManagedProcess`,
                // async/`tokio` I/O, and blocking-vs-async I/O in general as
                // the cause. Declaring both capabilities together resolves
                // it: `publishDiagnostics` arrives in under a second on
                // every transport tested, including the real product path
                // through this exact session/transport. Both declarations
                // are real, generic prerequisites -- not TS6-specific -- and
                // rust-analyzer/gopls/Pyright never depended on the client
                // omitting either.
                workspace: Some(ls_types::WorkspaceClientCapabilities {
                    configuration: Some(true),
                    workspace_folders: Some(true),
                    ..Default::default()
                }),
                text_document: Some(ls_types::TextDocumentClientCapabilities {
                    publish_diagnostics: Some(ls_types::PublishDiagnosticsClientCapabilities {
                        related_information: Some(true),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            // `extra_initialization_options` (from `ResolvedLaunch`, e.g. a
            // managed TypeScript 6 runtime's resolved `tsserver.path`) is
            // merged on top of the profile's own static
            // `initialization_options` -- the managed-resolved value always
            // wins over the profile's own static shape, since it reflects
            // what actually resolved at spawn time (Phase 7B-C). A shallow
            // top-level merge is sufficient for every real use today (a
            // single top-level key, e.g. `tsserver`, that the profile's own
            // static options never set).
            initialization_options: merge_initialization_options(
                profile.initialization_options.map(|build| build()),
                extra_initialization_options,
            ),
            workspace_folders: Some(vec![ls_types::WorkspaceFolder {
                uri: root_uri,
                name: "workspace".to_string(),
            }]),
            ..Default::default()
        };
        let params_value =
            serde_json::to_value(params).map_err(|_| LspError::UnrepresentableResult)?;
        let response = self
            .transport
            .request(
                "initialize",
                params_value,
                DEFAULT_REQUEST_TIMEOUT,
                cancellation,
            )
            .await?;
        let _typed: ls_types::InitializeResult =
            serde_json::from_value(response).map_err(|_| LspError::UnrepresentableResult)?;

        self.transport
            .notify("initialized", serde_json::json!({}))
            .await?;
        Ok(())
    }
}

/// Shallow top-level merge of `extra` onto `base` for `initializationOptions`
/// -- `extra` (a managed runtime's resolved value, e.g. `{"tsserver":
/// {"path": ...}}`) always wins on a key collision, since it reflects what
/// actually resolved at spawn time; a key present in `base` but absent from
/// `extra` is preserved unchanged. `None`/`None` stays `None`; either side
/// alone passes through unchanged.
fn merge_initialization_options(
    base: Option<serde_json::Value>,
    extra: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    match (base, extra) {
        (
            Some(serde_json::Value::Object(mut base_map)),
            Some(serde_json::Value::Object(extra_map)),
        ) => {
            for (key, value) in extra_map {
                base_map.insert(key, value);
            }
            Some(serde_json::Value::Object(base_map))
        }
        (base, None) => base,
        (None, extra) => extra,
        (Some(base), Some(_)) => Some(base),
    }
}

impl LspSession {
    /// Awaits [`Readiness::Ready`] within `timeout`. See `crate::readiness`
    /// for why this is never assumed true merely because `initialize`
    /// completed.
    pub async fn wait_until_ready(&self, timeout: Duration) -> Result<(), LspError> {
        self.readiness
            .lock()
            .await
            .wait_until_ready(timeout)
            .await?;
        Ok(())
    }

    #[must_use]
    pub async fn readiness(&self) -> Readiness {
        self.readiness.lock().await.current()
    }

    #[must_use]
    pub fn workspace_root(&self) -> &WorkspaceRoot {
        &self.workspace_root
    }

    /// The exact `TextDocumentItem.languageId` this session was spawned
    /// with (e.g. `"typescript"`, `"javascript"`, `"rust"`). Used by
    /// `crate::project_priming` to decide, per session, whether whole-
    /// project operations need bounded sibling-document priming -- kept as
    /// a plain accessor rather than exposing the whole profile, since that
    /// is the only field priming decisions need.
    #[must_use]
    pub(crate) fn lsp_language_id(&self) -> &'static str {
        self.lsp_language_id
    }

    #[must_use]
    pub fn root_id(&self) -> WorkspaceRootId {
        self.root_id
    }

    #[must_use]
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// This session's `ManagedExecutionLease` lifecycle state, if its
    /// provider resolved through `CORULIX_MANAGED` (`None` for a
    /// `HOST_ONLY`/system provider, which is never leased). Test/
    /// observability use, proving the real `Starting -> Active -> Stopping
    /// -> Stopped` transitions against a real managed process (Phase
    /// 7B-B1-R3-A §6) -- production control flow never branches on this.
    #[must_use]
    pub fn lease_state(&self) -> Option<wht_corulix_tooling::provisioning::lease::LeaseState> {
        self.lease_waiter
            .as_ref()
            .map(wht_corulix_tooling::provisioning::lease::LeaseWaiter::state)
    }

    /// This session's real managed-process pid, for a caller proving real
    /// OS-level process-tree evidence (e.g. a process-group descendant
    /// scan). `None` once the process has already been reaped (after
    /// [`Self::shutdown`]) or if this session never had a managed process
    /// to begin with. Test/observability use, mirroring [`Self::lease_state`];
    /// production control flow never branches on this.
    #[must_use]
    pub async fn process_pid(&self) -> Option<u32> {
        self.process
            .lock()
            .await
            .as_ref()
            .and_then(wht_corulix_tooling::ManagedProcess::pid)
    }

    /// Reads `absolute_path` (already confined by the caller against
    /// `self.workspace_root` via `wht_corulix_workspace`) and, if not
    /// already open, sends `textDocument/didOpen`. Returns the file's text
    /// (needed by callers for position/range translation) and its `file://`
    /// URI either way.
    pub async fn ensure_open(
        &self,
        absolute_path: &Path,
    ) -> Result<(ls_types::Uri, String), LspError> {
        // Normalized against Windows's `\\?\` extended-length prefix before
        // comparison -- see `crate::operations::relative_to_workspace_root`'s
        // own doc comment for the exact real defect this guards against
        // (P17-W-R4-C3). A no-op on Unix and on any caller-supplied path
        // that already matches `canonical_path()`'s own representation.
        let normalized_root =
            crate::uri::strip_windows_verbatim_prefix(self.workspace_root.canonical_path());
        let normalized_absolute = crate::uri::strip_windows_verbatim_prefix(absolute_path);
        let relative = normalized_absolute
            .strip_prefix(&normalized_root)
            .map_err(|_| LspError::ResultOutsideWorkspace)?
            .to_path_buf();
        let bytes = wht_corulix_workspace::confined_read(
            self.workspace_root.clone(),
            relative,
            crate::operations::MAX_LOCATION_SOURCE_BYTES,
        )
        .await
        .map_err(|_| LspError::SourceUnavailable)?;
        let text = String::from_utf8(bytes).map_err(|_| LspError::UnrepresentableResult)?;
        let file_uri =
            uri::path_to_file_uri(absolute_path).ok_or(LspError::UnrepresentableResult)?;
        let uri_key = file_uri.as_str().to_string();

        let mut open_documents = self.open_documents.lock().await;
        if !open_documents.contains(&uri_key) {
            let params = ls_types::DidOpenTextDocumentParams {
                text_document: ls_types::TextDocumentItem {
                    uri: file_uri.clone(),
                    language_id: self.lsp_language_id.to_string(),
                    version: 1,
                    text: text.clone(),
                },
            };
            let params_value =
                serde_json::to_value(params).map_err(|_| LspError::UnrepresentableResult)?;
            self.transport
                .notify("textDocument/didOpen", params_value)
                .await?;
            open_documents.insert(uri_key);
            drop(open_documents);
            if self.readiness_strategy == ReadinessStrategy::FirstPullDiagnosticsResponse {
                self.pull_diagnostics_for_readiness(&file_uri).await;
            }
        }
        Ok((file_uri, text))
    }

    /// Actively issues one `textDocument/diagnostic` pull request for
    /// `file_uri` and, on receiving any real response, populates the
    /// diagnostics store (the same store/`Notify`
    /// [`Self::wait_for_diagnostics`] reads, so a caller never needs to know
    /// whether a given provider pushed or was pulled) and records
    /// [`Readiness::Ready`] -- see [`ReadinessStrategy::FirstPullDiagnosticsResponse`]'s
    /// own doc comment for why this active step exists. Best-effort: a
    /// failed/timed-out pull leaves readiness at its current state (never
    /// falsely marked ready), so [`Self::wait_until_ready`]'s own timeout
    /// surfaces the failure honestly rather than this function retrying or
    /// panicking.
    async fn pull_diagnostics_for_readiness(&self, file_uri: &ls_types::Uri) {
        let cancellation = CancellationToken::new();
        let params = serde_json::json!({ "textDocument": { "uri": file_uri.as_str() } });
        let Ok(response) = self
            .transport
            .request(
                "textDocument/diagnostic",
                params,
                DEFAULT_REQUEST_TIMEOUT,
                &cancellation,
            )
            .await
        else {
            return;
        };
        let items = response
            .get("items")
            .cloned()
            .unwrap_or(serde_json::Value::Array(Vec::new()));
        let Ok(diagnostics) = serde_json::from_value::<Vec<ls_types::Diagnostic>>(items) else {
            return;
        };
        self.diagnostics
            .lock()
            .await
            .insert(file_uri.as_str().to_string(), diagnostics);
        self.diagnostics_published.notify_waiters();
        self.readiness_sink.record(Readiness::Ready);
    }

    /// Closes a previously-opened document. Idempotent: closing a document
    /// this session never opened is a no-op, never an error.
    pub async fn close(&self, file_uri: &ls_types::Uri) -> Result<(), LspError> {
        let uri_key = file_uri.as_str().to_string();
        let mut open_documents = self.open_documents.lock().await;
        if !open_documents.remove(&uri_key) {
            return Ok(());
        }
        let params = ls_types::DidCloseTextDocumentParams {
            text_document: ls_types::TextDocumentIdentifier {
                uri: file_uri.clone(),
            },
        };
        let params_value =
            serde_json::to_value(params).map_err(|_| LspError::UnrepresentableResult)?;
        self.transport
            .notify("textDocument/didClose", params_value)
            .await?;
        Ok(())
    }

    /// The most recently published diagnostics for one `file://` URI, or an
    /// empty vec if none have been published yet -- callers combine this
    /// with [`Self::readiness`] to distinguish "not ready" from "proven
    /// empty" (see `crate::dto::DiagnosticsResult`).
    pub async fn diagnostics_for(&self, file_uri: &ls_types::Uri) -> Vec<ls_types::Diagnostic> {
        self.diagnostics
            .lock()
            .await
            .get(file_uri.as_str())
            .cloned()
            .unwrap_or_default()
    }

    /// Awaits the *first* `textDocument/publishDiagnostics` this session has
    /// received for `file_uri`, bounded by `timeout` -- never a fixed sleep.
    /// Diagnostics are pushed asynchronously by every provider this crate
    /// supports (proven for both rust-analyzer and gopls during this
    /// phase's capability probe), so a just-opened document's diagnostics
    /// may not have arrived yet; this waits for the pump's
    /// [`Notify::notify_waiters`] signal rather than polling on a clock.
    /// Returns whatever is present once the URI's key exists in the
    /// diagnostics store (possibly empty, if the server genuinely reported
    /// zero diagnostics), or an empty vec if `timeout` elapses first --
    /// callers still gate on [`Self::readiness`] before treating that as an
    /// authoritative zero.
    pub async fn wait_for_diagnostics(
        &self,
        file_uri: &ls_types::Uri,
        timeout: Duration,
    ) -> Vec<ls_types::Diagnostic> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Register as a waiter *before* checking the map: `Notify`
            // only wakes waiters that already existed at the moment
            // `notify_waiters` was called, so constructing this future
            // after the check would risk missing a notification that
            // lands in between (a classic check-then-wait race).
            let notified = self.diagnostics_published.notified();
            if let Some(diagnostics) = self.diagnostics.lock().await.get(file_uri.as_str()) {
                return diagnostics.clone();
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Vec::new();
            }
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep(remaining) => { return Vec::new(); }
            }
        }
    }

    /// Canonical shutdown lifecycle: `shutdown` request, `exit`
    /// notification, a bounded graceful-exit window, then whole-process-
    /// tree termination if the process has not exited on its own.
    /// Idempotent-safe: calling this more than once (or after the process
    /// already died) never panics or hangs.
    pub async fn shutdown(&self, cancellation: &CancellationToken) {
        stop_managed_process(&self.transport, &self.process, cancellation).await;

        self.transport.shutdown().await;
        if let Some(task) = self.pump_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        // The lease-stop-race task's only job was to observe an *external*
        // stop request and perform exactly the sequence this method just
        // ran itself; whichever of the two actually wins the
        // `process_slot.take()` race performs the real work; the loser's
        // `take()` sees `None` and no-ops. Abort it here regardless of
        // which happened, so an explicit `shutdown()` call never leaves
        // that task waiting forever on a stop signal nobody will send.
        if let Some(task) = self.lease_stop_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        // A self-initiated shutdown (not triggered by an external
        // `request_stop_for_component`) never ran through
        // `wait_for_stop_request`'s `Stopping` transition -- go straight to
        // `Stopped` here so the lease reflects reality regardless of which
        // path stopped the process (`STALE_LEASE_RECONCILIATION` does not
        // depend on this -- it is independent process-identity
        // verification -- but a lease that still claimed `Active` forever
        // after a normal, successful shutdown would be a needlessly
        // misleading observable).
        if let Some(waiter) = &self.lease_waiter {
            waiter.acknowledge_stopped();
        }
    }
}

/// The `shutdown` request / `exit` notification / bounded graceful-wait /
/// forced-terminate sequence, factored out so both [`LspSession::shutdown`]
/// (an explicit, caller-initiated stop) and [`spawn_lease_stop_task`]'s
/// background task (an *external* stop request via a
/// `wht_corulix_tooling::provisioning::lease::LeaseWaiter`) share one
/// implementation rather than two independently-maintained copies.
/// `process_slot.take()` makes the two paths mutually exclusive and
/// idempotent-safe: whichever reaches this first performs the real work,
/// the other's `take()` finds `None` and does nothing.
async fn stop_managed_process(
    transport: &Transport,
    process_slot: &Mutex<Option<wht_corulix_tooling::ManagedProcess>>,
    cancellation: &CancellationToken,
) {
    let _ = transport
        .request(
            "shutdown",
            serde_json::Value::Null,
            DEFAULT_REQUEST_TIMEOUT,
            cancellation,
        )
        .await;
    let _ = transport.notify("exit", serde_json::Value::Null).await;

    let mut process_guard = process_slot.lock().await;
    if let Some(mut process) = process_guard.take() {
        let exit = process.wait_for_exit(GRACEFUL_EXIT_WINDOW).await;
        if exit == wht_corulix_tooling::ManagedProcessExit::StillRunning {
            let _ = process.terminate().await;
        }
    }
}

/// Spawns the background task that lets an *external*
/// `wht_corulix_tooling::provisioning::uninstall::uninstall` call stop this
/// exact session even though nothing else is currently driving it --
/// without this, `ManagedExecutionLease` registration alone would let
/// uninstall *discover* an active session but never actually stop one that
/// is sitting idle between requests. Races
/// `LeaseWaiter::wait_for_stop_request` against nothing else (it has no
/// other work) and, once observed, runs the exact same
/// [`stop_managed_process`] sequence [`LspSession::shutdown`] uses, then
/// acknowledges. A fresh [`CancellationToken`] is used for the `shutdown`
/// request here since this task has no caller-supplied one of its own --
/// the bounded graceful-exit window plus forced-terminate fallback inside
/// [`stop_managed_process`] is what actually bounds this, not the
/// cancellation token.
fn spawn_lease_stop_task(
    transport: Arc<Transport>,
    process: Arc<Mutex<Option<wht_corulix_tooling::ManagedProcess>>>,
    waiter: wht_corulix_tooling::provisioning::lease::LeaseWaiter,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        waiter.wait_for_stop_request().await;
        let cancellation = CancellationToken::new();
        stop_managed_process(&transport, &process, &cancellation).await;
        waiter.acknowledge_stopped();
    })
}

/// Drains the transport's notification channel for the session's entire
/// lifetime, routing `experimental/serverStatus` into readiness (for
/// [`ReadinessStrategy::ServerStatusNotification`] providers) and
/// `textDocument/publishDiagnostics` into both the diagnostics store and
/// readiness (for [`ReadinessStrategy::FirstDiagnosticsPublished`]
/// providers, which have no vendor readiness extension -- see
/// `crate::profile::LspProviderProfile::gopls`). Always joined by
/// [`LspSession::shutdown`] -- never a detached task.
fn spawn_notification_pump(
    transport: Arc<Transport>,
    readiness_sink: ReadinessSink,
    diagnostics: Arc<Mutex<HashMap<String, Vec<ls_types::Diagnostic>>>>,
    diagnostics_published: Arc<Notify>,
    readiness_strategy: ReadinessStrategy,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(notification) = transport.next_notification().await {
            if readiness_strategy == ReadinessStrategy::ServerStatusNotification
                && notification.method == readiness::SERVER_STATUS_METHOD
            {
                if let Some(state) = readiness::interpret_server_status(&notification.params) {
                    readiness_sink.record(state);
                }
                continue;
            }
            if notification.method == "textDocument/publishDiagnostics"
                && let Ok(params) = serde_json::from_value::<ls_types::PublishDiagnosticsParams>(
                    notification.params,
                )
            {
                diagnostics
                    .lock()
                    .await
                    .insert(params.uri.as_str().to_string(), params.diagnostics);
                diagnostics_published.notify_waiters();
                if readiness_strategy == ReadinessStrategy::FirstDiagnosticsPublished {
                    readiness_sink.record(readiness::Readiness::Ready);
                }
            }
        }
    })
}

// Every test in this module spawns a real child process via
// `wht_corulix_process_fixture` and asserts Unix-specific fail-closed
// behavior (symlink/ancestor root replacement); pre-existing gap (not
// introduced by M09-P9) discovered only because this phase was the first
// to run `cargo clippy --workspace --all-targets --target
// x86_64-pc-windows-gnu -D warnings` in this exact strict form. Gated
// per-item (`#[cfg(unix)]` on the helpers below, matching every test
// function further down) rather than at the module level: the
// architecture verifier's own test-region exemption
// (`wht_verify_architecture.py`) recognizes the literal marker
// `#[cfg(test)]` only -- `#[cfg(all(test, unix))]` would silently defeat
// that exemption and misclassify this test-only module as production
// source.
#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;
    #[cfg(unix)]
    use crate::fixture_support;
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use wht_corulix_tooling::EnvironmentPolicy;

    #[cfg(unix)]
    fn temp_dir(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("corulix-session-lifecycle-{label}-{stamp}"));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// A [`ResolvedLaunch`] pointing at the shared
    /// `wht_corulix_process_fixture` binary in `write-pid-file` mode: it
    /// writes its own real OS pid to `pid_file` immediately, then sleeps
    /// (producing no stdout at all -- no LSP framing ever arrives) for
    /// `sleep_ms`. This stands in for a language-server process that is
    /// genuinely running but will never complete the `initialize` handshake
    /// -- the exact real-world shape confirmed against managed rust-analyzer
    /// on a real host (`FAILED_LSP_STARTUP_ROOT_CAUSE`'s own evidence).
    #[cfg(unix)]
    fn silent_fixture_launch(pid_file: &Path, sleep_ms: u64) -> crate::profile::ResolvedLaunch {
        let executable = fixture_support::fixture_binary_path()
            .unwrap_or_else(|error| unreachable!("fixture must resolve: {error}"));
        crate::profile::ResolvedLaunch {
            executable,
            arguments: vec![
                "write-pid-file".to_string(),
                pid_file.to_string_lossy().into_owned(),
                sleep_ms.to_string(),
            ],
            environment: EnvironmentPolicy::empty(),
            managed_lease: None,
            extra_initialization_options: None,
        }
    }

    /// Polls (bounded) until `pid_file` exists and contains a parseable
    /// pid, or panics-via-`unreachable!` if it never appears -- the fixture
    /// writes it essentially immediately, so a generous bound is purely
    /// defensive against CI scheduling jitter, never expected to actually
    /// wait long.
    #[cfg(unix)]
    async fn read_pid_file(pid_file: &Path) -> u32 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(contents) = std::fs::read_to_string(pid_file)
                && let Ok(pid) = contents.trim().parse::<u32>()
            {
                return pid;
            }
            if tokio::time::Instant::now() >= deadline {
                unreachable!("fixture never wrote its pid file at {pid_file:?}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Real, direct liveness check via `/proc` -- never inferred from
    /// `LspSession`'s own bookkeeping, since that is exactly what this test
    /// is trying to independently verify.
    #[cfg(unix)]
    fn process_is_alive(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    /// `FAILED_LSP_STARTUP_LEAK_COUNT=0` proof: a session whose `initialize`
    /// handshake never completes (here, via caller cancellation racing the
    /// same `tokio::select!` a genuine 30s timeout would -- see
    /// `Transport::request`'s own implementation -- so this test exercises
    /// the identical cleanup code path a real timeout hits, in milliseconds
    /// rather than 30 real seconds) must not leave its spawned OS process
    /// running. Reproduces, in isolation, the real defect found against a
    /// real managed rust-analyzer on a real host (multiple orphaned
    /// processes accumulated from repeated failed attempts before this
    /// fix).
    #[cfg(unix)]
    #[tokio::test]
    async fn spawn_terminates_the_child_when_initialize_never_completes() {
        let dir = temp_dir("initialize-cancelled");
        let pid_file = dir.join("pid");
        let launch = silent_fixture_launch(&pid_file, 60_000);
        // Any real profile works here: `spawn()` never consults
        // `managed_component`/`auxiliary_tools`/etc. (only `resolve_launch`
        // does, which this test bypasses by building `ResolvedLaunch`
        // directly), and `gopls()` is the simplest already-audited,
        // unmanaged real constructor -- reused rather than hand-building a
        // struct literal here (Architecture Rule P: every `LspProviderProfile`
        // must come from `profile.rs`'s own named constructors).
        let profile = LspProviderProfile::gopls();
        let root = WorkspaceRoot::open(&dir).unwrap_or_else(|error| {
            unreachable!("temp dir must open as a workspace root: {error:?}")
        });
        let cancellation = CancellationToken::new();

        let cancel_after_a_moment = {
            let cancellation = cancellation.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                cancellation.cancel();
            })
        };
        // Samples the pid and its liveness concurrently with `spawn()`
        // itself, *before* cancellation fires -- `spawn()`'s own cleanup
        // (this test's whole point) runs synchronously as part of its
        // return path, so sampling *after* `.await` resolves could already
        // observe a terminated process and never prove it was genuinely
        // alive to begin with.
        let sanity_check = {
            let pid_file = pid_file.clone();
            tokio::spawn(async move {
                let pid = read_pid_file(&pid_file).await;
                let alive_at_start = process_is_alive(pid);
                (pid, alive_at_start)
            })
        };

        let result =
            LspSession::spawn(launch, &profile, root, WorkspaceRootId(0), &cancellation).await;
        assert!(
            result.is_err(),
            "initialize can never complete against a process that writes no LSP frames at all"
        );
        // M09-P8 negative control: this scenario never touches the
        // workspace root's pathname, so the new pre-`initialize` identity
        // gate must not spuriously fire -- the real failure here is the
        // cancelled/timed-out `initialize` request itself, never a
        // fabricated root-identity mismatch.
        assert!(
            !matches!(
                result,
                Err(LspError::RootIdentityMismatch) | Err(LspError::SessionInvalidated)
            ),
            "an unmodified root must never trigger the identity gate: {:?}",
            result.err()
        );
        let _ = cancel_after_a_moment.await;

        let (pid, alive_at_start) = sanity_check
            .await
            .unwrap_or_else(|error| unreachable!("sanity-check task must not panic: {error}"));
        assert!(
            alive_at_start,
            "sanity check: the fixture process must have actually started"
        );

        // The real cleanup runs asynchronously as part of `shutdown()`'s own
        // graceful-then-forceful sequence; give it a bounded window rather
        // than asserting instantaneously.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while process_is_alive(pid) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !process_is_alive(pid),
            "FAILED_LSP_STARTUP_UNREAPED_PROCESS_COUNT must be 0: pid {pid} is still alive after \
             spawn() failed"
        );
    }

    // -----------------------------------------------------------------
    // M09-P8: root-swap reproduction against the real public
    // `LspSession::spawn` -> `initialize_handshake` ->
    // `ensure_root_identity_or_invalidate` call graph. Each test opens a
    // real `WorkspaceRoot` (pinning a real fd), performs one swap shape at
    // that root's own canonical pathname, then spawns -- proving both that
    // P7's fd-pinned cwd binding still spawns the child against the
    // ORIGINAL object (unaffected by the swap) and that P8's new
    // pre-`initialize` gate independently detects the pathname-level
    // divergence and fails closed before any `initialize` request is ever
    // sent, terminating the already-spawned provider.
    // -----------------------------------------------------------------

    /// Shared shape for the three root-swap tests below: spawns against a
    /// workspace root that has just been swapped at the OS level, and
    /// asserts the exact fail-closed contract (Section 14/18/20-22).
    #[cfg(unix)]
    async fn assert_spawn_fails_closed_on_swapped_root(dir: &Path, root: WorkspaceRoot) {
        let pid_file = dir.join("pid");
        let launch = silent_fixture_launch(&pid_file, 60_000);
        let profile = LspProviderProfile::gopls();
        let cancellation = CancellationToken::new();

        let sanity_check = {
            let pid_file = pid_file.clone();
            tokio::spawn(async move {
                let pid = read_pid_file(&pid_file).await;
                (pid, process_is_alive(pid))
            })
        };

        let result =
            LspSession::spawn(launch, &profile, root, WorkspaceRootId(0), &cancellation).await;
        assert!(
            matches!(result, Err(LspError::RootIdentityMismatch)),
            "expected RootIdentityMismatch, got {:?}",
            result.err()
        );

        let (pid, alive_at_start) = sanity_check
            .await
            .unwrap_or_else(|error| unreachable!("sanity-check task must not panic: {error}"));
        assert!(
            alive_at_start,
            "sanity check: the fixture process must have actually started (proves P7's \
             fd-pinned cwd binding still spawned it against the original object)"
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while process_is_alive(pid) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !process_is_alive(pid),
            "the provider must be terminated/reaped after an observed root-identity mismatch"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spawn_fails_closed_on_normal_directory_root_replacement_before_initialize() {
        let dir = temp_dir("root-swap-normal");
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-session-lifecycle-root-swap-normal-moved-{}",
            std::process::id()
        ));
        let root = WorkspaceRoot::open(&dir).unwrap_or_else(|error| {
            unreachable!("temp dir must open as a workspace root: {error:?}")
        });

        std::fs::rename(&dir, &moved_away)
            .unwrap_or_else(|error| unreachable!("must move the workspace dir aside: {error}"));
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| {
            unreachable!("must recreate an ordinary directory at the same path: {error}")
        });

        assert_spawn_fails_closed_on_swapped_root(&dir, root).await;

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&moved_away);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spawn_fails_closed_on_symlink_root_replacement_before_initialize() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("root-swap-symlink");
        let outside = temp_dir("root-swap-symlink-outside");
        let root = WorkspaceRoot::open(&dir).unwrap_or_else(|error| {
            unreachable!("temp dir must open as a workspace root: {error:?}")
        });

        std::fs::remove_dir_all(&dir)
            .unwrap_or_else(|error| unreachable!("must remove the original directory: {error}"));
        symlink(&outside, &dir).unwrap_or_else(|error| {
            unreachable!("must symlink the workspace path to an unrelated directory: {error}")
        });

        assert_spawn_fails_closed_on_swapped_root(&dir, root).await;

        let _ = std::fs::remove_file(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spawn_fails_closed_on_ancestor_root_replacement_before_initialize() {
        let parent = temp_dir("root-swap-ancestor-parent");
        let child = parent.join("workspace_root");
        let _ = std::fs::create_dir_all(&child);
        let root = WorkspaceRoot::open(&child).unwrap_or_else(|error| {
            unreachable!("temp dir must open as a workspace root: {error:?}")
        });

        let moved_away = std::env::temp_dir().join(format!(
            "corulix-session-lifecycle-root-swap-ancestor-moved-{}",
            std::process::id()
        ));
        std::fs::rename(&parent, &moved_away)
            .unwrap_or_else(|error| unreachable!("must move the ancestor aside: {error}"));
        std::fs::create_dir_all(&child).unwrap_or_else(|error| {
            unreachable!("must recreate an identically-named child under a fresh ancestor: {error}")
        });

        assert_spawn_fails_closed_on_swapped_root(&child, root).await;

        let _ = std::fs::remove_dir_all(&parent);
        let _ = std::fs::remove_dir_all(&moved_away);
    }
}
