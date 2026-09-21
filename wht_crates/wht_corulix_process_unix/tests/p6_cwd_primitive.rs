// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! M09-P6 permanent tests for the raw `bind_cwd` primitive itself --
//! independent of `wht_corulix_workspace::WorkspaceRoot` (which has its
//! own, separate P6 integration suite covering the root-object-identity/
//! swap/clone/drop scenarios specific to that type). These tests exercise
//! exactly the primitive this crate exists to provide: given ANY owned,
//! open directory fd, `bind_cwd` makes a spawned child's cwd that exact
//! object, with the fd-lifetime/CLOEXEC/failure-mode guarantees documented
//! in `wht_corulix_process_unix::bind_cwd`'s own doc comment.
//!
//! Run as a separate integration-test binary (its own OS process) so its
//! own `/proc/self/fd`-based assertions are never perturbed by whatever
//! else a different, unrelated test binary's threads are doing
//! concurrently -- but that alone is not sufficient (M09-P6 Section 34's
//! own reliability requirement): Rust's default test harness still runs
//! every `#[test]` fn in THIS file on its own thread, in parallel, within
//! this one process, and several of these tests spawn real child
//! processes with piped stdio -- exactly the kind of transient fd another,
//! concurrently-running test in this same binary could observe. Every
//! test below therefore acquires [`FD_TEST_GUARD`] for its entire body,
//! serializing this file's own tests against each other (never against
//! any other test binary) so an `/proc/self/fd` sample here is never
//! perturbed by a sibling test's own in-flight spawn.
//!
//! M09-P9 fix: this file exercises `wht_corulix_process_unix::bind_cwd` and
//! `rustix::fs`/`std::os::unix::fs::MetadataExt`, all Unix-only -- it was
//! missing its own `#![cfg(unix)]` guard, so `cargo test`/`cargo check
//! --tests` for a Windows target attempted (and failed) to compile it.
//! Pre-existing gap, unrelated to P9's own Windows implementation;
//! unrelated to any Unix behavior change (still compiles/runs identically
//! on Unix).

#![cfg(unix)]

mod support;

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_process_unix::bind_cwd;

/// M09-P6 Section 34: serializes every test in this file against every
/// other test in this file (never against other test binaries), so
/// `/proc/self/fd`-based assertions are never perturbed by a sibling
/// test's own in-flight child-process spawn running concurrently in this
/// same process.
static FD_TEST_GUARD: Mutex<()> = Mutex::new(());

fn fd_test_guard() -> std::sync::MutexGuard<'static, ()> {
    FD_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn temp_dir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!(
        "corulix-p6-primitive-{label}-{}-{stamp}-{unique}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&root);
    root
}

fn open_dir_fd(path: &Path) -> Result<Arc<OwnedFd>, String> {
    let owned = rustix::fs::open(
        path,
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("open({path:?}) failed: {error}"))?;
    Ok(Arc::new(owned))
}

fn identity_of(path: &Path) -> Result<(u64, u64), String> {
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("metadata({path:?}) failed: {error}"))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn oracle_command() -> Result<Command, String> {
    let exe = support::fixture_binary_path()?;
    let mut command = Command::new(exe);
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    Ok(command)
}

fn run_and_parse(mut command: Command) -> Result<serde_json::Value, String> {
    let output = command
        .output()
        .map_err(|error| format!("spawn/wait failed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "child exited non-zero: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("stdout was not valid UTF-8: {error}"))?;
    serde_json::from_str(text.trim()).map_err(|error| format!("invalid JSON {text:?}: {error}"))
}

fn oracle_identity(mut command: Command) -> Result<(u64, u64), String> {
    command.arg("print-cwd-identity");
    let payload = run_and_parse(command)?;
    let device = payload["device"].as_u64().ok_or("missing device")?;
    let inode = payload["inode"].as_u64().ok_or("missing inode")?;
    Ok((device, inode))
}

/// One entry of the child's own post-exec fd table, resolved to the
/// (device, inode) identity of whatever object that fd actually refers to
/// -- never just its raw number. This is what lets a caller prove a
/// SPECIFIC filesystem object is absent from the child, not merely that a
/// total count didn't change (a count alone cannot distinguish "the bound
/// fd leaked" from "this host naturally opens one more baseline fd than
/// another host does").
#[derive(Debug, Clone, Copy)]
struct FdTarget {
    fd: i64,
    device: u64,
    inode: u64,
}

fn oracle_fd_targets(mut command: Command) -> Result<Vec<FdTarget>, String> {
    command.arg("print-fd-targets");
    let payload = run_and_parse(command)?;
    let entries = payload["targets"]
        .as_array()
        .ok_or("missing targets array")?;
    entries
        .iter()
        .map(|entry| {
            let fd = entry["fd"].as_i64().ok_or("missing fd")?;
            let device = entry["device"].as_u64().ok_or("missing device")?;
            let inode = entry["inode"].as_u64().ok_or("missing inode")?;
            Ok(FdTarget { fd, device, inode })
        })
        .collect()
}

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(0)
}

// -- basic binding -------------------------------------------------------

#[test]
fn binds_child_cwd_to_pinned_directory_object() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("basic");
    let fd = open_dir_fd(&dir)?;
    let expected = identity_of(&dir)?;

    let mut command = oracle_command()?;
    bind_cwd(&mut command, Arc::clone(&fd));
    let actual = oracle_identity(command)?;

    assert_eq!(
        actual, expected,
        "child cwd must be the pinned directory object"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// -- fd ownership / lifetime (Section 8, 16) -----------------------------

#[test]
fn dropping_original_arc_reference_before_spawn_does_not_invalidate_binding() -> Result<(), String>
{
    let _guard = fd_test_guard();
    let dir = temp_dir("drop-before-spawn");
    let expected = identity_of(&dir)?;

    let mut command = oracle_command()?;
    {
        // The only Arc clone this scope creates is moved into `bind_cwd`;
        // `fd` itself is dropped at the end of this block, BEFORE
        // `command` is ever spawned below -- proving the Command's own
        // captured clone, not `fd`'s continued existence, is what keeps
        // the fd open.
        let fd = open_dir_fd(&dir)?;
        bind_cwd(&mut command, Arc::clone(&fd));
    }

    let actual = oracle_identity(command)?;
    assert_eq!(
        actual, expected,
        "the Command's own captured Arc clone must keep the fd open independent of the \
         original owner's lifetime"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// -- fchdir failure fails spawn closed (Section 26, 27) ------------------

#[test]
fn fchdir_on_a_non_directory_fd_fails_spawn_closed() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("fchdir-failure");
    let regular_file = dir.join("not-a-directory.txt");
    std::fs::write(&regular_file, b"x").map_err(|error| error.to_string())?;

    // A regular-file fd, never sourced from any real WorkspaceRoot -- this
    // does not corrupt any production pinned-root state, it is simply an
    // fd that `fchdir` is documented to reject with `ENOTDIR`.
    let owned = rustix::fs::open(
        &regular_file,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("open failed: {error}"))?;
    let fd: Arc<OwnedFd> = Arc::new(owned);

    let mut command = oracle_command()?;
    command.arg("print-cwd-identity");
    bind_cwd(&mut command, fd);

    let result = command.spawn();
    assert!(
        result.is_err(),
        "spawn must fail closed when the bound fd cannot be fchdir'd to, not silently fall \
         back to the inherited parent cwd or any current_dir pathname"
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// -- CLOEXEC (Section 10, 25) ---------------------------------------------

#[test]
fn bound_fd_is_cloexec_and_never_reaches_the_child_after_exec() -> Result<(), String> {
    let _guard = fd_test_guard();

    // BASELINE_CAPTURE_POINT -- measured before the target directory (the
    // resource whose leak this test proves) is even created, let alone
    // opened or bound, so this baseline cannot itself already reflect
    // that resource's presence or absence. It is a live measurement of
    // whatever this specific host/container naturally opens by the time
    // an identical, entirely unbound oracle child's `main` runs -- never
    // a hardcoded constant, since that count is expected to (and has been
    // observed to) differ between a local machine and a hosted CI runner
    // for reasons unrelated to `bind_cwd`.
    let self_fds_before = open_fd_count();
    let baseline_targets = oracle_fd_targets(oracle_command()?)?;

    // TARGET_FD_CREATED_POINT
    let dir = temp_dir("cloexec");
    let fd = open_dir_fd(&dir)?;
    let target_identity = identity_of(&dir)?;

    // Structural proof: the fd this test (and, in production,
    // `WorkspaceRoot`) opens carries `O_CLOEXEC` from construction.
    let flags = rustix::io::fcntl_getfd(fd.as_fd())
        .map_err(|error| format!("fcntl_getfd failed: {error}"))?;
    assert!(
        flags.contains(rustix::io::FdFlags::CLOEXEC),
        "the fd bind_cwd is given must already carry O_CLOEXEC"
    );

    // CHILD_EXEC_POINT -- bind, then spawn/exec through the real,
    // production `bind_cwd` path.
    let mut command = oracle_command()?;
    bind_cwd(&mut command, Arc::clone(&fd));
    let bound_targets = oracle_fd_targets(command)?;

    // Runtime proof, primary: the SPECIFIC bound directory -- identified
    // by its (device, inode) object identity, never by an fd number or a
    // raw count, since either of those can coincide by chance -- must not
    // appear anywhere in the child's own post-exec fd table. This directly
    // proves the property this test is named for; a total-count
    // comparison alone could not distinguish "the bound fd leaked" from
    // "this host's own baseline naturally differs from another host's".
    let leaked: Vec<i64> = bound_targets
        .iter()
        .filter(|target| (target.device, target.inode) == target_identity)
        .map(|target| target.fd)
        .collect();
    assert!(
        leaked.is_empty(),
        "the bound directory (device={}, inode={}) was found open in the child's own fd \
         table after exec, at fd(s) {leaked:?} -- it must not have survived exec",
        target_identity.0,
        target_identity.1,
    );

    // Runtime proof, secondary: the bound run must never carry MORE open
    // descriptors than the live baseline measured above -- catching an
    // unexpected leak of any OTHER descriptor the binding path might
    // introduce, while remaining tolerant of whatever legitimate baseline
    // fd count this specific host/container happens to have (never a
    // hardcoded absolute ceiling that a differently-provisioned runner
    // could legitimately exceed for reasons that have nothing to do with
    // this crate).
    assert!(
        bound_targets.len() <= baseline_targets.len(),
        "child's own post-exec fd count was {} with the bound fd vs a baseline of {} \
         measured before the target directory even existed -- an unexpected descriptor \
         survived exec",
        bound_targets.len(),
        baseline_targets.len(),
    );

    // TARGET_FD_CLOSED_POINT -- the only owning reference besides `fd`
    // itself was the one temporary `Arc` clone `bind_cwd` consumed for the
    // now-exited, already-reaped child above; dropping `fd` here closes
    // the underlying descriptor in THIS process.
    drop(fd);
    let _ = std::fs::remove_dir_all(&dir);

    // POST_CLEANUP_MEASUREMENT_POINT -- proves cleanup leaves no
    // additional descriptor behind in this test's OWN process (dimension
    // F), independent of the two sibling tests below that cover this same
    // dimension across repeated bind/spawn cycles.
    let self_fds_after = open_fd_count();
    assert!(
        self_fds_after <= self_fds_before,
        "this test's own process fd count grew from {self_fds_before} to {self_fds_after} -- \
         possible leak in cleanup"
    );

    Ok(())
}

// -- baseline variance is measured live, never a hardcoded platform
// -- constant (Section 7/10 of the corrective mandate) --------------------

#[test]
fn bound_fd_leak_detection_tolerates_additional_benign_inherited_descriptors() -> Result<(), String>
{
    // Proves the assertion strategy above does not merely happen to work
    // for THIS host's current baseline: it must keep working when this
    // process itself is holding extra, ordinary (non-`CLOEXEC`) open
    // descriptors it did nothing wrong to have -- exactly the situation a
    // differently-provisioned CI runner or container is in versus a local
    // machine. A non-`CLOEXEC` fd this process holds is inherited across
    // `fork()` and, having no `CLOEXEC` flag, survives `exec()` into the
    // child too -- so it naturally inflates BOTH the baseline run and the
    // bound run by the same amount, and the delta-based assertion in
    // `bound_fd_is_cloexec_and_never_reaches_the_child_after_exec` above
    // must still hold under that inflation. This never touches production
    // `bind_cwd` behavior -- it only changes what this TEST's own process
    // happens to have open before invoking it.
    let _guard = fd_test_guard();

    // Simulate a host/container baseline with several extra ambient
    // descriptors already open, deliberately WITHOUT `O_CLOEXEC`, so they
    // behave exactly like inherited-but-unrelated fds a real differently-
    // provisioned runner might already hold.
    const EXTRA_BENIGN_FDS: usize = 4;
    let mut benign_guards: Vec<OwnedFd> = Vec::with_capacity(EXTRA_BENIGN_FDS);
    for _ in 0..EXTRA_BENIGN_FDS {
        // `std::fs::File::open` sets `O_CLOEXEC` by default on this
        // platform, which would make the opened fd close on exec just
        // like the object under test -- the opposite of what this
        // simulation needs. `rustix::fs::open` is used directly instead,
        // deliberately WITHOUT `OFlags::CLOEXEC`, so the resulting fd is
        // inherited across `fork()` AND survives `exec()`, exactly like a
        // real ambient descriptor a differently-provisioned runner might
        // already hold for reasons unrelated to this crate.
        let owned = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| format!("open(/dev/null) failed: {error}"))?;
        let raw = rustix::io::fcntl_getfd(owned.as_fd())
            .map_err(|error| format!("fcntl_getfd failed: {error}"))?;
        assert!(
            !raw.contains(rustix::io::FdFlags::CLOEXEC),
            "this benign fd must not carry CLOEXEC for this test's own inflation to be \
             representative of a real ambient, exec-surviving descriptor"
        );
        benign_guards.push(owned);
    }

    let dir = temp_dir("cloexec-benign-baseline");
    let fd = open_dir_fd(&dir)?;
    let target_identity = identity_of(&dir)?;

    let baseline_targets = oracle_fd_targets(oracle_command()?)?;
    assert!(
        baseline_targets.len() >= EXTRA_BENIGN_FDS,
        "the artificially inflated baseline ({}) must reflect at least the {EXTRA_BENIGN_FDS} \
         extra benign descriptors this process deliberately opened -- otherwise this test \
         proves nothing about baseline tolerance",
        baseline_targets.len(),
    );

    let mut command = oracle_command()?;
    bind_cwd(&mut command, Arc::clone(&fd));
    let bound_targets = oracle_fd_targets(command)?;

    let leaked: Vec<i64> = bound_targets
        .iter()
        .filter(|target| (target.device, target.inode) == target_identity)
        .map(|target| target.fd)
        .collect();
    assert!(
        leaked.is_empty(),
        "the bound directory leaked into the child even under an inflated baseline, at fd(s) \
         {leaked:?}"
    );
    assert!(
        bound_targets.len() <= baseline_targets.len(),
        "the delta-based assertion failed under an artificially inflated baseline of {} \
         (bound run had {}) -- it must tolerate legitimate ambient fd inflation, not just a \
         single machine's own default baseline",
        baseline_targets.len(),
        bound_targets.len(),
    );

    drop(benign_guards);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// -- multiple independent bindings (Section 22) ---------------------------

#[test]
fn multiple_commands_bound_from_the_same_fd_are_independent() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir_a = temp_dir("multi-a");
    let dir_b = temp_dir("multi-b");
    let fd_a = open_dir_fd(&dir_a)?;
    let fd_b = open_dir_fd(&dir_b)?;
    let expected_a = identity_of(&dir_a)?;
    let expected_b = identity_of(&dir_b)?;

    let mut command_a = oracle_command()?;
    bind_cwd(&mut command_a, Arc::clone(&fd_a));
    let mut command_b = oracle_command()?;
    bind_cwd(&mut command_b, Arc::clone(&fd_b));

    let actual_a = oracle_identity(command_a)?;
    let actual_b = oracle_identity(command_b)?;

    assert_eq!(actual_a, expected_a);
    assert_eq!(actual_b, expected_b);
    assert_ne!(
        actual_a, actual_b,
        "two independently-bound commands must not have collapsed onto the same object"
    );

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    Ok(())
}

// -- Command dropped without spawn (Section 23) ---------------------------

#[test]
fn unspawned_bound_command_leaks_no_fd() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("unspawned");
    let fd = open_dir_fd(&dir)?;
    let before = open_fd_count();

    for _ in 0..200 {
        let mut command = oracle_command()?;
        bind_cwd(&mut command, Arc::clone(&fd));
        drop(command);
    }

    let after = open_fd_count();
    assert!(
        after <= before + 4,
        "fd count grew from {before} to {after} after 200 bind+drop-without-spawn cycles -- \
         possible leak"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// -- repeated spawn fd retention (Section 24) ------------------------------

#[test]
fn repeated_bind_spawn_wait_cycles_do_not_retain_fds() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("repeated-spawn");
    let fd = open_dir_fd(&dir)?;
    let expected = identity_of(&dir)?;
    let before = open_fd_count();
    let mut peak = before;

    for _ in 0..50 {
        let mut command = oracle_command()?;
        bind_cwd(&mut command, Arc::clone(&fd));
        let actual = oracle_identity(command)?;
        assert_eq!(actual, expected);
        peak = peak.max(open_fd_count());
    }

    let after = open_fd_count();
    assert!(
        after <= before + 4,
        "fd count grew from {before} (peak {peak}) to {after} after 50 bind+spawn+wait cycles"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// -- pre-existing current_dir interaction (Section 28) ---------------------

#[test]
fn preexisting_current_dir_is_overridden_by_bound_cwd() -> Result<(), String> {
    let _guard = fd_test_guard();
    let bound_dir = temp_dir("preexisting-bound");
    let impostor_dir = temp_dir("preexisting-impostor");
    let expected = identity_of(&bound_dir)?;
    let impostor_identity = identity_of(&impostor_dir)?;
    assert_ne!(expected, impostor_identity, "test setup sanity check");

    let fd = open_dir_fd(&bound_dir)?;
    let mut command = oracle_command()?;
    command.current_dir(&impostor_dir);
    bind_cwd(&mut command, fd);

    let actual = oracle_identity(command)?;
    assert_eq!(
        actual, expected,
        "pre_exec's fchdir must win over an earlier Command::current_dir pathname, since \
         std runs current_dir's chdir before registered pre_exec closures"
    );

    let _ = std::fs::remove_dir_all(&bound_dir);
    let _ = std::fs::remove_dir_all(&impostor_dir);
    Ok(())
}
