// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Controlled JSON-RPC 2.0 / LSP `stdio` transport.
//!
//! This is the one and only place in the workspace that frames JSON-RPC
//! messages over a language server's stdio pipes (Architecture Rule L).
//! rust-analyzer's stdout is LSP protocol only -- never treated as a log
//! stream -- and its stderr is drained separately by
//! `wht_corulix_tooling::ManagedProcess` as a bounded diagnostic channel,
//! never parsed as protocol.
//!
//! Bounds enforced here: inbound/outbound frame size, pending-request
//! count, and the notification channel's capacity -- there is no unbounded
//! `HashMap`/queue growth reachable from a hostile or malfunctioning
//! server.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{ChildStdin, ChildStdout},
    sync::{Mutex, mpsc, oneshot},
};
use wht_corulix_core::CancellationToken;

/// Maximum number of requests this transport allows in flight
/// simultaneously. A caller that exceeds this is a deterministic,
/// typed error, never unbounded queue growth.
pub const MAX_PENDING_REQUESTS: usize = 64;

/// Maximum size of one inbound frame's body, after `Content-Length`
/// parsing. A server sending a larger frame is a protocol violation this
/// transport rejects, not a resource exhaustion vector.
pub const MAX_INBOUND_FRAME_BYTES: usize = 32 * 1024 * 1024;

/// Maximum size of one outbound frame's body this transport will send.
pub const MAX_OUTBOUND_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Capacity of the bounded channel that delivers server notifications
/// (`publishDiagnostics`, `experimental/serverStatus`, `$/progress`, ...)
/// to the caller. A full channel applies backpressure to the reader loop
/// rather than growing without bound.
pub const NOTIFICATION_CHANNEL_CAPACITY: usize = 256;

/// One inbound server notification, kept as a raw method/params pair --
/// this module has no opinion on LSP semantics, only on framing/
/// correlation. Higher layers (`crate::readiness`, `crate::operations`)
/// interpret specific methods.
#[derive(Debug, Clone)]
pub struct InboundNotification {
    pub method: String,
    pub params: serde_json::Value,
}

/// Why a transport operation failed. Never a bare string, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The transport's reader loop observed EOF or a fatal framing error;
    /// the connection is no longer usable.
    Closed,
    /// The pending-request table is at `MAX_PENDING_REQUESTS`.
    TooManyPendingRequests,
    /// A request's `timeout` elapsed before a response arrived.
    Timeout,
    /// The caller's [`CancellationToken`] was observed cancelled while
    /// awaiting a response; `$/cancelRequest` was sent best-effort.
    Cancelled,
    /// The server's response body could not be deserialized into the
    /// expected result type.
    MalformedResponse,
    /// The server returned a JSON-RPC error object.
    ServerError { code: i64, message: String },
    /// A frame exceeded `MAX_OUTBOUND_FRAME_BYTES` on send, or the
    /// message could not be serialized at all.
    MessageTooLarge,
}

struct PendingTable {
    entries: HashMap<i64, oneshot::Sender<Result<serde_json::Value, TransportError>>>,
}

/// A live JSON-RPC/LSP `stdio` transport over an already-spawned process's
/// stdin/stdout. Owns two structured background tasks (a reader loop and a
/// writer loop), both always joined by [`Self::shutdown`] -- neither is
/// ever a detached, fire-and-forget task.
pub struct Transport {
    next_id: AtomicI64,
    pending: Arc<Mutex<PendingTable>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    notifications_rx: Mutex<mpsc::Receiver<InboundNotification>>,
    reader_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    writer_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl Transport {
    /// Spawns the reader/writer background tasks over `stdin`/`stdout`.
    /// Every subsequent frame is Content-Length-framed JSON-RPC 2.0; no
    /// other framing is ever attempted.
    #[must_use]
    pub fn spawn(stdin: ChildStdin, stdout: ChildStdout) -> Self {
        let pending: Arc<Mutex<PendingTable>> = Arc::new(Mutex::new(PendingTable {
            entries: HashMap::new(),
        }));
        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(MAX_PENDING_REQUESTS * 2);
        let (notifications_tx, notifications_rx) =
            mpsc::channel::<InboundNotification>(NOTIFICATION_CHANNEL_CAPACITY);
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let writer_task = tokio::spawn(writer_loop(stdin, outbound_rx));
        let reader_task = tokio::spawn(reader_loop(
            stdout,
            Arc::clone(&pending),
            notifications_tx,
            Arc::clone(&closed),
            outbound_tx.clone(),
        ));

        Self {
            next_id: AtomicI64::new(1),
            pending,
            outbound_tx,
            notifications_rx: Mutex::new(notifications_rx),
            reader_task: Mutex::new(Some(reader_task)),
            writer_task: Mutex::new(Some(writer_task)),
            closed,
        }
    }

    /// Sends a JSON-RPC request and awaits its correlated response, bounded
    /// by `timeout` and `cancellation`. On timeout or cancellation, the
    /// pending entry is removed so a late server response cannot leak or
    /// be misattributed to a future request reusing the same id space (ids
    /// are never reused by this transport -- [`Self::next_id`] is
    /// monotonic for the transport's lifetime).
    pub async fn request(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<serde_json::Value, TransportError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(TransportError::Closed);
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            if pending.entries.len() >= MAX_PENDING_REQUESTS {
                return Err(TransportError::TooManyPendingRequests);
            }
            pending.entries.insert(id, tx);
        }

        let frame = encode_frame(&message_with_optional_params(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
            }),
            params,
        ))?;
        if self.outbound_tx.send(frame).await.is_err() {
            self.pending.lock().await.entries.remove(&id);
            return Err(TransportError::Closed);
        }

        tokio::select! {
            result = rx => {
                result.unwrap_or(Err(TransportError::Closed))
            }
            () = tokio::time::sleep(timeout) => {
                self.pending.lock().await.entries.remove(&id);
                Err(TransportError::Timeout)
            }
            () = await_cancellation(cancellation) => {
                self.pending.lock().await.entries.remove(&id);
                let _ = self
                    .notify(
                        "$/cancelRequest",
                        serde_json::json!({ "id": id }),
                    )
                    .await;
                Err(TransportError::Cancelled)
            }
        }
    }

    /// Sends a JSON-RPC notification (no id, no response expected).
    pub async fn notify(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<(), TransportError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(TransportError::Closed);
        }
        let frame = encode_frame(&message_with_optional_params(
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": method,
            }),
            params,
        ))?;
        self.outbound_tx
            .send(frame)
            .await
            .map_err(|_| TransportError::Closed)
    }

    /// Awaits the next inbound server notification (or server-to-client
    /// request, surfaced the same way after this transport auto-answers it
    /// with a null result so the server is never left stalled). Returns
    /// `None` once the transport is closed and no further notifications
    /// will ever arrive.
    pub async fn next_notification(&self) -> Option<InboundNotification> {
        self.notifications_rx.lock().await.recv().await
    }

    /// Joins the reader/writer tasks, leaving no detached background work.
    /// Does not itself terminate the underlying process -- that remains
    /// `wht_corulix_tooling::ManagedProcess`'s responsibility.
    pub async fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Fail every still-pending request deterministically rather than
        // leaving its future to hang forever.
        let mut pending = self.pending.lock().await;
        for (_, sender) in pending.entries.drain() {
            let _ = sender.send(Err(TransportError::Closed));
        }
        drop(pending);
        if let Some(task) = self.writer_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.reader_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn await_cancellation(token: &CancellationToken) {
    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    while !token.is_cancelled() {
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Merges `params` into `base` (an already-built `jsonrpc`/`id`/`method`
/// object) as a `"params"` key -- unless `params` is `Value::Null`, in
/// which case the key is omitted entirely rather than sent as a literal
/// `null`.
///
/// Strict JSON-RPC 2.0 treats `params` as optional -- omitted, not
/// present-as-`null` -- and at least one real provider proven during this
/// phase's research (TypeScript 7's native LSP, `serverInfo.name ==
/// "typescript-go"`) enforces this strictly: a `shutdown` request sent with
/// `"params": null` is rejected with `InvalidParams: expected no params,
/// got null`, confirmed against the real binary. Every existing provider
/// this crate spawns (rust-analyzer, gopls, `typescript-language-server`,
/// Pyright) already tolerates the literal-`null` form this function used to
/// send unconditionally, so omitting the key for `Value::Null` is strictly
/// more spec-compliant and does not change behavior for any of them.
fn message_with_optional_params(
    mut base: serde_json::Value,
    params: serde_json::Value,
) -> serde_json::Value {
    if let serde_json::Value::Object(map) = &mut base
        && params != serde_json::Value::Null
    {
        map.insert("params".to_string(), params);
    }
    base
}

fn encode_frame(value: &serde_json::Value) -> Result<Vec<u8>, TransportError> {
    let body = serde_json::to_vec(value).map_err(|_| TransportError::MessageTooLarge)?;
    if body.len() > MAX_OUTBOUND_FRAME_BYTES {
        return Err(TransportError::MessageTooLarge);
    }
    let mut framed = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    framed.extend_from_slice(&body);
    Ok(framed)
}

async fn writer_loop(mut stdin: ChildStdin, mut outbound_rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame) = outbound_rx.recv().await {
        if stdin.write_all(&frame).await.is_err() {
            return;
        }
        if stdin.flush().await.is_err() {
            return;
        }
    }
}

/// Reads one Content-Length-framed JSON-RPC message from `stdout`.
/// Rejects a missing/invalid/oversized `Content-Length` header as a
/// malformed frame rather than attempting a best-effort recovery; returns
/// `Ok(None)` cleanly on EOF (no more messages will ever arrive).
async fn read_frame(stdout: &mut ChildStdout) -> Result<Option<serde_json::Value>, TransportError> {
    let mut header_buffer = Vec::new();
    let mut content_length: Option<usize> = None;
    loop {
        let mut byte = [0_u8; 1];
        let read: usize = stdout.read_exact(&mut byte).await.unwrap_or(0);
        if read == 0 {
            if header_buffer.is_empty() && content_length.is_none() {
                return Ok(None);
            }
            return Err(TransportError::Closed);
        }
        header_buffer.push(byte[0]);
        if header_buffer.ends_with(b"\r\n") {
            let line = String::from_utf8_lossy(&header_buffer).to_string();
            header_buffer.clear();
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':')
                && name.trim().eq_ignore_ascii_case("content-length")
            {
                let parsed: usize = value
                    .trim()
                    .parse()
                    .map_err(|_| TransportError::MalformedResponse)?;
                if parsed > MAX_INBOUND_FRAME_BYTES {
                    return Err(TransportError::MessageTooLarge);
                }
                content_length = Some(parsed);
            }
        }
    }
    let length = content_length.ok_or(TransportError::MalformedResponse)?;
    let mut body = vec![0_u8; length];
    stdout
        .read_exact(&mut body)
        .await
        .map_err(|_| TransportError::Closed)?;
    serde_json::from_slice(&body).map_err(|_| TransportError::MalformedResponse)
}

async fn reader_loop(
    mut stdout: ChildStdout,
    pending: Arc<Mutex<PendingTable>>,
    notifications_tx: mpsc::Sender<InboundNotification>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) {
    loop {
        let message = match read_frame(&mut stdout).await {
            Ok(Some(message)) => message,
            Ok(None) | Err(_) => break,
        };

        let has_id = message.get("id").is_some();
        let has_method = message.get("method").is_some();

        if has_method && has_id {
            // A server-to-client request. This transport does not
            // implement any specific server-to-client capability (no
            // apply-edit, no configuration, no message-action prompts) --
            // it answers every one with a null result purely so the
            // server is never left stalled waiting for a reply, exactly
            // as proven empirically against a real rust-analyzer process
            // during this phase's research gate.
            if let Some(id) = message.get("id").cloned() {
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": serde_json::Value::Null,
                });
                if let Ok(bytes) = serde_json::to_vec(&response) {
                    let framed = format!("Content-Length: {}\r\n\r\n", bytes.len()).into_bytes();
                    let mut framed = framed;
                    framed.extend_from_slice(&bytes);
                    let _ = outbound_tx.send(framed).await;
                }
            }
            continue;
        }

        if has_method {
            // A genuine notification.
            let method = message
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = message
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let _ = notifications_tx
                .send(InboundNotification { method, params })
                .await;
            continue;
        }

        // A response to one of our own requests.
        let Some(id) = message.get("id").and_then(serde_json::Value::as_i64) else {
            continue;
        };
        let sender = { pending.lock().await.entries.remove(&id) };
        let Some(sender) = sender else {
            continue;
        };
        if let Some(error) = message.get("error") {
            let code = error
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let error_message = error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();
            let _ = sender.send(Err(TransportError::ServerError {
                code,
                message: error_message,
            }));
        } else {
            let result = message
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let _ = sender.send(Ok(result));
        }
    }

    closed.store(true, Ordering::SeqCst);
    let mut pending = pending.lock().await;
    for (_, sender) in pending.entries.drain() {
        let _ = sender.send(Err(TransportError::Closed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_support;
    use wht_corulix_core::CancellationToken;
    use wht_corulix_tooling::{EnvironmentPolicy, ManagedProcess, ManagedProcessSpec};

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// Spawns the shared `wht_corulix_process_fixture` binary with
    /// `arguments` and returns a [`Transport`] wired to its stdin/stdout,
    /// so these tests exercise the real framing/correlation logic against
    /// a real (if trivial) child process rather than an in-memory mock --
    /// process construction stays exclusively `wht_corulix_tooling`'s,
    /// even in this crate's own tests. Portable stand-in for
    /// `/bin/sh -c <script>`, which does not exist on native Windows.
    async fn spawn_transport_over_fixture(arguments: Vec<String>) -> Transport {
        let executable = fixture_support::fixture_binary_path()
            .unwrap_or_else(|error| unreachable!("fixture must resolve: {error}"));
        let spec = ManagedProcessSpec {
            executable,
            arguments,
            environment: EnvironmentPolicy::empty(),
            working_directory: std::env::temp_dir(),
            max_stderr_bytes: 4096,
            argv0: None,
            managed_lease: None,
        };
        let mut process = ManagedProcess::spawn(&spec)
            .await
            .unwrap_or_else(|error| unreachable!("fixture always spawns: {error:?}"));
        let (stdin, stdout) = process
            .take_io()
            .unwrap_or_else(|| unreachable!("a freshly spawned process always has both pipes"));
        // The process itself is intentionally leaked here (not terminated)
        // -- these are short-lived one-shots that exit on their own once
        // they finish writing/reading (or once the eventual timeout/
        // cancellation/shutdown terminates them via the real transport
        // path this test is exercising), and the test only needs the
        // Transport's behavior, not full process lifecycle management.
        std::mem::forget(process);
        Transport::spawn(stdin, stdout)
    }

    /// A real child that writes exactly `bytes` to stdout (flushed), then
    /// holds itself alive for `hold_ms` before exiting -- the portable
    /// stand-in for a shell one-liner like `printf '...'; sleep 5`, used
    /// to prove framing behavior against a real, still-alive child that
    /// has produced exactly one partial, controlled write.
    async fn spawn_transport_writing_then_holding(bytes: &[u8], hold_ms: u64) -> Transport {
        spawn_transport_over_fixture(vec![
            "write-stdout-hex-then-sleep-ms".to_string(),
            hex_encode(bytes),
            hold_ms.to_string(),
        ])
        .await
    }

    /// A real child that produces no output at all and stays alive for
    /// `hold_ms` -- the portable stand-in for `sleep <seconds>`.
    async fn spawn_transport_silent_for(hold_ms: u64) -> Transport {
        spawn_transport_over_fixture(vec!["sleep-ms".to_string(), hold_ms.to_string()]).await
    }

    #[tokio::test]
    async fn malformed_frame_closes_the_connection_not_panics() {
        let transport =
            spawn_transport_writing_then_holding(b"Not-A-Valid-Header\r\n\r\n", 5000).await;
        let cancellation = CancellationToken::new();
        let result = transport
            .request(
                "textDocument/hover",
                serde_json::json!({}),
                Duration::from_secs(5),
                &cancellation,
            )
            .await;
        assert_eq!(result, Err(TransportError::Closed));
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_not_panicked() {
        let transport =
            spawn_transport_writing_then_holding(b"Content-Length: 999999999999\r\n\r\n", 5000)
                .await;
        let cancellation = CancellationToken::new();
        let result = transport
            .request(
                "textDocument/hover",
                serde_json::json!({}),
                Duration::from_secs(5),
                &cancellation,
            )
            .await;
        assert_eq!(result, Err(TransportError::Closed));
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn unexpected_eof_is_handled_not_hung() {
        // A real child that produces no output and exits immediately --
        // portable stand-in for `exit 0`.
        let transport = spawn_transport_silent_for(0).await;
        let cancellation = CancellationToken::new();
        let result = transport
            .request(
                "textDocument/hover",
                serde_json::json!({}),
                Duration::from_secs(5),
                &cancellation,
            )
            .await;
        assert_eq!(result, Err(TransportError::Closed));
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn request_without_a_reply_times_out_deterministically() {
        // A process that produces no output at all: this request
        // genuinely never receives a reply, proving it resolves via
        // `Timeout` rather than hanging.
        let transport = spawn_transport_silent_for(30000).await;
        let cancellation = CancellationToken::new();
        let result = transport
            .request(
                "textDocument/hover",
                serde_json::json!({}),
                Duration::from_millis(200),
                &cancellation,
            )
            .await;
        assert_eq!(result, Err(TransportError::Timeout));
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn request_is_cancelled_deterministically() {
        let transport = spawn_transport_silent_for(30000).await;
        let cancellation = CancellationToken::new();
        let cancel_handle = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel_handle.cancel();
        });
        let result = transport
            .request(
                "textDocument/hover",
                serde_json::json!({}),
                Duration::from_secs(30),
                &cancellation,
            )
            .await;
        assert_eq!(result, Err(TransportError::Cancelled));
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn too_many_pending_requests_is_rejected_not_unbounded() {
        let transport = spawn_transport_silent_for(30000).await;
        let cancellation = CancellationToken::new();
        let mut saw_rejection = false;
        for _ in 0..(MAX_PENDING_REQUESTS + 4) {
            let result = tokio::time::timeout(
                Duration::from_millis(20),
                transport.request(
                    "textDocument/hover",
                    serde_json::json!({}),
                    Duration::from_secs(30),
                    &cancellation,
                ),
            )
            .await;
            // Either the call itself returns TooManyPendingRequests
            // immediately, or the bounded-wait timeout above elapses while
            // it is still legitimately pending -- either is acceptable;
            // what this test forbids is unbounded growth, proven by the
            // explicit rejection appearing before the loop ends.
            if let Ok(Err(TransportError::TooManyPendingRequests)) = result {
                saw_rejection = true;
                break;
            }
        }
        assert!(
            saw_rejection,
            "expected TooManyPendingRequests once the bound was reached"
        );
        transport.shutdown().await;
    }
}
