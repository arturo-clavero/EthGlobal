mod settings;
mod verifier;
mod ws;

#[cfg(test)]
mod tests;

use async_tungstenite::tungstenite::Message;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    serve::ListenerExt,
    Router,
};
use bytes::BytesMut;
use futures_util::SinkExt;
use rangeset::prelude::RangeSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tlsn::transcript::PartialTranscript;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use ws::{TungsteniteStream, WsUpgrade};
use ws_stream_tungstenite::WsStream;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(true)
        .with_max_level(tracing::Level::INFO)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();

    // Load configuration from YAML file
    let config = Config::load(Path::new("config.yaml"));
    info!(
        "Webhook configurations loaded: {} endpoints",
        config.webhooks.len()
    );
    for (server_name, webhook) in &config.webhooks {
        info!("  {} -> {}", server_name, webhook.url);
    }

    // Create application state with session storage and config
    let app_state = Arc::new(AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        config: Arc::new(config),
        settings: Arc::new(settings::Settings::from_env()),
    });
    info!(
        "Session cap: {} active sessions",
        app_state.settings.max_sessions
    );

    // Build router with routes
    let app = router(app_state);

    // Start server
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7047);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("TLSNotary Verifier Server starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");
    let listener = listener.tap_io(|tcp_stream| {
        if let Err(err) = tcp_stream.set_nodelay(true) {
            warn!("failed to set TCP_NODELAY on incoming connection: {err}");
        }
    });

    info!("Server listening on http://{}", addr);
    info!("Health endpoint: http://{}/health", addr);
    info!("Info endpoint: http://{}/info", addr);
    info!("Session WebSocket endpoint: ws://{}/session", addr);
    info!(
        "Verifier WebSocket endpoint: ws://{}/verifier?sessionId=<id>",
        addr
    );
    info!("Proxy WebSocket endpoint: ws://{}/proxy?token=<host>", addr);

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

/// All routes.
pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/info", get(info_handler))
        .route("/session", get(session_ws_handler))
        .route("/verifier", get(verifier_ws_handler))
        .route("/proxy", get(proxy_ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum HandlerType {
    Sent,
    Recv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum HandlerPart {
    StartLine,
    Protocol,
    Method,
    RequestTarget,
    StatusCode,
    Headers,
    Body,
    All,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum HashAlgorithm {
    Blake3,
    Sha256,
    Keccak256,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "UPPERCASE")]
pub(crate) enum HandlerAction {
    Reveal,
    Hash {
        algorithm: HashAlgorithm,
    },
}

impl Default for HandlerAction {
    fn default() -> Self {
        Self::Reveal
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Handler {
    #[serde(rename = "type")]
    pub(crate) handler_type: HandlerType,
    pub(crate) part: HandlerPart,
    #[serde(default)]
    pub(crate) action: HandlerAction,
}

// Session data structure (without handlers - they come later with ranges)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionConfig {
    #[serde(rename = "maxRecvData")]
    max_recv_data: usize,
    #[serde(rename = "maxSentData")]
    max_sent_data: usize,
}

// Range with handler metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RangeWithHandler {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) handler: Handler,
}

// Reveal configuration sent before prover.reveal()
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RevealConfig {
    sent: Vec<RangeWithHandler>,
    recv: Vec<RangeWithHandler>,
    /// The step name of this proof's result (a later proof of a multi-reveal
    /// session); `None` = the session's own `sessionData.step`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    step: Option<String>,
}

// Handler result with revealed value
#[derive(Debug, Clone, Serialize)]
struct HandlerResult {
    #[serde(flatten)]
    handler: Handler,
    value: String,
}

// Verification result containing handler results or an error
#[derive(Debug, Clone, Serialize)]
struct VerificationResult {
    results: Vec<HandlerResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The id this proof's result is delivered under (the session id for the
    /// first proof, a fresh id for each later one).
    #[serde(skip)]
    result_id: Option<String>,
}

impl VerificationResult {
    fn failed(msg: String) -> Self {
        Self {
            results: vec![],
            error: Some(msg),
            result_id: None,
        }
    }
}

// Type aliases for WebSocket senders
type ProverSocketSender = oneshot::Sender<TungsteniteStream>;
type ProxySocketSender = oneshot::Sender<TungsteniteStream>;

// Session data stored in AppState
pub(crate) struct SessionData {
    pub(crate) prover_socket_tx: Option<ProverSocketSender>,
    /// In proxy mode, the verifier task stores a sender here so the /proxy
    /// endpoint can route the prover's proxy WebSocket to it.
    pub(crate) proxy_socket_tx: Option<ProxySocketSender>,
}

// Application state for sharing data between handlers
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) sessions: Arc<Mutex<HashMap<String, SessionData>>>,
    pub(crate) config: Arc<Config>,
    pub(crate) settings: Arc<settings::Settings>,
}

// Query parameters for verifier WebSocket connection
#[derive(Debug, Deserialize)]
struct VerifierQuery {
    #[serde(rename = "sessionId")]
    session_id: String,
}

// Query parameters for proxy WebSocket connection
// Supports both `token` (notary.pse.dev compatible) and `host` (legacy)
// In proxy mode, `session_id` routes the WS to the verifier task.
#[derive(Debug, Deserialize)]
struct ProxyQuery {
    #[serde(alias = "host")]
    token: String,
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
}

// ============================================================================
// WebSocket Message Protocol (Typed Messages)
// ============================================================================

/// Incoming messages from client (extension)
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    /// Registration message - sent first to establish session
    Register {
        #[serde(rename = "maxRecvData")]
        max_recv_data: usize,
        #[serde(rename = "maxSentData")]
        max_sent_data: usize,
        #[serde(rename = "sessionData", default)]
        session_data: HashMap<String, String>,
        /// The client may prove this session's transcript several times (one
        /// `reveal_config` + prove request per proof, then `finish`). Absent:
        /// one proof, as upstream.
        #[serde(rename = "multiReveal", default)]
        multi_reveal: bool,
    },
    /// Reveal configuration - sent with ranges and handlers
    RevealConfig {
        sent: Vec<RangeWithHandler>,
        recv: Vec<RangeWithHandler>,
        /// The step name of a later proof's result.
        #[serde(default)]
        step: Option<String>,
    },
    /// A multi-reveal session has made its last proof.
    Finish,
}

/// Outgoing messages to client (extension)
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    /// Session registered successfully
    SessionRegistered {
        #[serde(rename = "sessionId")]
        session_id: String,
        /// Set (true) only when the client asked for a multi-reveal session,
        /// so an upstream client sees the upstream message.
        #[serde(rename = "multiReveal", skip_serializing_if = "Option::is_none")]
        multi_reveal: Option<bool>,
    },
    /// Session completed with results
    SessionCompleted {
        results: Vec<HandlerResult>,
    },
    /// One proof of a multi-reveal session verified (the session stays open
    /// for the next `reveal_config` or `finish`).
    RevealCompleted {
        /// 0-based proof index in the session.
        reveal: usize,
        /// The id the result is delivered (webhook) under.
        #[serde(rename = "resultId")]
        result_id: String,
        results: Vec<HandlerResult>,
    },
    /// A multi-reveal session ended after `reveals` proofs.
    SessionClosed {
        reveals: usize,
    },
    /// Error occurred
    Error {
        message: String,
    },
}

// ============================================================================
// Webhook Types
// ============================================================================

/// Webhook configuration for a specific server
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct WebhookConfig {
    pub(crate) url: String,
    #[serde(default)]
    pub(crate) headers: HashMap<String, String>,
}

/// Application configuration loaded from YAML
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct Config {
    #[serde(default)]
    pub(crate) webhooks: HashMap<String, WebhookConfig>,
}

impl Config {
    /// Load configuration from YAML file, returns default if file doesn't exist
    fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => match serde_yaml_ng::from_str(&contents) {
                Ok(config) => {
                    info!("Loaded config from {:?}", path);
                    config
                }
                Err(e) => {
                    warn!("Failed to parse config file {:?}: {}", path, e);
                    Self::default()
                }
            },
            Err(_) => {
                info!("No config file found at {:?}, using defaults", path);
                Self::default()
            }
        }
    }

    /// Get webhook configuration for a server name (with wildcard fallback)
    fn get_webhook(&self, server_name: &str) -> Option<&WebhookConfig> {
        self.webhooks
            .get(server_name)
            .or_else(|| self.webhooks.get("*"))
    }
}

/// Webhook payload sent to configured endpoints
#[derive(Debug, Serialize)]
struct WebhookPayload {
    /// The server name (hostname) from the TLS connection
    server_name: String,
    /// Handler results with revealed values
    results: Vec<HandlerResult>,
    /// The reveal configuration (ranges + handlers)
    config: RevealConfigForWebhook,
    /// Session metadata
    session: SessionInfo,
    /// Redacted transcripts (bytes outside revealed ranges replaced with 0x00)
    transcript: RedactedTranscript,
}

/// Reveal config for webhook (same structure, different purpose)
#[derive(Debug, Serialize)]
struct RevealConfigForWebhook {
    sent: Vec<RangeWithHandler>,
    recv: Vec<RangeWithHandler>,
}

/// Session information for webhook
#[derive(Debug, Serialize)]
struct SessionInfo {
    id: String,
    #[serde(flatten)]
    data: HashMap<String, String>,
}

/// Redacted transcript data - bytes outside revealed ranges are zeroed out
#[derive(Debug, Serialize)]
struct RedactedTranscript {
    /// Redacted sent data (request) - unrevealed bytes replaced with 0x00
    sent: String,
    /// Redacted received data (response) - unrevealed bytes replaced with 0x00
    recv: String,
    /// Original sent length before redaction
    sent_length: usize,
    /// Original recv length before redaction
    recv_length: usize,
}

impl RedactedTranscript {
    /// Create redacted transcript from raw bytes and reveal config
    fn from_transcript(
        sent_bytes: &[u8],
        recv_bytes: &[u8],
        reveal_config: &RevealConfig,
    ) -> Self {
        Self {
            sent: Self::redact_bytes(sent_bytes, &reveal_config.sent),
            recv: Self::redact_bytes(recv_bytes, &reveal_config.recv),
            sent_length: sent_bytes.len(),
            recv_length: recv_bytes.len(),
        }
    }

    /// Redact bytes by zeroing out bytes outside the revealed ranges
    fn redact_bytes(bytes: &[u8], ranges: &[RangeWithHandler]) -> String {
        let mut redacted = vec![0u8; bytes.len()];

        for range in ranges {
            if range.start < bytes.len() && range.end <= bytes.len() {
                redacted[range.start..range.end].copy_from_slice(&bytes[range.start..range.end]);
            }
        }

        // Convert to string - using lossy conversion for non-UTF8 bytes
        String::from_utf8_lossy(&redacted).to_string()
    }
}

// Health check endpoint handler
async fn health_handler() -> impl IntoResponse {
    "ok"
}

/// Info response structure
#[derive(Debug, Serialize)]
struct InfoResponse {
    /// Package version from Cargo.toml
    version: &'static str,
    /// Git commit hash (from GIT_HASH env var, set by CI)
    git_hash: String,
    /// TLSNotary library version
    tlsn_version: &'static str,
}

/// Info endpoint handler - returns server information as JSON
pub(crate) async fn info_handler() -> impl IntoResponse {
    let git_hash = std::env::var("GIT_HASH").unwrap_or_else(|_| "dev".to_string());

    axum::Json(InfoResponse {
        version: env!("CARGO_PKG_VERSION"),
        git_hash,
        tlsn_version: "0.1.0-alpha.15",
    })
}

// WebSocket session handler for extension
pub(crate) async fn session_ws_handler(
    ws: WsUpgrade,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // The slot is shared by the socket handler and the verifier task and is
    // released when both are done.
    let Some(slot) = state.settings.try_acquire_session() else {
        warn!(
            "Rejecting new session: {} active sessions (max {})",
            state.settings.active_sessions(),
            state.settings.max_sessions
        );
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Verifier is at capacity, retry shortly".to_string(),
        ));
    };
    let slot = Arc::new(slot);
    Ok(ws.on_upgrade(move |socket| handle_session_websocket(socket, state, slot)))
}

/// Helper to send typed server messages
async fn send_server_message(socket: &mut TungsteniteStream, message: &ServerMessage) -> bool {
    match socket
        .send(Message::Text(serde_json::to_string(message).unwrap().into()))
        .await
    {
        Ok(_) => true,
        Err(e) => {
            error!("Failed to send message: {}", e);
            false
        }
    }
}

/// Helper to send error message
async fn send_error(socket: &mut TungsteniteStream, message: &str) {
    let _ = send_server_message(socket, &ServerMessage::Error {
        message: message.to_string(),
    })
    .await;
}

// Handle the session WebSocket connection with typed message protocol
async fn handle_session_websocket(
    mut socket: TungsteniteStream,
    state: Arc<AppState>,
    slot: Arc<settings::SessionSlot>,
) {
    use futures_util::StreamExt;

    // Generate session ID upfront (but don't send yet - wait for register)
    let session_id = Uuid::new_v4().to_string();
    info!("[{}] New session WebSocket connected", session_id);

    // Wait for "register" message first (bounded, so an idle socket cannot hold a slot)
    let first = match timeout(settings::REGISTER_TIMEOUT, socket.next()).await {
        Ok(msg) => msg,
        Err(_) => {
            error!("[{}] Timed out waiting for registration", session_id);
            send_error(&mut socket, "Timed out waiting for register").await;
            return;
        }
    };
    let register_msg = match first {
        Some(Ok(Message::Text(text))) => text,
        Some(Ok(msg)) => {
            error!("[{}] Expected text message, got: {:?}", session_id, msg);
            send_error(&mut socket, "Expected text message").await;
            return;
        }
        Some(Err(e)) => {
            error!("[{}] Error receiving message: {}", session_id, e);
            return;
        }
        None => {
            error!("[{}] Connection closed before registration", session_id);
            return;
        }
    };

    // Parse as ClientMessage
    let client_msg: ClientMessage = match serde_json::from_str(&register_msg) {
        Ok(msg) => msg,
        Err(e) => {
            error!("[{}] Failed to parse message: {}", session_id, e);
            send_error(&mut socket, &format!("Invalid message format: {}", e)).await;
            return;
        }
    };

    // Expect "register" message type
    let (max_recv_data, max_sent_data, mut session_data, multi_reveal) = match client_msg {
        ClientMessage::Register {
            max_recv_data,
            max_sent_data,
            session_data,
            multi_reveal,
        } => (max_recv_data, max_sent_data, session_data, multi_reveal),
        _ => {
            error!("[{}] Expected 'register' message type", session_id);
            send_error(&mut socket, "Expected 'register' message type").await;
            return;
        }
    };

    // The keys that link the proofs of a multi-reveal session are the
    // verifier's to set; a client cannot claim them.
    for key in RESERVED_SESSION_KEYS {
        session_data.remove(*key);
    }

    let over_recv = state.settings.max_recv_data.is_some_and(|cap| max_recv_data > cap);
    let over_sent = state.settings.max_sent_data.is_some_and(|cap| max_sent_data > cap);
    if over_recv || over_sent {
        error!(
            "[{}] Registration exceeds limits: maxRecvData={} (cap {:?}), maxSentData={} (cap {:?})",
            session_id,
            max_recv_data,
            state.settings.max_recv_data,
            max_sent_data,
            state.settings.max_sent_data
        );
        send_error(&mut socket, "maxRecvData/maxSentData exceed verifier limits").await;
        return;
    }

    info!(
        "[{}] Received registration: maxRecvData={}, maxSentData={}, sessionData keys: {:?}",
        session_id,
        max_recv_data,
        max_sent_data,
        session_data.keys().collect::<Vec<_>>()
    );

    // Send session_registered response
    if !send_server_message(
        &mut socket,
        &ServerMessage::SessionRegistered {
            session_id: session_id.clone(),
            multi_reveal: multi_reveal.then_some(true),
        },
    )
    .await
    {
        error!("[{}] Failed to send session_registered", session_id);
        return;
    }

    info!(
        "[{}] Sent session_registered to client (multi-reveal: {})",
        session_id, multi_reveal
    );

    // Create channels for prover socket, reveal configs, and results: one
    // reveal config and one result per proof (a single proof unless the client
    // registered multiReveal); dropping `reveal_config_tx` ends the session.
    let (prover_socket_tx, prover_socket_rx) = oneshot::channel::<TungsteniteStream>();
    let (reveal_config_tx, reveal_config_rx) = mpsc::channel::<RevealConfig>(1);
    let (result_tx, mut result_rx) = mpsc::channel::<VerificationResult>(1);

    let session_data_storage = Arc::new(session_data.clone());

    let session_config = SessionConfig {
        max_recv_data,
        max_sent_data,
    };

    // Store session data (so prover can connect)
    {
        let mut sessions = state.sessions.lock().await;
        sessions.insert(
            session_id.clone(),
            SessionData {
                prover_socket_tx: Some(prover_socket_tx),
                proxy_socket_tx: None,
            },
        );
    }

    info!(
        "[{}] Session stored, prover can now connect to /verifier",
        session_id
    );

    // Spawn the verifier task with the result sender
    let session_id_clone = session_id.clone();
    let state_clone = state.clone();
    let session_data_clone = session_data_storage.clone();
    let task_slot = slot.clone();
    // Kept so a refused reveal_config can stop the task before it proves.
    let verifier_task = tokio::spawn(async move {
        // The task holds the slot until it ends.
        run_verifier_task(
            session_id_clone,
            session_config,
            (*session_data_clone).clone(),
            multi_reveal,
            reveal_config_rx,
            prover_socket_rx,
            result_tx,
            state_clone,
            task_slot,
        )
        .await;
    });

    info!(
        "[{}] Verifier task spawned, waiting for prover connection and reveal config",
        session_id
    );

    let mut reveals = 0usize;
    loop {
        // The first reveal_config may take the prover's setup and transfer; a later
        // one only the client's reaction to the previous result.
        let wait = if reveals == 0 {
            settings::REVEAL_CONFIG_TIMEOUT
        } else {
            settings::NEXT_REVEAL_TIMEOUT
        };
        let next = match timeout(wait, socket.next()).await {
            Ok(msg) => msg,
            Err(_) if reveals > 0 => {
                warn!(
                    "[{}] No further reveal_config within {:?}: closing after {} proof(s)",
                    session_id, wait, reveals
                );
                break;
            }
            Err(_) => {
                error!("[{}] Timed out waiting for reveal_config", session_id);
                send_error(&mut socket, "Timed out waiting for reveal_config").await;
                return;
            }
        };
        let reveal_msg = match next {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(msg)) => {
                error!(
                    "[{}] Expected text message for reveal_config, got: {:?}",
                    session_id, msg
                );
                send_error(&mut socket, "Expected text message").await;
                return;
            }
            Some(Err(e)) => {
                error!("[{}] Error receiving reveal_config: {}", session_id, e);
                return;
            }
            None if reveals > 0 => {
                info!("[{}] Client closed after {} proof(s)", session_id, reveals);
                break;
            }
            None => {
                error!(
                    "[{}] Connection closed before receiving reveal_config",
                    session_id
                );
                return;
            }
        };

        // Parse as ClientMessage
        let client_msg: ClientMessage = match serde_json::from_str(&reveal_msg) {
            Ok(msg) => msg,
            Err(e) => {
                error!("[{}] Failed to parse reveal_config: {}", session_id, e);
                send_error(&mut socket, &format!("Invalid message format: {}", e)).await;
                return;
            }
        };

        // Expect "reveal_config" message type (or `finish` after a proof)
        let reveal_config = match client_msg {
            ClientMessage::RevealConfig { sent, recv, step } => RevealConfig { sent, recv, step },
            ClientMessage::Finish if multi_reveal && reveals > 0 => {
                info!("[{}] finish after {} proof(s)", session_id, reveals);
                break;
            }
            _ => {
                error!("[{}] Expected 'reveal_config' message type", session_id);
                send_error(&mut socket, "Expected 'reveal_config' message type").await;
                return;
            }
        };

        // A later proof names its own step; at most MAX_REVEALS_PER_SESSION.
        if let Some(msg) = reveal_step_problem(&reveal_config, reveals) {
            error!("[{}] {}", session_id, msg);
            verifier_task.abort();
            cleanup_session(&state, &session_id).await;
            send_error(&mut socket, &msg).await;
            let _ = socket.close(None).await;
            return;
        }

        info!(
            "[{}] Received reveal_config {}: {} sent ranges, {} recv ranges",
            session_id,
            reveals,
            reveal_config.sent.len(),
            reveal_config.recv.len()
        );

        // Forward reveal config to verifier task
        if reveal_config_tx.send(reveal_config).await.is_err() {
            error!(
                "[{}] ❌ Verifier task dropped reveal config receiver",
                session_id
            );
            send_error(&mut socket, "Verification failed").await;
            let _ = socket.close(None).await;
            return;
        }

        info!(
            "[{}] ✅ Reveal config sent, verifier task can now proceed",
            session_id
        );

        // Wait for verification result
        match result_rx.recv().await {
            Some(result) if result.error.is_some() => {
                let err_msg = result.error.as_deref().unwrap_or("Unknown error");
                error!("[{}] ❌ {}", session_id, err_msg);
                send_error(&mut socket, err_msg).await;
                let _ = socket.close(None).await;
                return;
            }
            Some(result) if multi_reveal => {
                let result_id = result.result_id.clone().unwrap_or_else(|| session_id.clone());
                if send_server_message(
                    &mut socket,
                    &ServerMessage::RevealCompleted {
                        reveal: reveals,
                        result_id,
                        results: result.results,
                    },
                )
                .await
                {
                    info!("[{}] ✅ Sent reveal_completed {} to extension", session_id, reveals);
                } else {
                    error!("[{}] Failed to send reveal_completed", session_id);
                    return;
                }
            }
            Some(result) => {
                info!(
                    "[{}] Received verification result, sending to extension",
                    session_id
                );

                // Send session_completed to extension
                if send_server_message(
                    &mut socket,
                    &ServerMessage::SessionCompleted {
                        results: result.results,
                    },
                )
                .await
                {
                    info!("[{}] ✅ Sent session_completed to extension", session_id);
                } else {
                    error!("[{}] Failed to send session_completed", session_id);
                }
            }
            None => {
                error!(
                    "[{}] ❌ Verifier task closed without sending result",
                    session_id
                );
                send_error(&mut socket, "Verification failed").await;
                let _ = socket.close(None).await;
                return;
            }
        }
        reveals += 1;
        if !multi_reveal {
            break;
        }
    }

    // No further proof: the verifier task closes the TLSNotary session.
    drop(reveal_config_tx);
    if multi_reveal {
        let _ = send_server_message(&mut socket, &ServerMessage::SessionClosed { reveals }).await;
    }

    // Close the WebSocket
    let _ = socket.close(None).await;
    info!("[{}] Session WebSocket closed", session_id);
}

/// sessionData keys only the verifier sets, on the results of a multi-reveal
/// session: `revealOf` = the session id (the first proof's result id) and
/// `reveal` = the proof's 0-based index. Removed from what a client registers,
/// so they always come from here.
pub(crate) const RESERVED_SESSION_KEYS: &[&str] = &["revealOf", "reveal"];

/// Why a reveal_config cannot be the `index`-th proof of its session.
fn reveal_step_problem(config: &RevealConfig, index: usize) -> Option<String> {
    if index >= settings::MAX_REVEALS_PER_SESSION {
        return Some(format!(
            "too many proofs in one session (at most {})",
            settings::MAX_REVEALS_PER_SESSION
        ));
    }
    match config.step.as_deref() {
        None if index > 0 => Some("a later proof's reveal_config must name its step".to_string()),
        Some(step)
            if step.is_empty()
                || step.len() > 32
                || !step.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
        {
            Some("invalid reveal_config step".to_string())
        }
        _ => None,
    }
}

/// The sessionData a proof's result carries: the session's own, with the
/// proof's step, and for a multi-reveal session the verifier's link keys.
fn result_session_data(
    session_data: &HashMap<String, String>,
    session_id: &str,
    multi_reveal: bool,
    reveal: usize,
    step: Option<&str>,
) -> HashMap<String, String> {
    let mut data = session_data.clone();
    if let Some(step) = step {
        data.insert("step".to_string(), step.to_string());
    }
    if multi_reveal {
        data.insert("revealOf".to_string(), session_id.to_string());
        data.insert("reveal".to_string(), reveal.to_string());
    }
    data
}

// WebSocket handler for verifier (prover connection)
pub(crate) async fn verifier_ws_handler(
    ws: WsUpgrade,
    State(state): State<Arc<AppState>>,
    Query(query): Query<VerifierQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = query.session_id;

    // Look up the session and extract the prover socket sender.
    // Don't remove the session — proxy mode needs it for the proxy WS routing.
    let prover_socket_tx = {
        let mut sessions = state.sessions.lock().await;
        sessions
            .get_mut(&session_id)
            .and_then(|s| s.prover_socket_tx.take())
    };

    match prover_socket_tx {
        Some(sender) => {
            info!(
                "[{}] Prover WebSocket connection established, passing to verifier",
                session_id
            );
            Ok(ws.on_upgrade(move |socket| async move {
                // Send the WebSocket to the waiting verifier
                if sender.send(socket).is_err() {
                    error!(
                        "[{}] Failed to send socket to verifier - channel closed",
                        session_id
                    );
                } else {
                    info!(
                        "[{}] Prover socket passed to verifier successfully",
                        session_id
                    );
                }
            }))
        }
        None => {
            error!("[{}] Session not found or already connected", session_id);
            Err((
                StatusCode::NOT_FOUND,
                format!("Session not found or already connected: {}", session_id),
            ))
        }
    }
}

// WebSocket proxy handler - bridges WebSocket to TCP
// Compatible with notary.pse.dev: /proxy?token=<host> or legacy /proxy?host=<host>
// In proxy mode: /proxy?token=<host>&sessionId=<id> routes to verifier task
pub(crate) async fn proxy_ws_handler(
    ws: WsUpgrade,
    Query(query): Query<ProxyQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let host = query.token;
    let session_id = query.session_id;

    info!(
        "[Proxy] New proxy request for host: {}, sessionId: {:?}",
        host, session_id
    );

    if let Some(sid) = session_id {
        // Proxy mode: route this WebSocket to the verifier task
        Ok(ws.on_upgrade(move |socket| async move {
            let proxy_tx = {
                let mut sessions = state.sessions.lock().await;
                sessions
                    .get_mut(&sid)
                    .and_then(|s| s.proxy_socket_tx.take())
            };
            match proxy_tx {
                Some(tx) => {
                    info!("[Proxy] Routing proxy WS to verifier task for session {}", sid);
                    if tx.send(socket).is_err() {
                        error!("[Proxy] Verifier task dropped proxy channel for session {}", sid);
                    }
                }
                None => {
                    error!(
                        "[Proxy] No proxy socket channel for session {} (not proxy mode or already connected)",
                        sid
                    );
                }
            }
        }))
    } else {
        // MPC mode: standard TCP bridge
        Ok(ws.on_upgrade(move |socket| handle_proxy_connection(socket, host)))
    }
}

// Handle the proxy WebSocket connection by bridging to TCP
async fn handle_proxy_connection(ws: TungsteniteStream, host: String) {
    use futures_util::StreamExt;

    let proxy_id = Uuid::new_v4().to_string();
    info!(
        "[{}] Proxy WebSocket connected for host: {}",
        proxy_id, host
    );

    // Parse host and port (default to 443 for HTTPS)
    let (hostname, port) = if host.contains(':') {
        let parts: Vec<&str> = host.split(':').collect();
        (
            parts[0].to_string(),
            parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443),
        )
    } else {
        (host.clone(), 443)
    };

    info!("[{}] Connecting to {}:{}", proxy_id, hostname, port);

    // Connect to the remote TCP host
    let tcp_stream = match tokio::net::TcpStream::connect((hostname.as_str(), port)).await {
        Ok(stream) => {
            info!(
                "[{}] TCP connection established to {}:{}",
                proxy_id, hostname, port
            );
            stream
        }
        Err(e) => {
            error!(
                "[{}] Failed to connect to {}:{} - {}",
                proxy_id, hostname, port, e
            );
            return;
        }
    };
    if let Err(err) = tcp_stream.set_nodelay(true) {
        warn!(
            "[{}] failed to set TCP_NODELAY on outbound proxy connection: {}",
            proxy_id, err
        );
    }

    // Split WebSocket into sink and stream
    let (mut ws_sink, mut ws_stream) = ws.split();

    // Split the TCP stream into read and write halves
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);

    // Spawn task to forward WebSocket -> TCP
    // Read WebSocket Binary messages and write payload to TCP
    let proxy_id_clone = proxy_id.clone();
    let ws_to_tcp = tokio::spawn(async move {
        let mut total_bytes = 0u64;

        loop {
            match ws_stream.next().await {
                Some(Ok(msg)) => {
                    match msg {
                        Message::Binary(data) => {
                            let len = data.len();
                            total_bytes += len as u64;

                            if let Err(e) = tcp_write.write_all(&data).await {
                                error!("[{}] Failed to write to TCP: {}", proxy_id_clone, e);
                                break;
                            }
                        }
                        Message::Close(_) => {
                            info!(
                                "[{}] WebSocket close frame received, forwarded {} bytes total",
                                proxy_id_clone, total_bytes
                            );
                            break;
                        }
                        _ => {
                            // Ignore Text, Ping, Pong messages for now
                        }
                    }
                }
                Some(Err(e)) => {
                    error!("[{}] WebSocket read error: {}", proxy_id_clone, e);
                    break;
                }
                None => {
                    info!(
                        "[{}] WebSocket stream ended, forwarded {} bytes total",
                        proxy_id_clone, total_bytes
                    );
                    break;
                }
            }
        }

        total_bytes
    });

    // Spawn task to forward TCP -> WebSocket
    // Read from TCP and wrap in WebSocket Binary messages
    let proxy_id_clone = proxy_id.clone();
    let tcp_to_ws = tokio::spawn(async move {
        const CHUNK: usize = 8192;
        let mut buf = BytesMut::with_capacity(CHUNK);
        let mut total_bytes = 0u64;

        loop {
            buf.reserve(CHUNK);
            match tcp_read.read_buf(&mut buf).await {
                Ok(0) => {
                    info!(
                        "[{}] TCP read EOF (server closed), forwarded {} bytes to WebSocket",
                        proxy_id_clone, total_bytes
                    );
                    // Send WebSocket close frame to signal EOF to client
                    if let Err(e) = ws_sink.send(Message::Close(None)).await {
                        error!("[{}] Failed to send WebSocket close frame: {}", proxy_id_clone, e);
                    }
                    break;
                }
                Ok(n) => {
                    total_bytes += n as u64;
                    let chunk = buf.split().freeze();

                    if let Err(e) = ws_sink.send(Message::Binary(chunk)).await {
                        error!("[{}] Failed to send to WebSocket: {}", proxy_id_clone, e);
                        break;
                    }
                }
                Err(e) => {
                    error!("[{}] TCP read error: {}", proxy_id_clone, e);
                    // Send close frame on error too
                    let _ = ws_sink.send(Message::Close(None)).await;
                    break;
                }
            }
        }

        total_bytes
    });

    // Wait for both tasks to complete
    let (ws_result, tcp_result) = tokio::join!(ws_to_tcp, tcp_to_ws);

    let ws_total = ws_result.unwrap_or(0);
    let tcp_total = tcp_result.unwrap_or(0);

    info!(
        "[{}] Proxy closed: WS→TCP {} bytes, TCP→WS {} bytes",
        proxy_id, ws_total, tcp_total
    );
}

/// How long the TLS connection, and then each proof, may take. With the mux
/// backpressure of the pinned core a single large reveal step legitimately
/// takes minutes, so this matches the extension's proxy send timeout: both
/// sides must clear the same worst case or the shorter one wins.
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(300);

// Verifier task that waits for WebSocket and runs verification
#[allow(clippy::too_many_arguments)]
async fn run_verifier_task(
    session_id: String,
    config: SessionConfig,
    session_data: HashMap<String, String>,
    multi_reveal: bool,
    mut reveal_config_rx: mpsc::Receiver<RevealConfig>,
    socket_rx: oneshot::Receiver<TungsteniteStream>,
    result_tx: mpsc::Sender<VerificationResult>,
    state: Arc<AppState>,
    _slot: Arc<settings::SessionSlot>,
) {
    info!(
        "[{}] Verifier task started, waiting for WebSocket connection...",
        session_id
    );
    info!(
        "[{}] Configuration: maxRecvData={}, maxSentData={}",
        session_id, config.max_recv_data, config.max_sent_data
    );

    // Wait for WebSocket connection with timeout
    let connection_timeout = Duration::from_secs(30);
    let socket_result = timeout(connection_timeout, socket_rx).await;

    let socket = match socket_result {
        Ok(Ok(socket)) => {
            info!(
                "[{}] ✅ WebSocket received, starting verification",
                session_id
            );
            socket
        }
        Ok(Err(_)) => {
            error!(
                "[{}] ❌ Socket channel closed before connection",
                session_id
            );
            cleanup_session(&state, &session_id).await;
            return;
        }
        Err(_) => {
            error!(
                "[{}] ⏱️  Timed out waiting for WebSocket connection after {:?}",
                session_id, connection_timeout
            );
            cleanup_session(&state, &session_id).await;
            return;
        }
    };

    // Set up a channel to receive the prover's proxy WebSocket.
    // In universal mode the verifier accepts both MPC and Proxy — the prover decides.
    // If the prover chooses proxy, it connects to /proxy?sessionId=... which routes here.
    let (proxy_tx, proxy_rx) = oneshot::channel::<TungsteniteStream>();
    {
        let mut sessions = state.sessions.lock().await;
        if let Some(session_data) = sessions.get_mut(&session_id) {
            session_data.proxy_socket_tx = Some(proxy_tx);
        }
    }
    let proxy_socket_rx = Some(proxy_rx);

    // Wrap the WebSocket stream in WsStream for AsyncRead/AsyncWrite compatibility
    let stream = WsStream::new(socket);
    info!("[{}] WebSocket converted to stream", session_id);

    // Convert from futures AsyncRead/AsyncWrite to tokio AsyncRead/AsyncWrite
    let stream = stream.compat();

    // Run the verifier with timeout: the TLS session, then each proof
    let verification_timeout = VERIFICATION_TIMEOUT;
    info!(
        "[{}] Starting verification with timeout of {:?}",
        session_id, verification_timeout
    );

    let setup = timeout(
        verification_timeout,
        verifier::setup(
            stream,
            config.max_sent_data,
            config.max_recv_data,
            proxy_socket_rx,
            &state.settings,
        ),
    )
    .await;

    let mut session = match setup {
        Ok(Ok(session)) => session,
        Ok(Err(e)) => {
            let msg = format!("Verification failed: {}", e);
            error!("[{}] ❌ {}", session_id, msg);
            let _ = result_tx.send(VerificationResult::failed(msg)).await;
            cleanup_session(&state, &session_id).await;
            return;
        }
        Err(_) => {
            let msg = format!("Verification timed out after {:?}", verification_timeout);
            error!("[{}] ⏱️  {}", session_id, msg);
            let _ = result_tx.send(VerificationResult::failed(msg)).await;
            cleanup_session(&state, &session_id).await;
            return;
        }
    };

    // One proof per reveal_config the session handler forwards (one, unless the
    // client registered multiReveal); the channel closes when there are no more.
    // The reveal_config arrives before the prover's prove request, so each proof
    // is checked against what the client announced for it.
    let mut session_server: Option<tlsn::connection::DnsName> = None;
    while let Some(reveal_config) = reveal_config_rx.recv().await {
        let reveal = session.reveals();
        let verified = timeout(verification_timeout, session.reveal()).await;
        let out = match verified {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                let msg = format!("Verification failed: {}", e);
                error!("[{}] ❌ {}", session_id, msg);
                let _ = result_tx.send(VerificationResult::failed(msg)).await;
                break;
            }
            Err(_) => {
                let msg = format!("Verification timed out after {:?}", verification_timeout);
                error!("[{}] ⏱️  {}", session_id, msg);
                let _ = result_tx.send(VerificationResult::failed(msg)).await;
                break;
            }
        };

        // The first proof proves the server identity; a later proof of the same
        // session may leave it out but may not name another server.
        let server_name = match (out.server_name, &session_server) {
            (Some(name), None) => name,
            (None, Some(first)) => first.clone(),
            (Some(name), Some(first)) if name == *first => name,
            (Some(_), Some(_)) => {
                let msg = "Verification failed: a later proof named another server".to_string();
                error!("[{}] ❌ {}", session_id, msg);
                let _ = result_tx.send(VerificationResult::failed(msg)).await;
                break;
            }
            (None, None) => {
                let msg = "Verification failed: prover should have revealed server name".to_string();
                error!("[{}] ❌ {}", session_id, msg);
                let _ = result_tx.send(VerificationResult::failed(msg)).await;
                break;
            }
        };
        session_server.get_or_insert_with(|| server_name.clone());
        let transcript = out.transcript;
        let transcript_commitments = out.transcript_commitments;

        info!("[{}] ✅ Verification {} completed successfully!", session_id, reveal);

        // Extract sent and received data
        let sent_bytes = transcript.sent_unsafe().to_vec();
        let recv_bytes = transcript.received_unsafe().to_vec();

        info!(
            "[{}] Sent data length: {} bytes (authed: {} bytes)",
            session_id,
            sent_bytes.len(),
            transcript.sent_authed().len(),
        );
        info!(
            "[{}] Received data length: {} bytes (authed: {} bytes)",
            session_id,
            recv_bytes.len(),
            transcript.received_authed().len()
        );

        // Validate each action against its own authenticated evidence.
        if let Err((direction, start, end)) = verify_reveal_config(
            &reveal_config,
            &transcript,
            &transcript_commitments,
        ) {
            error!(
                "[{}] ❌ Invalid {} range [{}, {}) - not fully within authenticated ranges",
                session_id, direction, start, end
            );
            break;
        }

        info!(
            "[{}] ✅ All reveal_config ranges validated against authenticated transcript",
            session_id
        );

        // Map revealed ranges to handler results using raw transcript bytes.
        // For HASH handlers, substitute the hex-encoded hash digest (the
        // plaintext was never revealed, so `bytes[..]` is zeroed).

        let mut handler_results = Vec::new();

        handler_results.extend(process_ranges(
            &reveal_config.sent,
            &sent_bytes,
            tlsn::transcript::Direction::Sent,
            &transcript_commitments,
            "SENT",
            &session_id,
        ));
        handler_results.extend(process_ranges(
            &reveal_config.recv,
            &recv_bytes,
            tlsn::transcript::Direction::Received,
            &transcript_commitments,
            "RECV",
            &session_id,
        ));

        // Each proof is delivered as its own result: the first under the session
        // id, each later one under a fresh id, with its step and the link to its
        // session (`revealOf`, `reveal`) in the session data.
        let result_id = if reveal == 0 {
            session_id.clone()
        } else {
            Uuid::new_v4().to_string()
        };
        let result_data = result_session_data(
            &session_data,
            &session_id,
            multi_reveal,
            reveal,
            reveal_config.step.as_deref(),
        );

        // Check if webhook is configured for this server_name
        let server_name_str = server_name.as_ref();
        if let Some(webhook_config) = state.config.get_webhook(server_name_str) {
            info!(
                "[{}] Webhook configured for {}, sending POST to {}",
                result_id, server_name_str, webhook_config.url
            );

            // Create redacted transcript - only revealed ranges are visible
            let redacted_transcript = RedactedTranscript::from_transcript(
                &sent_bytes,
                &recv_bytes,
                &reveal_config,
            );

            let payload = WebhookPayload {
                server_name: server_name_str.to_string(),
                results: handler_results.clone(),
                config: RevealConfigForWebhook {
                    sent: reveal_config.sent.clone(),
                    recv: reveal_config.recv.clone(),
                },
                session: SessionInfo {
                    id: result_id.clone(),
                    data: result_data,
                },
                transcript: redacted_transcript,
            };

            // Fire and forget - don't block on webhook
            let webhook_config = webhook_config.clone();
            let result_id_for_webhook = result_id.clone();
            tokio::spawn(async move {
                send_webhook(&webhook_config, &payload, &result_id_for_webhook).await;
            });
        }

        // Send result to extension via the result channel
        let result = VerificationResult {
            results: handler_results,
            error: None,
            result_id: Some(result_id),
        };

        if result_tx.send(result).await.is_err() {
            error!(
                "[{}] ❌ Failed to send result to extension - channel closed",
                session_id
            );
            break;
        } else {
            info!("[{}] ✅ Result {} sent to extension successfully", session_id, reveal);
        }
    }

    // Close the TLSNotary session (bounded: a prover that never closes its side
    // must not hold the slot).
    match timeout(Duration::from_secs(30), session.finish()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("[{}] Session close: {}", session_id, e),
        Err(_) => warn!("[{}] Session close timed out", session_id),
    }

    // Clean up session (if it still exists in the map)
    cleanup_session(&state, &session_id).await;

    info!("[{}] Verifier task completed and cleaned up", session_id);
}

/// Validates revealed ranges against plaintext and hash ranges against exact commitments.
fn verify_reveal_config(
    reveal_config: &RevealConfig,
    transcript: &PartialTranscript,
    transcript_commitments: &[tlsn::transcript::TranscriptCommitment],
) -> Result<(), (String, usize, usize)> {
    use tlsn::transcript::Direction;

    for (ranges, auth_set, length, direction, label) in [
        (
            &reveal_config.sent,
            transcript.sent_authed(),
            transcript.len_sent(),
            Direction::Sent,
            "sent",
        ),
        (
            &reveal_config.recv,
            transcript.received_authed(),
            transcript.len_received(),
            Direction::Received,
            "recv",
        ),
    ] {
        for range in ranges {
            let valid = range.start < range.end
                && range.end <= length
                && matches!(
                    (direction, &range.handler.handler_type),
                    (Direction::Sent, HandlerType::Sent)
                        | (Direction::Received, HandlerType::Recv)
                )
                && (!matches!(range.handler.part, HandlerPart::All)
                    || (range.start == 0 && range.end == length))
                && match range.handler.action {
                    HandlerAction::Reveal => {
                        (range.start..range.end).all(|i| auth_set.contains(&i))
                    }
                    HandlerAction::Hash { algorithm } => find_hash_digest(
                        transcript_commitments,
                        direction,
                        range.start,
                        range.end,
                        algorithm,
                    )
                    .is_some(),
                };
            if !valid {
                return Err((label.to_string(), range.start, range.end));
            }
        }
    }
    Ok(())
}

// Helper function to clean up session from state
async fn cleanup_session(state: &Arc<AppState>, session_id: &str) {
    let mut sessions = state.sessions.lock().await;
    if sessions.remove(session_id).is_some() {
        info!("[{}] Session removed from state", session_id);
    }
}

/// Processes ranges and extracts values from the transcript.
///
/// - For REVEAL handlers, returns the revealed plaintext bytes as UTF-8.
/// - For HASH handlers, returns the hex-encoded hash digest from the matching
///   `TranscriptCommitment::Hash` (plaintext was never revealed).
fn process_ranges(
    ranges: &[RangeWithHandler],
    bytes: &[u8],
    direction: tlsn::transcript::Direction,
    transcript_commitments: &[tlsn::transcript::TranscriptCommitment],
    direction_label: &str,
    session_id: &str,
) -> Vec<HandlerResult> {
    ranges
        .iter()
        .map(|range_with_handler| {
            let value = match range_with_handler.handler.action {
                HandlerAction::Hash { algorithm } => find_hash_digest(
                    transcript_commitments,
                    direction,
                    range_with_handler.start,
                    range_with_handler.end,
                    algorithm,
                )
                .unwrap_or_else(|| {
                    format!(
                        "ERROR: No hash commitment for [{}, {})",
                        range_with_handler.start, range_with_handler.end
                    )
                }),
                HandlerAction::Reveal => {
                    if range_with_handler.start < bytes.len()
                        && range_with_handler.end <= bytes.len()
                        && range_with_handler.start < range_with_handler.end
                    {
                        let extracted_bytes =
                            &bytes[range_with_handler.start..range_with_handler.end];
                        String::from_utf8_lossy(extracted_bytes).to_string()
                    } else {
                        format!(
                            "ERROR: Invalid range [{}, {})",
                            range_with_handler.start, range_with_handler.end
                        )
                    }
                }
            };

            debug!(
                "[{}] Mapped {} range [{}, {}) to handler {:?}: {} bytes",
                session_id,
                direction_label,
                range_with_handler.start,
                range_with_handler.end,
                range_with_handler.handler.part,
                value.len()
            );

            HandlerResult {
                handler: range_with_handler.handler.clone(),
                value,
            }
        })
        .collect()
}

/// Finds the hash digest for an exact range, direction, and algorithm.
fn find_hash_digest(
    commitments: &[tlsn::transcript::TranscriptCommitment],
    direction: tlsn::transcript::Direction,
    start: usize,
    end: usize,
    algorithm: HashAlgorithm,
) -> Option<String> {
    use tlsn::hash::HashAlgId;
    use tlsn::transcript::TranscriptCommitment;

    if start >= end {
        return None;
    }
    let algorithm = match algorithm {
        HashAlgorithm::Blake3 => HashAlgId::BLAKE3,
        HashAlgorithm::Sha256 => HashAlgId::SHA256,
        HashAlgorithm::Keccak256 => HashAlgId::KECCAK256,
    };
    let idx = RangeSet::from(start..end);
    for commitment in commitments {
        if let TranscriptCommitment::Hash(hash) = commitment {
            if hash.direction == direction
                && hash.idx == idx
                && hash.hash.alg == algorithm
            {
                let bytes = hash.hash.value.as_bytes();
                let mut hex_str = String::with_capacity(bytes.len() * 2);
                for b in bytes {
                    use std::fmt::Write;
                    let _ = write!(hex_str, "{:02x}", b);
                }
                return Some(hex_str);
            }
        }
    }
    None
}


/// Send webhook POST request to configured endpoint
async fn send_webhook(config: &WebhookConfig, payload: &WebhookPayload, session_id: &str) {
    let client = reqwest::Client::new();

    let mut request = client.post(&config.url).json(payload);

    // Add custom headers from config
    for (key, value) in &config.headers {
        request = request.header(key, value);
    }

    match request.send().await {
        Ok(response) => {
            if response.status().is_success() {
                info!(
                    "[{}] ✅ Webhook POST successful: {}",
                    session_id, config.url
                );
            } else {
                error!(
                    "[{}] ❌ Webhook POST failed with status {}: {}",
                    session_id,
                    response.status(),
                    config.url
                );
            }
        }
        Err(e) => {
            // Log error but don't fail the verification
            error!(
                "[{}] ❌ Webhook POST error: {} - {}",
                session_id, config.url, e
            );
        }
    }
}
