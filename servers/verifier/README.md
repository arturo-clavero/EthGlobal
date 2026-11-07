# TLSNotary Verifier Server

A Rust-based HTTP server with WebSocket support for TLSNotary verification operations.

## Features

- **Health Check Endpoint**: Simple `/health` endpoint that returns "ok" for monitoring
- **Verifier WebSocket**: WebSocket server at `/verifier` for TLSNotary verification
- **CORS Enabled**: Permissive CORS configuration for cross-origin requests
- **Async Runtime**: Built on Tokio for high-performance async operations
- **Logging**: Structured logging with tracing for debugging and monitoring
- **Error Handling**: Proper error handling and automatic cleanup on failure

## Dependencies

- **tlsn**: TLSNotary verification library
- **axum**: Modern web framework with WebSocket support
- **tokio**: Async runtime with full features
- **tokio-util**: Async utilities for stream compatibility
- **tower-http**: CORS middleware
- **tracing**: Structured logging and diagnostics
- **eyre**: Error handling and reporting

## Building

The server builds against the same pinned, patched TLSNotary core as the extension's WASM prover (mux backpressure,
several proofs on one session). Prepare it once at `core/tlsn` (the path `Cargo.toml` points at; it is git-ignored):

```bash
# From the repository root
bash core/prepare-core.sh "$PWD/core/tlsn"
```

```bash
# From the verifier package directory
cargo build

# For production release
cargo build --release
```

## Running

```bash
# Development mode
cargo run

# Production release
cargo run --release
```

The server will start on `0.0.0.0:7047` by default.

## API Endpoints

### Health Check

**GET** `/health`

Returns a simple "ok" response to verify the server is running.

**Example:**

```bash
curl http://localhost:7047/health
# Response: ok
```

### Create Session

**POST** `/session`

Creates a new verification session with specified data limits. Returns a session ID that can be used to connect to the verifier WebSocket.

**Request Body:**

```json
{
  "maxRecvData": 16384,
  "maxSentData": 4096
}
```

**Response:**

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Example:**

```bash
curl -X POST http://localhost:7047/session \
  -H "Content-Type: application/json" \
  -d '{"maxRecvData": 16384, "maxSentData": 4096}'
```

### Verifier WebSocket

**WS** `/verifier?sessionId=<session-id>`

Establishes a WebSocket connection for TLSNotary verification using a previously created session. Upon connection:

1. Validates the session ID exists
2. Retrieves maxRecvData and maxSentData from the session
3. Spawns a verifier with the configured limits
4. Performs TLS proof verification
5. Cleans up and removes the session when connection closes

**Query Parameters:**

- `sessionId` (required): Session ID returned from POST /session

**Error Responses:**

- `404 Not Found`: Session ID does not exist or has already been used

**Example using websocat:**

```bash
# First, create a session
SESSION_ID=$(curl -s -X POST http://localhost:7047/session \
  -H "Content-Type: application/json" \
  -d '{"maxRecvData": 16384, "maxSentData": 4096}' | jq -r '.sessionId')

# Then connect with the session ID
websocat "ws://localhost:7047/verifier?sessionId=$SESSION_ID"
```

**Example using JavaScript:**

```javascript
// Create a session first
const response = await fetch('http://localhost:7047/session', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ maxRecvData: 16384, maxSentData: 4096 }),
});
const { sessionId } = await response.json();

// Connect to verifier with session ID
const ws = new WebSocket(`ws://localhost:7047/verifier?sessionId=${sessionId}`);

ws.onopen = () => {
  console.log('Connected to verifier');
};

ws.onmessage = (event) => {
  console.log('Verification result:', event.data);
};

ws.onclose = () => {
  console.log('Verifier disconnected, session cleaned up');
};

ws.onerror = (error) => {
  console.error('Verification error:', error);
};
```

### Proof protocol on `/session`

The client sends `register`, then one `reveal_config` per proof **before** the prover's prove request: the
verifier checks each proof against the ranges announced for it.

- Results: a `REVEAL` range must lie in revealed plaintext; a `HASH` range must match a hash commitment of exactly
  that range, direction and algorithm, and its result is the commitment's hex digest. A hash-only proof (nothing
  revealed) is accepted. An `ALL` handler must cover the whole transcript of its direction.
- Several proofs on one session: `register` with `"multiReveal": true` gets `session_registered` with
  `"multiReveal": true` and may then prove the same transcript several times: per proof a `reveal_config` (from
  the second proof on with a `step`, `[A-Za-z0-9_-]{1,32}`), the prove request, then
  `reveal_completed {reveal, resultId, results}`. `{"type":"finish"}` (or the client closing, or 60 s without a
  further `reveal_config`) ends it with `session_closed {reveals}`. At most 64 proofs. Each proof is a result of
  its own (webhook shape unchanged): the first under the session id, each later one under a fresh UUID, its
  `sessionData` carrying the proof's `step`, `revealOf` (the session id) and `reveal` (0-based index); a client
  cannot set those two keys. The first proof proves the server identity; a later one may leave it out but may
  not name another server. A failed proof ends the session; earlier results stand. A client without
  `multiReveal` sees the upstream protocol (`session_completed`).
- The TLS connection, and then each proof, may take up to 300 s.

## Verifier Architecture

The verifier implementation follows this flow:

1. **Session Creation**: Client sends POST request to `/session` with maxRecvData and maxSentData
2. **Session Storage**: Server generates UUID, stores session config in HashMap
3. **WebSocket Connection**: Client connects to `/verifier?sessionId=<id>`
4. **Session Lookup**: Server validates session exists and retrieves configuration
5. **Task Spawning**: Server spawns async task with session-specific limits
6. **Verification Process**:
   - Uses maxRecvData and maxSentData from session config
   - Configures protocol validator with session limits
   - Creates verifier with TLSNotary config
   - Performs MPC-TLS verification
   - Validates server name and transcript data
7. **Error Handling**: Any errors are caught, logged, and cleaned up automatically
8. **Cleanup**: Session is removed from storage when WebSocket closes

### Session Management

- **Thread-safe storage**: Uses `Arc<Mutex<HashMap>>` for concurrent access
- **One-time use**: Sessions are automatically removed after WebSocket closes
- **Session isolation**: Each verifier gets independent maxRecvData/maxSentData limits
- **Error handling**: Invalid session IDs return 404 before WebSocket upgrade

**Note**: The current implementation logs all incoming WebSocket messages. Full verifier integration requires converting the axum WebSocket to AsyncRead/AsyncWrite format using the WsStream bridge.

## Configuration

The server configuration is currently hardcoded in `main.rs`:

- **Host**: `0.0.0.0` (all interfaces)
- **Port**: `7047`

To change these, modify the `SocketAddr::from()` call in `main.rs`.

Limits, read from the environment at start-up (a malformed value stops the server):

| Variable | Default | Effect |
|---|---|---|
| `TLSN_MAX_SESSIONS` | 20 | `/session` upgrades get 429 while this many sessions are active |
| `TLSN_MAX_RECV_DATA`, `TLSN_MAX_SENT_DATA` | none | a `register` declaring more bytes is refused |
| `TLSN_MAX_REVEAL_BLOCKS` | 2500 | a proof touching more 16-byte AES blocks (revealed and hash-committed ranges, per direction) is refused with `REVEAL_TOO_LARGE`, at `reveal_config` and again at the prove request, before the prove phase where verifier memory grows with the block count |
| `TLSN_MEMORY_BUDGET_MB` | 85% of the container's cgroup memory limit; none without a limit | memory-weighted admission: 64 MB per session at the `/session` upgrade (429 when full), then the step budget of its blocks (180 MB up to 120 blocks, 320 up to 400, 520 up to 820, 860 up to 1420, 1640 up to 2520) at `reveal_config` and at the prove request, waiting up to 30 s in a FIFO queue, else `VERIFIER_BUSY` (retryable). The reveal ceiling is lowered to what one session can be admitted with; at least 180 |

Refusals log one JSON line each (`tlsn.reveal.too_large`, `tlsn.admission`), counts only. A session holds its
reservation (the largest of its proofs) until it ends.

A new `/session` socket must send `register` within 30 s and its first `reveal_config` within 180 s.

## Development

### Adding New Routes

Add routes to the Router in `main.rs`:

```rust
let app = Router::new()
    .route("/health", get(health_handler))
    .route("/verifier", get(verifier_ws_handler))
    .route("/your-route", get(your_handler))  // Add here
    .layer(CorsLayer::permissive())
    .with_state(app_state);
```

### Project Structure

```
src/
├── main.rs       # Server setup, routing, and WebSocket handling
├── config.rs     # Configuration constants (MAX_SENT_DATA, MAX_RECV_DATA)
└── verifier.rs   # TLSNotary verification logic
```

### Extending Application State

Modify the `AppState` struct to share data between handlers:

```rust
struct AppState {
    // Add your shared state here
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}
```

## Integration with Extension

This server is designed to work with the TLSNotary browser extension located in `packages/extension`. The extension will connect to the WebSocket endpoint for verification operations.

## License

See the root LICENSE file for license information.
