/**
 * How long the prover may wait for one request/response to the target server.
 *
 * Proxy mode: the prover talks to the server over the verifier's session mux, gated by
 * post-handshake proof-batch synchronization. A single large reveal step can take
 * minutes for large reveal batches, so a 20 s send timeout would abort a correct, in-progress proof as
 * TIMEOUT. 300 s keeps real hangs bounded while leaving headroom for those batches.
 *
 * MPC mode: the request goes through a websockify channel and the MPC-TLS handshake is
 * much slower; keep upstream's 60 s.
 */
export const MPC_SEND_REQUEST_TIMEOUT_MS = 60_000;
export const PROXY_SEND_REQUEST_TIMEOUT_MS = 300_000;

/** The send timeout for a request; `proxyUrl` is set only in MPC mode (the websockify target). */
export function sendRequestTimeoutMs(proxyUrl: string | undefined): number {
  return proxyUrl ? MPC_SEND_REQUEST_TIMEOUT_MS : PROXY_SEND_REQUEST_TIMEOUT_MS;
}
