// Backend side: signs the rp_context and verifies IDKit results with World's Developer Portal.
import { hashSignal } from '@worldcoin/idkit-core/hashing';
import { signRequest } from '@worldcoin/idkit-core/signing';
import { CREDENTIALS } from './client.mjs';

const VERIFY_URL = 'https://developer.world.org/api/v4/verify/';
const fail = reason => { throw new Error(`PERSONHOOD_INVALID: ${reason}`); };

/** rp_context for IDKit.request. signingKeyHex comes from an env var and never leaves the backend. */
export function signRpContext({ rpId, action, signingKeyHex, ttl } = {}, { sign = signRequest } = {}) {
  if (typeof rpId !== 'string' || !/^rp_[A-Za-z0-9_]+$/.test(rpId)) fail('rpId');
  if (typeof action !== 'string' || !/^apply:[A-Za-z0-9_-]{1,64}$/.test(action)) fail('action');
  if (typeof signingKeyHex !== 'string' || !signingKeyHex) fail('signingKeyHex');
  const { sig, nonce, createdAt, expiresAt } = sign({ signingKeyHex, action, ...(ttl === undefined ? {} : { ttl }) });
  return { rp_id: rpId, nonce, created_at: createdAt, expires_at: expiresAt, signature: sig };
}

/**
 * Checks the result is for this action, environment and commitment, then forwards it unchanged to World's verify API.
 * Returns { ok, nullifier, credential } or { ok: false, reason }. Store the nullifier privately, unique per job;
 * never publish it.
 */
export async function verifyWorldIdResult(result, { rpId, action, signal, environment = 'production', fetch = globalThis.fetch } = {}) {
  if (typeof rpId !== 'string' || !/^rp_[A-Za-z0-9_]+$/.test(rpId)) fail('rpId');
  if (result?.protocol_version !== '4.0' || !Array.isArray(result.responses) || !result.responses.length) return { ok: false, reason: 'malformed' };
  if (result.action !== action) return { ok: false, reason: 'action-mismatch' };
  if (result.environment !== environment) return { ok: false, reason: 'environment-mismatch' };
  if (signal !== undefined) {
    const expected = hashSignal(signal);
    if (result.responses.some(item => item?.signal_hash !== expected)) return { ok: false, reason: 'signal-mismatch' };
  }
  if (result.responses.some(item => !CREDENTIALS.includes(item?.identifier))) return { ok: false, reason: 'credential-not-allowed' };
  let response, body;
  try {
    response = await fetch(`${VERIFY_URL}${encodeURIComponent(rpId)}`, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(result) });
    body = await response.json();
  } catch { return { ok: false, reason: 'unavailable' }; }
  if (!response.ok || body?.success !== true || body.environment !== environment) return { ok: false, reason: body?.code ?? 'rejected' };
  const passed = (Array.isArray(body.results) ? body.results : []).find(item => item?.success === true && CREDENTIALS.includes(item.identifier));
  const nullifier = passed?.nullifier ?? body.nullifier;
  const credential = passed?.identifier ?? (result.responses.length === 1 ? result.responses[0].identifier : undefined);
  if (typeof nullifier !== 'string' || !/^0x[0-9a-f]+$/i.test(nullifier) || !credential) return { ok: false, reason: 'no-nullifier' };
  return { ok: true, nullifier: nullifier.toLowerCase(), credential };
}
