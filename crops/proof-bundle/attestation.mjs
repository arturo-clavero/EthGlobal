// Verifier attestations over a bundle commitment: Ed25519 through WebCrypto (Node 22+ and current browsers).
import { bundleCommitment, canonicalize, commitmentFields, sha256Hex } from './commitment.mjs';

export const ATTESTATION_TYPE = 'tlsn-attestation';
const HEX64 = /^[0-9a-f]{64}$/;
const KEY_ID = /^[0-9a-f]{32}$/;
const SIG = /^[A-Za-z0-9_-]{86}$/;
const CREDENTIALS = ['proof_of_human', 'passport'];
const KEYS = ['v', 'type', 'commitment', 'provider', 'claim', 'window', 'proofHash', 'vkHashes', 'coreDigest',
  'pluginSha256', 'issuedAt', 'expiresAt', 'humanCheck'];
const ED25519 = { name: 'Ed25519' };

const fail = reason => { throw new Error(`ATTESTATION_INVALID: ${reason}`); };
const subtle = () => globalThis.crypto.subtle;

function instant(value, name) {
  const date = value instanceof Date ? value : new Date(value);
  if ((typeof value !== 'string' && typeof value !== 'number' && !(value instanceof Date)) || Number.isNaN(date.getTime()) ||
      (typeof value === 'string' && date.toISOString() !== value)) fail(name);
  return date.toISOString();
}

function humanCheckShape(value) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Object.keys(value).sort().join() !== 'credential,scope' ||
      !CREDENTIALS.includes(value.credential) || value.scope !== 'per-job') fail('humanCheck');
  return { credential: value.credential, scope: 'per-job' };
}

/**
 * Builds the unsigned attestation for any evidence type. It carries the commitment fields (coarse claim, proof hash,
 * public pins) so anyone can recompute the commitment, never the proof or any personal data.
 */
export function createAttestation({ commitment, provider, claim, window, proofHash, vkHashes, coreDigest, pluginSha256,
  issuedAt, expiresAt, humanCheck } = {}) {
  if (typeof commitment !== 'string' || !HEX64.test(commitment)) fail('commitment');
  const fields = commitmentFields(Object.fromEntries(Object.entries({ provider, claim, window, proofHash, vkHashes, coreDigest,
    pluginSha256 }).filter(([, value]) => value !== undefined)));
  const issued = instant(issuedAt, 'issuedAt'), expires = instant(expiresAt, 'expiresAt');
  if (Date.parse(expires) <= Date.parse(issued)) fail('expiresAt');
  const attestation = { v: 1, type: ATTESTATION_TYPE, commitment, ...fields, issuedAt: issued, expiresAt: expires };
  const human = humanCheckShape(humanCheck);
  if (human) attestation.humanCheck = human;
  return attestation;
}

/** Re-validates an attestation read from an untrusted source and returns a clean copy. */
export function attestationShape(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('attestation');
  const extra = Object.keys(value).filter(key => !KEYS.includes(key));
  if (extra.length || value.v !== 1 || value.type !== ATTESTATION_TYPE) fail('attestation');
  const clean = createAttestation(value);
  if (clean.issuedAt !== value.issuedAt || clean.expiresAt !== value.expiresAt) fail('timestamps');
  return clean;
}

function pemBytes(pem, label) {
  const match = typeof pem === 'string' && pem.trim().match(new RegExp(`^-----BEGIN ${label}-----([A-Za-z0-9+/=\\s]+)-----END ${label}-----$`));
  if (!match) fail(`expected a ${label} PEM`);
  return Uint8Array.from(atob(match[1].replace(/\s+/g, '')), char => char.charCodeAt(0));
}

const base64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromBase64url = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));

async function keyIdFromSpki(spki) {
  return (await sha256Hex(new Uint8Array(spki))).slice(0, 32);
}

/** Stable id of a verifier key: the first 16 bytes (hex) of sha256 over its SPKI DER encoding. */
export async function verifierKeyId(publicKeyPem) {
  const spki = pemBytes(publicKeyPem, 'PUBLIC KEY');
  await subtle().importKey('spki', spki, ED25519, true, ['verify']);
  return keyIdFromSpki(spki);
}

async function checkCommitment(attestation) {
  const { v: _v, type: _type, commitment, issuedAt: _i, expiresAt: _e, humanCheck: _h, ...fields } = attestation;
  return commitment === await bundleCommitment(fields);
}

const message = (attestation, keyId) => new TextEncoder().encode(canonicalize({ ...attestation, verifierKeyId: keyId }));

/** Signs canonical JSON of the attestation plus the key id. The private key is a PKCS#8 Ed25519 PEM. */
export async function signAttestation(attestation, ed25519PrivateKeyPem) {
  const clean = attestationShape(attestation);
  if (!await checkCommitment(clean)) fail('commitment does not match its fields');
  const privateKey = await subtle().importKey('pkcs8', pemBytes(ed25519PrivateKeyPem, 'PRIVATE KEY'), ED25519, true, ['sign']);
  // A private OKP JWK carries its public point, so the key id needs no second input.
  const { x } = await subtle().exportKey('jwk', privateKey);
  const publicKey = await subtle().importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x }, ED25519, true, ['verify']);
  const keyId = await keyIdFromSpki(await subtle().exportKey('spki', publicKey));
  const sig = base64url(await subtle().sign(ED25519, privateKey, message(clean, keyId)));
  return { ...clean, verifierKeyId: keyId, sig };
}

/** Never throws. ok only for a well-formed, unexpired attestation signed by exactly this key. */
export async function verifyAttestation(signed, ed25519PublicKeyPem, { now = Date.now() } = {}) {
  let clean, keyId, publicKey;
  try {
    if (!signed || typeof signed !== 'object' || typeof signed.verifierKeyId !== 'string' || !KEY_ID.test(signed.verifierKeyId) ||
        typeof signed.sig !== 'string' || !SIG.test(signed.sig)) return { ok: false, reason: 'malformed' };
    const { verifierKeyId: _id, sig: _sig, ...rest } = signed;
    clean = attestationShape(rest);
  } catch { return { ok: false, reason: 'malformed' }; }
  try {
    const spki = pemBytes(ed25519PublicKeyPem, 'PUBLIC KEY');
    publicKey = await subtle().importKey('spki', spki, ED25519, false, ['verify']);
    keyId = await keyIdFromSpki(spki);
  } catch { return { ok: false, reason: 'bad-key' }; }
  if (keyId !== signed.verifierKeyId) return { ok: false, reason: 'key-mismatch' };
  if (!await checkCommitment(clean)) return { ok: false, reason: 'commitment-mismatch' };
  let valid = false;
  try { valid = await subtle().verify(ED25519, publicKey, fromBase64url(signed.sig), message(clean, keyId)); } catch { /* invalid */ }
  if (!valid) return { ok: false, reason: 'bad-signature' };
  if (Date.parse(clean.issuedAt) > now + 5 * 60 * 1000) return { ok: false, reason: 'not-yet-valid' };
  if (Date.parse(clean.expiresAt) <= now) return { ok: false, reason: 'expired' };
  return { ok: true };
}
