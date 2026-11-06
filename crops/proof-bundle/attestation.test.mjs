import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { createAttestation, signAttestation, verifierKeyId, verifyAttestation } from './attestation.mjs';
import { bundleCommitment } from './commitment.mjs';

const pem = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKey: publicKey.export({ type: 'spki', format: 'pem' }) };
};
const keys = pem(), other = pem();
const fields = { provider: 'aws', claim: 'aws:iam-role-trust-update:iam-user', window: 90, proofHash: 'c'.repeat(64),
  vkHashes: { 'aws-event-link-v1': 'a'.repeat(64) } };
const NOW = Date.parse('2026-11-06T12:00:00.000Z');
const attestation = async (extra = {}) => createAttestation({ ...fields, commitment: await bundleCommitment(fields),
  issuedAt: '2026-11-06T11:00:00.000Z', expiresAt: NOW + 86400000, ...extra });

test('a signed attestation verifies with its key and carries a stable key id', async () => {
  const signed = await signAttestation(await attestation({ humanCheck: { credential: 'passport', scope: 'per-job' } }), keys.privateKey);
  assert.equal(signed.verifierKeyId, await verifierKeyId(keys.publicKey));
  assert.equal(signed.expiresAt, '2026-11-07T12:00:00.000Z');
  assert.deepEqual(await verifyAttestation(signed, keys.publicKey, { now: NOW }), { ok: true });
  assert.deepEqual(await verifyAttestation(JSON.parse(JSON.stringify(signed)), keys.publicKey, { now: NOW }), { ok: true });
});

test('verification fails closed with a reason', async () => {
  const signed = await signAttestation(await attestation(), keys.privateKey);
  const reason = async (value, key = keys.publicKey, now = NOW) => (await verifyAttestation(value, key, { now })).reason;
  assert.equal(await reason(signed, other.publicKey), 'key-mismatch');
  assert.equal(await reason({ ...signed, claim: 'aws:other' }), 'commitment-mismatch');
  const swapped = { ...signed, window: 30, commitment: await bundleCommitment({ ...fields, window: 30 }) };
  assert.equal(await reason(swapped), 'bad-signature');
  assert.equal(await reason({ ...signed, email: 'a@b.c' }), 'malformed');
  assert.equal(await reason({ ...signed, sig: 'x' }), 'malformed');
  assert.equal(await reason(null), 'malformed');
  assert.equal(await reason(signed, 'not a pem'), 'bad-key');
  assert.equal(await reason(signed, keys.publicKey, NOW + 2 * 86400000), 'expired');
  assert.equal(await reason(signed, keys.publicKey, NOW - 86400000), 'not-yet-valid');
});

test('attestations reject inconsistent or personal fields before signing', async () => {
  await assert.rejects(signAttestation(await attestation({ commitment: 'f'.repeat(64) }), keys.privateKey), /ATTESTATION_INVALID/);
  await assert.rejects(async () => attestation({ humanCheck: { credential: 'passport', scope: 'per-job', nationality: 'x' } }),
    /ATTESTATION_INVALID/);
  await assert.rejects(async () => attestation({ expiresAt: '2026-11-06T10:00:00.000Z' }), /ATTESTATION_INVALID/);
  await assert.rejects(async () => attestation({ issuedAt: '2026-11-06' }), /ATTESTATION_INVALID/);
  await assert.rejects(async () => attestation({ claim: 'aws:Account 123456789012' }), /PROOF_BUNDLE_INVALID/);
});
