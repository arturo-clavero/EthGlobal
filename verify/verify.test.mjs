import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { BATCHES } from '../private-proof/gcp/policy.mjs';
import { bundleCommitment, createAttestation, fromVerifiedBundle, signAttestation, verifierKeyId } from '../crops/proof-bundle/index.mjs';
import { describeClaim, parseDropped, verifyCommitment } from './verify.mjs';

const loadJson = async path => JSON.parse(await readFile(new URL(path, import.meta.url)));
const pins = await loadJson('../private-proof/gcp/generated/verification-keys.json');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const pem = { privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKey: publicKey.export({ type: 'spki', format: 'pem' }) };
const keys = { keys: [{ id: await verifierKeyId(pem.publicKey), label: 'test verifier', publicKeyPem: pem.publicKey }] };
const NOW = Date.parse('2026-11-06T12:00:00.000Z');

// One timestamps-v1 proof per batch; group slot 1 of batch 0 is observed. Proof bytes are placeholders.
const timestamps = batch => Array.from({ length: 200 }, (_, index) =>
  index === 192 + 1 && batch === 0 ? '24' : index === 198 ? '1793900000000' : index === 199 ? '30' : '0');
const bundle = { kind: 'GCP_PRIVATE_RESULT', version: 1, proofs: [
  { circuitId: 'identity-scope-v1', proof: 'AAAA', publicInputs: ['1'] },
  ...BATCHES.map((_, batch) => ({ circuitId: 'timestamps-v1', proof: 'AAAA', publicInputs: timestamps(batch) }))] };
const groups = BATCHES.flatMap(batch => batch.groupIds.map(id => ({ id, status: 'empty' })));
groups.find(group => group.id === BATCHES[0].groupIds[1]).status = 'observed';

async function published(claimOverride) {
  const fields = await fromVerifiedBundle('gcp', bundle, { policy: { windowDays: 30 }, groups }, { pins });
  if (claimOverride) fields.claim = claimOverride;
  const commitment = await bundleCommitment(fields);
  const signed = await signAttestation(createAttestation({ ...fields, commitment, issuedAt: NOW - 1000, expiresAt: NOW + 86400000 }), pem.privateKey);
  return { commitment, signed };
}
const registry = (attestations, bundleJson) => ({
  findAttestations: async () => attestations,
  findBundle: async () => bundleJson ? { json: bundleJson, proofHash: 'x' } : null,
});
const run = (commitment, attestations, bundleJson, extra = {}) => verifyCommitment({ commitment, keys, loadJson, gcpBatches: BATCHES,
  now: NOW, registry: registry(attestations, bundleJson), ...extra });

test('a published attestation and bundle verify end to end and the claim is recomputed from public inputs', async () => {
  const { commitment, signed } = await published();
  const result = await run(commitment, [signed], JSON.stringify(bundle));
  assert.equal(result.status, 'verified');
  assert.ok(result.checks.every(check => check.ok), JSON.stringify(result.checks));
  assert.equal(result.checks.length, 4);
  assert.equal(describeClaim(result), 'Google Cloud: activity observed in 1 skill group(s) in the last 30 days.');
});

test('a signature over a claim the public inputs do not support fails', async () => {
  const { commitment, signed } = await published(`gcp:observed:${BATCHES[0].groupIds[1]},${BATCHES[1].groupIds[0]}`);
  const result = await run(commitment, [signed], JSON.stringify(bundle));
  assert.equal(result.status, 'failed');
  assert.deepEqual(result.checks.filter(check => !check.ok).map(check => check.label), ['Claim matches the proven public inputs']);
});

test('a swapped bundle, unknown key or missing data never shows verified', async () => {
  const { commitment, signed } = await published();
  const other = { ...bundle, proofs: bundle.proofs.slice(0, -1) };
  assert.equal((await run(commitment, [signed], JSON.stringify(other))).status, 'failed');
  assert.equal((await run(commitment, [signed], null)).status, 'signature-only');
  assert.equal((await run(commitment, [], null)).status, 'not-found');
  assert.equal((await run(commitment, [signed], null, { keys: { keys: [] } })).status, 'failed');
  assert.equal((await run('f'.repeat(64), [signed], JSON.stringify(bundle))).status, 'failed');
  await assert.rejects(run('nope', [signed], null), /64-character/);
});

test('a dropped attestation plus bundle file verifies without arkiv', async () => {
  const { commitment, signed } = await published();
  const dropped = parseDropped(JSON.stringify({ attestation: signed, bundle }));
  const result = await run(undefined, [], null, { dropped, registry: registry([], null) });
  assert.equal(result.commitment, commitment);
  assert.equal(result.status, 'verified');
  assert.throws(() => parseDropped('{"hello":1}'), /Unrecognised/);
});
