import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { canonicalize } from './commitment.mjs';
import { fromVerifiedBundle, proofHash, publicBundle, vkHashesFor } from './cloud.mjs';

const json = path => JSON.parse(readFileSync(new URL(path, import.meta.url)));
const gcpPins = json('../../private-proof/gcp/generated/verification-keys.json');
const awsPins = json('../../private-proof/aws/generated/pins.json');
const entry = (circuitId, inputs = ['1', '0x2']) => ({ circuitId, proof: 'AAAA', publicInputs: inputs });
const SESSIONS = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002'];
const gcp = { kind: 'GCP_PRIVATE_RESULT', version: 1, sessionIds: SESSIONS,
  proofs: [entry('identity-scope-v1'), entry('timestamps-v1'), entry('timestamps-v1', ['3'])] };
const aws = { kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: SESSIONS,
  proofs: [entry('aws-identity-link-v1'), entry('aws-event-link-v1')] };

test('proof hash covers exactly the proofs and public inputs, not session routing ids', async () => {
  const expected = createHash('sha256').update(canonicalize({ kind: gcp.kind, version: 1, proofs: gcp.proofs })).digest('hex');
  assert.equal(await proofHash(gcp), expected);
  assert.equal(await proofHash({ ...gcp, sessionIds: [] }), expected);
  assert.notEqual(await proofHash({ ...gcp, proofs: [...gcp.proofs].reverse() }), expected);
  assert.equal('sessionIds' in publicBundle(gcp), false);
  for (const bad of [{ ...gcp, kind: 'X' }, { ...gcp, proofs: [] }, { ...gcp, proofs: [entry('atom-v1', [1])] },
    { ...gcp, proofs: [{ ...entry('atom-v1'), proof: 'not base64!' }] }])
    await assert.rejects(proofHash(bad), /PROOF_BUNDLE_INVALID/);
});

test('vk hashes come from the pinned key manifests, not the circuit artifacts', () => {
  assert.deepEqual(vkHashesFor(gcp, gcpPins), { 'identity-scope-v1': gcpPins.circuits['identity-scope-v1'].sha256,
    'timestamps-v1': gcpPins.circuits['timestamps-v1'].sha256 });
  assert.equal(vkHashesFor(aws, awsPins)['aws-event-link-v1'], awsPins.circuits['aws-event-link-v1'].keySha256);
  assert.throws(() => vkHashesFor(aws, gcpPins), /no pinned key/);
});

test('gcp claim lists observed groups only; aws claim is the fixed coarse task', async () => {
  const groups = [{ id: 'g10', status: 'observed' }, { id: 'g2', status: 'observed' }, { id: 'g3', status: 'empty' },
    { id: 'g4', status: 'denied' }];
  const fields = await fromVerifiedBundle('gcp', gcp, { catalogDigest: 'x', policy: { cutoff: 1, windowDays: 30 }, groups },
    { pins: gcpPins, pluginSha256: 'e'.repeat(64) });
  assert.equal(fields.claim, 'gcp:observed:g2,g10');
  assert.equal(fields.window, 30);
  assert.equal(fields.pluginSha256, 'e'.repeat(64));
  assert.equal((await fromVerifiedBundle('gcp', gcp, { policy: { windowDays: 7 }, groups: [] }, { pins: gcpPins })).claim,
    'gcp:observed:none');
  const awsFields = await fromVerifiedBundle('aws', aws, { taskType: 'iam-role-trust-update', attribution: 'iam-user', windowDays: 90 },
    { pins: awsPins });
  assert.equal(awsFields.claim, 'aws:iam-role-trust-update:iam-user');
  await assert.rejects(fromVerifiedBundle('aws', gcp, {}, { pins: awsPins }), /does not match/);
  await assert.rejects(fromVerifiedBundle('gcp', gcp, { policy: { windowDays: 30 }, groups: [{ id: 'my-project', status: 'observed' }] },
    { pins: gcpPins }), /gcp group/);
});
