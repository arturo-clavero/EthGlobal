import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import pins from './generated/pins.json' with { type: 'json' };
import { loadAwsArtifacts, loadAwsVerificationKeys, pinnedAwsKey } from './artifact-registry.mjs';
import { createAwsProofRuntime } from './proof-runtime.mjs';
import { createProofRuntime } from '../gcp/proof-runtime.mjs';

const read = file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url));
const error = { message: 'AWS_PRIVATE_ARTIFACT_INVALID' };

test('loads ten pinned artifact/key pairs and owns verification key bytes', async () => {
  const artifacts = await loadAwsArtifacts(read), sources = [];
  const registry = await loadAwsVerificationKeys(async file => { const bytes = await read(file); sources.push(bytes); return bytes; });
  assert.equal(Object.keys(artifacts).length, 10);
  sources.forEach(bytes => bytes.fill(0));
  for (const [id, pin] of Object.entries(pins.circuits)) {
    assert.equal(artifacts[id].noir_version, pins.compiler);
    assert.deepEqual(pinnedAwsKey(registry, id), new Uint8Array(await read(pin.keyFile)));
    const copy = pinnedAwsKey(registry, id); copy.fill(0); assert.notDeepEqual(pinnedAwsKey(registry, id), copy);
  }
});

test('rejects corrupt, truncated and substituted artifacts or keys', async () => {
  for (const loader of [loadAwsArtifacts, loadAwsVerificationKeys]) {
    await assert.rejects(loader(async file => { const bytes = await read(file); bytes[bytes.length >> 1] ^= 1; return bytes; }), error);
    await assert.rejects(loader(async file => (await read(file)).subarray(1)), error);
    await assert.rejects(loader(async () => 'caller-data'), error);
    await assert.rejects(loader(async () => { throw new Error('missing'); }), { message: 'missing' });
  }
});

test('rejects stale compiler/backend/target, circuit policy and unsafe package paths', async () => {
  for (const [object, key, value] of [[pins, 'compiler', 'caller'], [pins, 'backend', 'caller'],
    [pins, 'verifierTarget', 'noir-recursive-no-zk'], [pins, 'circuits', {}],
    [pins, 'circuits', { ...pins.circuits, 'caller-v1': pins.circuits['atom-v1'] }],
    [pins.circuits['atom-v1'], 'file', '../caller.json'], [pins.circuits['atom-v1'], 'bytes', 10000001],
    [pins.circuits['atom-v1'], 'keyFile', '../caller.vk'], [pins.circuits['atom-v1'], 'keyBytes', 65537]]) {
    const old = object[key]; object[key] = value;
    try {
      const loader = key.startsWith('key') ? loadAwsVerificationKeys : loadAwsArtifacts;
      await assert.rejects(loader(read), error);
    } finally { object[key] = old; }
  }
});

test('requires the packaged AWS key registry and preserves the GCP circuit allowlist', async () => {
  const artifacts = await loadAwsArtifacts(read), keys = await loadAwsVerificationKeys(read);
  for (const forged of [undefined, {}, { 'aws-event-link-v1': pinnedAwsKey(keys, 'aws-event-link-v1') }]) {
    await assert.rejects(createAwsProofRuntime(artifacts, forged), error);
  }
  assert.throws(() => pinnedAwsKey(keys, 'timestamps-v1'), error);
  await assert.rejects(createProofRuntime(artifacts), { message: 'GCP_PRIVATE_PROOF_INVALID' });
  await assert.rejects(createAwsProofRuntime({ 'timestamps-v1': artifacts['atom-v1'] }, keys), { message: 'AWS_PRIVATE_PROOF_INVALID' });
});
