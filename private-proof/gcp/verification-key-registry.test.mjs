import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import manifest from './generated/verification-keys.json' with { type: 'json' };
import { loadPinnedArtifacts } from './artifact-registry.mjs';
import { loadPinnedVerificationKeys, pinnedVerificationKey } from './verification-key-registry.mjs';
import { createProofRuntime } from './proof-runtime.mjs';

const read = file => readFile(new URL(`./dist/verification-keys/${file}`, import.meta.url));
const registry = await loadPinnedVerificationKeys(read);
assert.equal(Object.keys(manifest.circuits).length, 7);
for (const [id, pin] of Object.entries(manifest.circuits)) {
  assert.deepEqual(pinnedVerificationKey(registry, id), new Uint8Array(await read(pin.file)));
  const copy = pinnedVerificationKey(registry, id); copy.fill(0);
  assert.notDeepEqual(pinnedVerificationKey(registry, id), copy);
}
const error = { message: 'GCP_PRIVATE_VERIFICATION_KEY_INVALID' };
await assert.rejects(loadPinnedVerificationKeys(async file => {
  const bytes = await read(file); bytes[bytes.length >> 1] ^= 1; return bytes;
}), error);
await assert.rejects(loadPinnedVerificationKeys(async file => (await read(file)).subarray(1)), error);
await assert.rejects(loadPinnedVerificationKeys(async () => 'caller-key'), error);
await assert.rejects(loadPinnedVerificationKeys(async () => { throw new Error('missing-key'); }), { message: 'missing-key' });
assert.throws(() => pinnedVerificationKey({}, 'timestamps-v1'), error);
assert.throws(() => pinnedVerificationKey(registry, 'caller-circuit'), error);
const sources = [];
const owned = await loadPinnedVerificationKeys(async file => {
  const bytes = await read(file); sources.push(bytes); return bytes;
});
sources.forEach(bytes => bytes.fill(0));
assert.deepEqual(pinnedVerificationKey(owned, 'timestamps-v1'), pinnedVerificationKey(registry, 'timestamps-v1'));

// Simulate stale deployment metadata without accepting an externally supplied manifest.
for (const [object, key, value] of [
  [manifest, 'backend', 'caller-backend'],
  [manifest, 'compiler', 'caller-compiler'],
  [manifest, 'verifierTarget', 'noir-recursive-no-zk'],
  [manifest.circuits['timestamps-v1'], 'artifactSha256', '00'.repeat(32)],
  [manifest.circuits['timestamps-v1'], 'file', '../caller-key.vk'],
  [manifest, 'circuits', {}],
  [manifest, 'circuits', { ...manifest.circuits, 'caller-circuit': manifest.circuits['timestamps-v1'] }],
]) {
  const original = object[key]; object[key] = value;
  try { await assert.rejects(loadPinnedVerificationKeys(read), error); }
  finally { object[key] = original; }
}
const artifacts = await loadPinnedArtifacts(file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url)));
await assert.rejects(createProofRuntime(artifacts, { 'timestamps-v1': pinnedVerificationKey(registry, 'timestamps-v1') }), error);
console.log('Seven pinned keys loaded; corrupt/missing keys, altered bindings, caller registries and post-load mutations rejected.');
