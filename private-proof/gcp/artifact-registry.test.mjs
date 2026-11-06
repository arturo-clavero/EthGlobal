import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { loadPinnedArtifacts } from './artifact-registry.mjs';

const read = file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url));
const artifacts = await loadPinnedArtifacts(read);
assert.equal(Object.keys(artifacts).length, 7);
for (const artifact of Object.values(artifacts)) {
  assert.deepEqual(Object.keys(artifact).sort(), ['abi', 'bytecode', 'noir_version']);
  assert.equal(typeof artifact.bytecode, 'string');
}
await assert.rejects(loadPinnedArtifacts(async file => {
  const bytes = await read(file); bytes[bytes.length >> 1] ^= 1; return bytes;
}), { message: 'GCP_PRIVATE_ARTIFACT_INVALID' });
await assert.rejects(loadPinnedArtifacts(async file => (await read(file)).subarray(1)),
  { message: 'GCP_PRIVATE_ARTIFACT_INVALID' });
await assert.rejects(loadPinnedArtifacts(async () => '{}'), { message: 'GCP_PRIVATE_ARTIFACT_INVALID' });
console.log('Seven pinned artifacts loaded; altered, truncated and non-byte artifacts rejected.');
