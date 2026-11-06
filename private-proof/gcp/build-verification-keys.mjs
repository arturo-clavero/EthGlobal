import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { findPackageJSON } from 'node:module';
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js';
import { loadPinnedArtifacts } from './artifact-registry.mjs';
import artifactPins from './generated/artifacts.json' with { type: 'json' };
import packageInfo from './package.json' with { type: 'json' };

const backend = packageInfo.dependencies['@aztec/bb.js'];
const installed = JSON.parse(await readFile(findPackageJSON('@aztec/bb.js', import.meta.url), 'utf8'));
assert.equal(installed.version, backend, 'Install the pinned Barretenberg version before building keys.');
assert.equal(artifactPins.verifierTarget, 'noir-recursive', 'Verification keys must use the ZK target.');
const artifacts = await loadPinnedArtifacts(file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url)));
const pins = { backend, compiler: artifactPins.compiler, verifierTarget: 'noir-recursive', circuits: {} };
const output = [];
const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 2, memory: { maximum: 32768 } });
try {
  for (const [id, artifact] of Object.entries(artifacts)) {
    const started = performance.now();
    const bytes = await new UltraHonkBackend(artifact.bytecode, api).getVerificationKey({ verifierTarget: pins.verifierTarget });
    assert.ok(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= 65536);
    const sha256 = createHash('sha256').update(bytes).digest('hex'), file = `${id}-${sha256}.vk`;
    pins.circuits[id] = { artifactSha256: artifactPins.circuits[id].sha256, file, sha256, bytes: bytes.length };
    output.push({ file, bytes });
    console.log(JSON.stringify({ circuitId: id, keyBytes: bytes.length, buildMs: Math.round(performance.now() - started) }));
  }
} finally { await api.destroy(); }
const manifestPath = new URL('./generated/verification-keys.json', import.meta.url);
if (process.argv.includes('--update-pins')) await writeFile(manifestPath, JSON.stringify(pins, null, 2) + '\n');
else assert.deepEqual(pins, JSON.parse(await readFile(manifestPath, 'utf8')), 'Verification key changed: review it before --update-pins.');
await mkdir(new URL('./dist/verification-keys/', import.meta.url), { recursive: true });
for (const { file, bytes } of output) await writeFile(new URL(`./dist/verification-keys/${file}`, import.meta.url), bytes);
console.log(`Built ${output.length} pinned verification keys (${output.reduce((n, key) => n + key.bytes.length, 0)} bytes).`);
