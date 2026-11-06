import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js';

const compiler = '1.0.0-beta.19+74d6be658e1ad252f87943292ba09bdd4da80bd4';
const nargo = process.env.AZURE_NOIR_NARGO || 'nargo';
const version = spawnSync(nargo, ['--version'], { encoding: 'utf8' });
assert.equal(version.status, 0, 'Set AZURE_NOIR_NARGO to the pinned compiler.');
assert.ok(version.stdout.includes(`noirc version = ${compiler}\n`) && version.stdout.includes('is dirty: false'));
const target = 'noir-recursive';
const manifest = new URL('./generated/artifacts.json', import.meta.url);
const selected = process.argv.find(value => value.startsWith('--circuit='))?.slice('--circuit='.length);
const previous = JSON.parse(await readFile(manifest, 'utf8'));
const pins = selected ? structuredClone(previous) : { compiler, verifierTarget: target, circuits: {} };
assert.equal(pins.compiler, compiler); assert.equal(pins.verifierTarget, target);
const circuits = [
  ['identity-v1', './circuits/identity/', 'azure_private_identity'],
  ['header-v1', '../gcp/circuits/header/', 'gcp_private_header'],
  ['identity-link-v1', './circuits/identity-link/', 'azure_private_identity_link'],
  ['scope-link-v1', './circuits/scope-link/', 'azure_private_scope_link'],
  ['activity-atoms-v1', './circuits/activity-atoms/', 'azure_private_activity_atoms'],
  ['catalog-activity-atoms-v1', './circuits/catalog-activity-atoms/', 'azure_private_catalog_activity_atoms'],
  ['claims-chunk-v1', './circuits/claims-chunk/', 'azure_private_claims_chunk'],
  ['arg-delta-v1', './circuits/arg-delta/', 'azure_private_arg_delta'],
  ['arg-link-v1', './circuits/arg-link/', 'azure_private_arg_link'],
  ['request-uuid-v1', './circuits/request-uuid/', 'azure_private_request_uuid'],
  ['subscription-state-v1', './circuits/subscription-state/', 'azure_private_subscription_state'],
  ['atom-v1', '../gcp/circuits/atom/', 'gcp_private_atom'],
  ['atoms-small-v1', '../gcp/circuits/atoms-small/', 'gcp_private_atoms_small'],
  ['headers-small-v1', '../gcp/circuits/headers-small/', 'gcp_private_headers_small'],
  ['tenant-extra-v1', './circuits/tenant-extra/', 'azure_private_tenant_extra'],
];
if (selected !== undefined) assert.ok(circuits.some(([id]) => id === selected), 'Unknown circuit');
await mkdir(new URL('./dist/', import.meta.url), { recursive: true });
for (const [id, path, name] of circuits) {
  if (selected && id !== selected) continue;
  const directory = new URL(path, import.meta.url);
  const result = spawnSync(nargo, ['compile', '--silence-warnings'], { cwd: fileURLToPath(directory), encoding: 'utf8', timeout: 120000 });
  assert.equal(result.status, 0, `Compilation failed for ${id}: ${result.stderr}`);
  const compiled = JSON.parse(await readFile(new URL(`target/${name}.json`, directory), 'utf8'));
  assert.equal(compiled.noir_version, compiler);
  const bytes = JSON.stringify({ noir_version: compiled.noir_version, abi: compiled.abi, bytecode: compiled.bytecode }) + '\n';
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1, memory: { maximum: 32768 } });
  let key;
  try { key = await new UltraHonkBackend(compiled.bytecode, api).getVerificationKey({ verifierTarget: target }); }
  finally { await api.destroy(); }
  const keySha256 = createHash('sha256').update(key).digest('hex');
  const artifactFile = `${id}-${sha256}.json`, keyFile = `${id}-${keySha256}.key`;
  await writeFile(new URL(`./dist/${artifactFile}`, import.meta.url), bytes);
  await writeFile(new URL(`./dist/${keyFile}`, import.meta.url), key);
  pins.circuits[id] = { artifactFile, sha256, keyFile, keySha256 };
}
if (process.argv.includes('--update-pins')) {
  await mkdir(new URL('./generated/', import.meta.url), { recursive: true });
  await writeFile(manifest, JSON.stringify(pins, null, 2) + '\n');
} else assert.deepEqual(pins, previous, 'Review changed circuits before updating their pins.');
console.log(`Built ${selected || 'all'} pinned Azure ZK artifacts and verification keys serially.`);
