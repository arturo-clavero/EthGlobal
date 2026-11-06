import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const compiler = '1.0.0-beta.19+74d6be658e1ad252f87943292ba09bdd4da80bd4';
const nargo = process.env.GCP_NOIR_NARGO || 'nargo';
const version = spawnSync(nargo, ['--version'], { encoding: 'utf8' });
assert.equal(version.status, 0, 'Install the pinned Noir compiler or set GCP_NOIR_NARGO.');
assert.ok(version.stdout.includes(`noirc version = ${compiler}\n`), 'Wrong Noir compiler.');
assert.ok(version.stdout.includes('is dirty: false'), 'A modified Noir compiler is not accepted.');
const names = ['header', 'atom', 'headers-small', 'atoms-small', 'timestamps', 'identity-scope', 'query-scope'];
const pins = { compiler, verifierTarget: 'noir-recursive', circuits: {} };
const output = [];
for (const name of names) {
  const directory = new URL(`./circuits/${name}/`, import.meta.url);
  // Compile serially: one proof/build lane protects developer machines from memory spikes.
  const result = spawnSync(nargo, ['compile'], { cwd: fileURLToPath(directory), encoding: 'utf8', timeout: 120000 });
  assert.equal(result.status, 0, `Compilation failed for ${name}: ${result.stderr}`);
  const compiled = JSON.parse(await readFile(new URL(`target/gcp_private_${name.replaceAll('-', '_')}.json`, directory), 'utf8'));
  assert.equal(compiled.noir_version, compiler);
  // Debug maps contain build-machine paths and are unnecessary for executing the circuit.
  const bytes = JSON.stringify({ noir_version: compiled.noir_version, abi: compiled.abi, bytecode: compiled.bytecode }) + '\n';
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const id = `${name}-v1`, file = `${id}-${sha256}.json`;
  pins.circuits[id] = { file, sha256, bytes: Buffer.byteLength(bytes) };
  output.push({ file, bytes });
}
const manifestPath = new URL('./generated/artifacts.json', import.meta.url);
if (process.argv.includes('--update-pins')) await writeFile(manifestPath, JSON.stringify(pins, null, 2) + '\n');
else assert.deepEqual(pins, JSON.parse(await readFile(manifestPath, 'utf8')), 'Circuit changed: review it and rebuild with --update-pins.');
await mkdir(new URL('./dist/artifacts/', import.meta.url), { recursive: true });
for (const { file, bytes } of output) await writeFile(new URL(`./dist/artifacts/${file}`, import.meta.url), bytes);
console.log(`Built ${output.length} pinned ZK circuit artifacts (${output.reduce((n, file) => n + file.bytes.length, 0)} bytes).`);
