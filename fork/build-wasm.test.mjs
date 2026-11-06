import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { patchSpawnSnippet, stagePackage, validatePackage } from './build-wasm.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const files = ['package.json', 'tlsn_wasm.js', 'tlsn_wasm_bg.wasm', 'tlsn_wasm.d.ts',
  'tlsn_wasm_bg.wasm.d.ts', 'spawn.js', 'snippets/web-spawn-fixture/js/spawn.js'];
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'tlsn-wasm-guard-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = join(root, 'source'), upstream = join(root, 'upstream');
  mkdirSync(join(source, 'snippets/web-spawn-fixture/js'), { recursive: true });
  mkdirSync(join(upstream, 'packages/extension/node_modules'), { recursive: true });
  for (const name of files) writeFileSync(join(source, name), `fixture:${name}`);
  writeFileSync(join(source, 'package.json'), JSON.stringify({ name: 'tlsn-wasm', version: 'fixture',
    type: 'module', main: 'tlsn_wasm.js', types: 'tlsn_wasm.d.ts', sideEffects: ['./snippets/*'] }));
  const inputs = { source: 'fixed-source', patch: 'fixed-patch' }, inputHash = sha(JSON.stringify(inputs));
  const pins = { packageVersion: 'fixture', publicTypesSha256: sha(readFileSync(join(source, 'tlsn_wasm.d.ts'))) };
  const seal = () => writeFileSync(join(source, 'fork-wasm-provenance.json'), JSON.stringify({ schema: 1, inputs, inputHash,
    files: Object.fromEntries(files.map(name => [name, sha(readFileSync(join(source, name)))])) }));
  seal();
  return { root, source, upstream, inputs, inputHash, pins, seal,
    target: join(upstream, 'packages/extension/node_modules/tlsn-wasm') };
}

test('stages the complete verified package and replaces stale generated files together', t => {
  const f = fixture(t); mkdirSync(f.target); writeFileSync(join(f.target, 'stale.js'), 'old');
  stagePackage(f.source, f.upstream, f.inputHash, f.pins);
  assert.equal(validatePackage(f.target, f.inputHash, f.pins).inputHash, f.inputHash);
  assert(!readdirSync(f.target).includes('stale.js'));
  assert.deepEqual(readFileSync(join(f.target, 'spawn.js')), readFileSync(join(f.source, 'spawn.js')));
});

test('rejects a tampered cached WASM before replacing the installed package', t => {
  const f = fixture(t); mkdirSync(f.target); writeFileSync(join(f.target, 'old.js'), 'preserve');
  writeFileSync(join(f.source, 'tlsn_wasm_bg.wasm'), 'tampered');
  assert.throws(() => stagePackage(f.source, f.upstream, f.inputHash, f.pins), /WASM_PACKAGE_HASH/);
  assert.equal(readFileSync(join(f.target, 'old.js'), 'utf8'), 'preserve');
});

test('rejects a stale recipe or changed provenance inputs', t => {
  const f = fixture(t);
  assert.throws(() => validatePackage(f.source, 'different-input', f.pins), /WASM_PROVENANCE_INPUT/);
  f.inputs.patch = 'changed'; f.seal();
  assert.throws(() => validatePackage(f.source, f.inputHash, f.pins), /WASM_PROVENANCE_INPUT_HASH/);
});

test('rejects changed public ABI even with internally consistent package hashes', t => {
  const f = fixture(t); writeFileSync(join(f.source, 'tlsn_wasm.d.ts'), 'changed API'); f.seal();
  assert.throws(() => validatePackage(f.source, f.inputHash, f.pins), /WASM_PUBLIC_ABI_CHANGED/);
});

test('rejects extra and missing generated files', t => {
  const f = fixture(t); writeFileSync(join(f.source, 'unexpected.js'), 'extra');
  assert.throws(() => validatePackage(f.source, f.inputHash, f.pins), /WASM_PACKAGE_FILE_SET/);
  rmSync(join(f.source, 'unexpected.js')); rmSync(join(f.source, 'spawn.js'));
  assert.throws(() => validatePackage(f.source, f.inputHash, f.pins), /WASM_PACKAGE_FILE_SET/);
});

test('rejects source package and nested snippet symlinks', t => {
  const f = fixture(t), link = join(f.root, 'source-link'); symlinkSync(f.source, link);
  assert.throws(() => validatePackage(link, f.inputHash, f.pins), /WASM_PACKAGE_SYMLINK/);
  symlinkSync(join(f.source, 'spawn.js'), join(f.source, 'snippets/web-spawn-fixture/js/extra.js'));
  assert.throws(() => validatePackage(f.source, f.inputHash, f.pins), /WASM_PACKAGE_SYMLINK/);
});

test('refuses installed-package symlinks, including broken links', t => {
  const f = fixture(t); symlinkSync(f.source, f.target);
  assert.throws(() => stagePackage(f.source, f.upstream, f.inputHash, f.pins), /WASM_STAGE_SYMLINK/);
  rmSync(f.target); symlinkSync(join(f.root, 'missing'), f.target);
  assert.throws(() => stagePackage(f.source, f.upstream, f.inputHash, f.pins), /WASM_STAGE_SYMLINK/);
});

test('refuses a node_modules ancestor redirected outside the upstream checkout', t => {
  const f = fixture(t), parent = join(f.upstream, 'packages/extension/node_modules'), outside = join(f.root, 'outside');
  mkdirSync(outside); rmSync(parent, { recursive: true }); symlinkSync(outside, parent);
  assert.throws(() => stagePackage(f.source, f.upstream, f.inputHash, f.pins), /WASM_STAGE_OUTSIDE_UPSTREAM/);
  assert.deepEqual(readdirSync(outside), []);
});

test('rejects a package entry point drift with otherwise valid hashes', t => {
  const f = fixture(t), file = join(f.source, 'package.json'), pkg = JSON.parse(readFileSync(file, 'utf8'));
  pkg.main = 'unexpected.js'; writeFileSync(file, JSON.stringify(pkg)); f.seal();
  assert.throws(() => validatePackage(f.source, f.inputHash, f.pins), /WASM_PACKAGE_ENTRY/);
});

test('patches both pinned worker imports and rejects a changed upstream import contract', () => {
  const original = "const spawner = await import('../../..');\nconst worker = await import('../../..');\n";
  assert.equal(patchSpawnSnippet(original),
    "const spawner = await import('../../../tlsn_wasm.js');\nconst worker = await import('../../../tlsn_wasm.js');\n");
  assert.throws(() => patchSpawnSnippet(original.replaceAll("../../..", "../../../")), /WASM_SPAWN_IMPORT_CHANGED/);
  assert.throws(() => patchSpawnSnippet(original + "await import('../../..');"), /WASM_SPAWN_IMPORT_CHANGED/);
});
