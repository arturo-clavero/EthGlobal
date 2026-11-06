import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import variant from '../node_modules/@jitl/quickjs-ng-wasmfile-release-sync/dist/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const dependency = 'node_modules/@sebastianwessel/quickjs';
const upstream = join(here, '..');
const repair = root => spawnSync(process.execPath, [join(here, 'fix-quickjs-handles.mjs'), root], { encoding: 'utf8' });
const fixed = repair(upstream);
assert.equal(fixed.status, 0, fixed.stderr);

// Both module formats must release a callback's copied private arguments on success and error.
for (const format of ['esm', 'commonjs']) {
  const { loadQuickJs } = await import(`../${dependency}/dist/${format}/loadQuickJs.js`);
  const { runSandboxed } = await loadQuickJs(variant);
  for (let repeat = 0; repeat < 3; repeat++) {
    await runSandboxed(async ({ evalCode }) => {
      const result = await evalCode(`export default {
        filter: rows => rows.filter(row => row.ok),
        later: async rows => { await env.tick(); return rows[0]; },
        fail: row => { throw new Error('expected failure'); }
      };`);
      assert.equal(result.ok, true);
      const input = [{ ok: true, privateHeader: 'synthetic-private' }, { ok: false }];
      assert.deepEqual(result.data.filter.call({ privateOwner: 'synthetic-owner' }, input), [input[0]]);
      assert.deepEqual(await result.data.later(input), input[0]);
      assert.throws(() => result.data.fail(input), /expected failure/);
    }, { allowFetch: false, allowFs: false, env: { tick: () => new Promise(resolve => setTimeout(resolve, 0)) } });
    const resolved = await runSandboxed(({ evalCode }) => evalCode('export default Promise.resolve({ ok: true });'));
    assert.deepEqual(resolved, { ok: true, data: { ok: true } });
    const rejected = await runSandboxed(({ evalCode }) => evalCode("export default Promise.reject(new Error('expected rejection'));"));
    assert.equal(rejected.ok, false);
    assert.match(rejected.error.message, /expected rejection/);
  }
  console.log(`${format}: repeated object arguments, throws and settled promises release their QuickJS runtime`);
}

// Repeated builds accept only the exact original or repaired bridge and pinned version.
const fixture = await mkdtemp(join(tmpdir(), 'quickjs-ownership-'));
try {
  const target = join(fixture, dependency);
  await mkdir(target, { recursive: true });
  await writeFile(join(target, 'package.json'), JSON.stringify({ version: '3.0.1' }));
  for (const format of ['esm', 'commonjs']) {
    const relative = `dist/${format}/sandbox/handleToNative/handleToNative.js`;
    await mkdir(dirname(join(target, relative)), { recursive: true });
    await writeFile(join(target, relative), await readFile(join(upstream, dependency, relative)));
  }
  assert.equal(repair(fixture).status, 0);
  assert.equal(repair(fixture).status, 0);
  await writeFile(join(target, 'dist/commonjs/sandbox/handleToNative/handleToNative.js'), '// unexpected upstream change');
  assert.notEqual(repair(fixture).status, 0);
  await writeFile(join(target, 'package.json'), JSON.stringify({ version: '3.1.0' }));
  assert.notEqual(repair(fixture).status, 0);
} finally { await rm(fixture, { recursive: true, force: true }); }
console.log('repair: idempotent, rejects changed source and dependency versions');
