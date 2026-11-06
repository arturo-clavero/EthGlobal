import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

// The pinned bridge leaks guest callback arguments and settled-promise result copies.
// Keep this repair until an upstream release fixes both ownership paths.
const root = join(process.argv[2], 'node_modules/@sebastianwessel/quickjs');
assert.equal(JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version, '3.0.1');
const hashes = {
  esm: ['b54a5d6741a39e7447ad45ad21c006f727f8f5e84e9a2c5b8fd8083b2fa2ff28', '1ca82341aa28f2efed92702a8d83fde2b65668ba33c88966be0d93ac03390f8e'],
  commonjs: ['7b05594c0f4770cd93bd7421991e4a6e80788fa01b0c7e495bed6400c7707407', 'c958d6681585713ccbde9246c480afd08e5bf820e2ef31ddeef7c9b9eadbe507'],
};
const sha256 = source => createHash('sha256').update(source).digest('hex');
const updates = [];
for (const [format, [before, after]] of Object.entries(hashes)) {
  const file = join(root, `dist/${format}/sandbox/handleToNative/handleToNative.js`);
  const source = await readFile(file, 'utf8');
  if (sha256(source) === after) continue;
  assert.equal(sha256(source), before, `Unrecognized QuickJS ${format} bridge; review ownership before rebuilding`);
  const fixed = source
    .replace("if (asPromiseState.type && !asPromiseState.notAPromise) {", `if (asPromiseState.type && !asPromiseState.notAPromise) {
        if (asPromiseState.type === 'fulfilled') asPromiseState.value.dispose();
        if (asPromiseState.type === 'rejected') asPromiseState.error.dispose();`)
    .replace(/(const scope = new (?:quickjs_emscripten_core_1\.)?Scope\(\);)\n/, '$1\n            try {\n')
    .replace(/const thisHandle = (.+);/, 'const thisHandle = scope.manage($1);')
    .replace(/const argHandles = args.map\(a => (.+)\);/, 'const argHandles = args.map(a => scope.manage($1));')
    .replace(/(const instance = .+\(ctx, )(.+\(ctx, 'internal\/serializer\/newClass.js'.+\)), rootScope\);/, '$1scope.manage($2), rootScope);')
    .replace('                scope.dispose();\n                return this;', '                return this;')
    .replace('            try {\n                const resultHandle', '                const resultHandle');
  assert.equal(sha256(fixed), after, `QuickJS ${format} repair did not match its reviewed output`);
  updates.push([file, fixed]);
}
// Validate both module formats before mutating either one.
for (const [file, fixed] of updates) await writeFile(file, fixed);
console.log(`QuickJS handle ownership checked (3.0.1; ${updates.length} files repaired)`);
