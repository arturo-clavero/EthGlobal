// Regenerate exact query bytes from the production builders; never maintain a second operation catalog.
// The builders live in the verifying service, not in this package: set GCP_CATALOG_SOURCE_ROOT to a checkout that
// contains them (and a TypeScript install at its backend package). The source paths below are recorded and hashed
// into catalog.json and CATALOG_DIGEST, so they must stay byte-identical.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import vm from 'node:vm';

assert.ok(process.env.GCP_CATALOG_SOURCE_ROOT, 'Set GCP_CATALOG_SOURCE_ROOT to the checkout holding the catalog sources.');
const root = pathToFileURL(process.env.GCP_CATALOG_SOURCE_ROOT.replace(/\/?$/, '/'));
const require = createRequire(new URL('apps/backend/package.json', root));
const ts = require('typescript');
const sourcePath = 'apps/backend/src/verification/methods/gcp-work/source.ts';
const catalogPath = 'apps/backend/src/verification/methods/gcp-work/catalog.ts';
const sourceText = await readFile(new URL(sourcePath, root), 'utf8');
const catalogText = await readFile(new URL(catalogPath, root), 'utf8');
const sha256 = value => createHash('sha256').update(value).digest('hex');

function load(text, filename, imports = {}) {
  const compiled = ts.transpileModule(text, { fileName: filename, reportDiagnostics: true,
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } });
  assert.equal(compiled.diagnostics?.filter(d => d.category === ts.DiagnosticCategory.Error).length ?? 0, 0);
  const module = { exports: {} };
  vm.runInNewContext(compiled.outputText, { module, exports: module.exports,
    require: name => { assert.ok(Object.hasOwn(imports, name), `Unexpected source import: ${name}`); return imports[name]; } },
  { filename, timeout: 1000 });
  return module.exports;
}

const catalog = load(catalogText, catalogPath);
const source = load(sourceText, sourcePath, { './catalog': catalog });
const ast = ts.createSourceFile(sourcePath, sourceText, ts.ScriptTarget.ES2022, true);
const validator = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'validateGcpScope');
assert.ok(validator);
const patterns = {}, excludedSuffixes = [];
function scopeRules(node) {
  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    const member = node.expression, argument = node.arguments[0];
    if (member.name.text === 'test' && member.expression.kind === ts.SyntaxKind.RegularExpressionLiteral &&
        argument && ts.isPropertyAccessExpression(argument) && argument.expression.getText(ast) === 'scope') {
      assert.ok(['projectId', 'email'].includes(argument.name.text));
      assert.equal(patterns[argument.name.text], undefined);
      patterns[argument.name.text] = member.expression.getText(ast);
    }
    if (member.name.text === 'endsWith' && member.expression.getText(ast) === 'scope.email.toLowerCase()') {
      assert.ok(argument && ts.isStringLiteral(argument));
      excludedSuffixes.push(argument.text);
    }
  }
  ts.forEachChild(node, scopeRules);
}
scopeRules(validator);
assert.deepEqual(Object.keys(patterns).sort(), ['email', 'projectId']);
assert.deepEqual(excludedSuffixes, ['.gserviceaccount.com']);
const { GCP_GROUPS: groups, GCP_CONTRACT_VERSION: contractVersion,
  gcpGroupRequest, gcpBatchRequest, gcpProofBatches } = source;
assert.equal(groups.length, 23, 'Review a changed group catalog before regenerating');
assert.equal(groups.reduce((n, group) => n + group.operations.length, 0), 104);
assert.equal(source.GCP_MAX_SENT, 16384);
assert.equal(source.GCP_MAX_RECV, 16384);
assert.equal(source.GCP_MAX_BATCH_GROUPS, 6);

const sample = { projectId: 'zcanonicalprojectscope', email: 'canonical-scope-marker@example.invalid',
  cutoff: Date.parse('2036-02-13T14:25:36.789Z'), windowDays: 30 };
const iso = scope => ({ startIso: new Date(scope.cutoff - scope.windowDays * 86400000).toISOString(),
  cutoffIso: new Date(scope.cutoff).toISOString() });
const slots = ['projectId', 'projectId', 'email', 'startIso', 'cutoffIso'];
const groupIds = Array.from(groups, group => group.id);
const worstScope = { ...sample, projectId: 'a'.repeat(30), email: 'x'.repeat(242) + '@example.com' };
const params = scope => ({ projectId: scope.projectId, windowDays: scope.windowDays, cutoff: scope.cutoff,
  groupIds, contractVersion });
const batches = JSON.parse(JSON.stringify(gcpProofBatches(params(worstScope))));
assert.equal(batches.length, 5, 'Private execution currently supports identity plus five group sessions');
assert.deepEqual(batches.flat(), groupIds);

const literals = [];
const names = new Map();
function literal(utf8) {
  assert.match(utf8, /^[\x20-\x7e\r\n]*$/, 'Noir literals must remain ASCII');
  let name = names.get(utf8);
  if (!name) {
    name = `LITERAL_${literals.length}`;
    names.set(utf8, name);
    literals.push({ name, byteLength: Buffer.byteLength(utf8), utf8 });
  }
  return name;
}
function split(body) {
  const values = { ...sample, ...iso(sample) };
  for (const key of new Set(slots)) {
    assert.equal(body.split(values[key]).length - 1, slots.filter(slot => slot === key).length,
      `Unexpected ${key} occurrence count`);
  }
  let cursor = 0;
  const chunks = slots.map(key => {
    const index = body.indexOf(values[key], cursor);
    assert.ok(index >= cursor, `Missing canonical insertion: ${key}`);
    const chunk = body.slice(cursor, index);
    cursor = index + values[key].length;
    return chunk;
  });
  chunks.push(body.slice(cursor));
  return chunks;
}

const boundary = 'gcp_groups_v1';
const closing = `--${boundary}--\r\n`;
const definitions = Array.from(groups, group => {
  const request = gcpGroupRequest(sample, group.id);
  const wire = gcpBatchRequest(sample, [group.id]).body;
  const start = wire.indexOf(request.body);
  assert.ok(start > 0);
  assert.equal(wire.indexOf(request.body, start + 1), -1);
  assert.ok(wire.endsWith(closing));
  const suffix = wire.slice(start + request.body.length, -closing.length);
  assert.equal(suffix, '\r\n');
  return { id: group.id, technology: group.technology, skills: Array.from(group.skills),
    predicates: Array.from(group.operations, operation => ({ id: operation.id, service: operation.service,
      method: operation.method, requiresCompletion: operation.requiresCompletion })),
    multipartPrefix: literal(wire.slice(0, start)), jsonChunks: split(request.body).map(literal),
    multipartSuffix: literal(suffix) };
});
const batchSuffix = literal(closing);
const literalText = name => literals.find(value => value.name === name).utf8;
function renderGroup(scope, group) {
  const values = { ...scope, ...iso(scope) };
  return group.jsonChunks.map((name, i) => literalText(name) + (i < slots.length ? values[slots[i]] : '')).join('');
}
function renderBatch(scope, ids) {
  return ids.map(id => {
    const group = definitions.find(value => value.id === id);
    return literalText(group.multipartPrefix) + renderGroup(scope, group) + literalText(group.multipartSuffix);
  }).join('') + literalText(batchSuffix);
}

// All permitted project lengths, ordinary/maximal/special-character emails, every window, and both ISO bounds.
// Email/project alphabets in validateGcpScope contain no JSON-escaped characters, so these lengths bound all inputs.
const existingPlans = new Set();
for (let length = 6; length <= 30; length++) {
  for (const email of ['a@b.co', worstScope.email, "a.!#$%&'*+/=?^_`{|}~-@example.invalid"]) {
    for (const windowDays of [7, 30, 90]) {
      for (const cutoff of [0, sample.cutoff, 253402300799999]) {
        const scope = { projectId: 'a'.repeat(length), email, windowDays, cutoff };
        assert.equal(iso(scope).startIso.length, 24);
        assert.equal(iso(scope).cutoffIso.length, 24);
        existingPlans.add(JSON.stringify(gcpProofBatches(params(scope))));
        for (const group of definitions) assert.equal(renderGroup(scope, group), gcpGroupRequest(scope, group.id).body);
        for (const ids of batches) assert.equal(renderBatch(scope, ids), gcpBatchRequest(scope, ids).body);
      }
    }
  }
}

const payload = {
  schema: 'gcp-private-canonical-v1', contractVersion,
  sources: [{ path: sourcePath, sha256: sha256(sourceText) }, { path: catalogPath, sha256: sha256(catalogText) }],
  scope: { projectLength: [6, 30], emailMaxLength: 254, windowDays: [7, 30, 90],
    cutoffMs: [0, 253402300799999], isoBytes: 24, insertions: slots,
    sourceValidationPatterns: patterns, excludedEmailSuffixesIgnoringCase: excludedSuffixes,
    insertionRule: 'Constrain the source alphabets and identity binding before inserting raw bytes; no JSON escapes are permitted.' },
  limits: { transcriptBytesPerDirection: 16384, batchBodyBytes: 10240, groupsPerBatch: 6 },
  batchContentType: `multipart/mixed; boundary=${boundary}`, batchSuffix,
  existingPlanStableAcrossScopeLengths: existingPlans.size === 1 && existingPlans.has(JSON.stringify(batches)),
  batches: batches.map((ids, index) => ({ step: `groups:${index}`, groupIds: ids,
    maxBodyBytes: Buffer.byteLength(gcpBatchRequest(worstScope, ids).body) })),
  groups: definitions, literals,
};
const digest = sha256(JSON.stringify(payload));
const manifest = { digest, ...payload };
const noir = [
  '// Generated by generate-catalog.mjs. Do not edit.',
  '// Exact JSON chunks: project, project, email, start ISO, cutoff ISO. Refer to catalog.json.',
  '// Constants are separate so a batch circuit references only its fixed groups, with compile-time lengths.',
  `global CATALOG_DIGEST: [u8; 32] = [${Array.from(Buffer.from(digest, 'hex')).join(', ')}];`,
  `global GROUP_COUNT: u32 = ${definitions.length};`,
  `global BATCH_COUNT: u32 = ${batches.length};`,
  ...batches.map((ids, index) => `global BATCH_${index}: [u8; ${ids.length}] = [${ids.map(id => groupIds.indexOf(id)).join(', ')}];`),
  ...literals.map(value => `global ${value.name}: [u8; ${value.byteLength}] = ${JSON.stringify(value.utf8)}.as_bytes();`),
  ...definitions.flatMap(group => [
    `// ${group.id}: ${group.predicates.length} exact operation predicates.`,
    `// prefix=${group.multipartPrefix}; json=${group.jsonChunks.join(',')}; suffix=${group.multipartSuffix}`,
  ]),
  `// batch closing=${batchSuffix}`,
  '',
].join('\n');
const outputs = [
  [new URL('./generated/catalog.json', import.meta.url), JSON.stringify(manifest, null, 2) + '\n'],
  [new URL('./circuits/lib/src/catalog_generated.nr', import.meta.url), noir],
];
assert.ok(process.argv.slice(2).every(arg => arg === '--check'), 'Usage: node generate-catalog.mjs [--check]');
for (const [path, text] of outputs) {
  if (process.argv.includes('--check')) assert.equal(await readFile(path, 'utf8'), text, `Stale catalog: ${fileURLToPath(path)}`);
  else { await mkdir(new URL('.', path), { recursive: true }); await writeFile(path, text); }
}
console.log(JSON.stringify({ digest, groups: definitions.length,
  predicates: definitions.reduce((n, group) => n + group.predicates.length, 0),
  batchGroups: batches.map(ids => ids.length), batchBytes: payload.batches.map(batch => batch.maxBodyBytes),
  existingPlanStableAcrossScopeLengths: payload.existingPlanStableAcrossScopeLengths }));
