import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { bundleCommitment, canonicalize, commitmentFields } from './commitment.mjs';

const h = c => c.repeat(64);
const FIELDS = Object.freeze({ provider: 'gcp', claim: 'gcp:observed:g1,g4', window: 30,
  vkHashes: { 'timestamps-v1': h('b'), 'atom-v1': h('a') }, proofHash: h('c'), coreDigest: h('d'), pluginSha256: h('e') });

test('canonical json sorts keys at every depth and drops whitespace', () => {
  assert.equal(canonicalize({ b: [1, { d: null, c: 'x' }], a: true }), '{"a":true,"b":[1,{"c":"x","d":null}]}');
  assert.equal(canonicalize(Object.assign(Object.create(null), { z: 1, y: 2 })), '{"y":2,"z":1}');
});

test('canonical json rejects values with more than one encoding', () => {
  for (const value of [1.5, NaN, 2 ** 60, undefined, () => 1, new Date(0), 1n, new Uint8Array(1)])
    assert.throws(() => canonicalize({ value }), /PROOF_BUNDLE_INVALID/);
});

test('commitment is sha256 over the domain-separated canonical fields', async () => {
  const expected = createHash('sha256').update(canonicalize({ v: 1, domain: 'tlsn-fork/proof-bundle', ...FIELDS })).digest('hex');
  assert.equal(await bundleCommitment(FIELDS), expected);
  assert.equal(await bundleCommitment({ ...FIELDS, vkHashes: { 'atom-v1': h('a'), 'timestamps-v1': h('b') } }), expected);
  assert.notEqual(await bundleCommitment({ ...FIELDS, window: 90 }), expected);
});

test('commitment fields are a closed shape with coarse claims only', () => {
  const bad = [{ ...FIELDS, email: 'a@b.c' }, { ...FIELDS, provider: 'Azure Corp' }, { ...FIELDS, claim: 'aws:x' },
    { ...FIELDS, claim: 'gcp:Project My-Corp' }, { ...FIELDS, window: 0 }, { ...FIELDS, window: 1.5 }, { provider: 'gcp', claim: 'gcp:x' }, { ...FIELDS, vkHashes: {} },
    { ...FIELDS, vkHashes: { 'atom-v1': 'A'.repeat(64) } }, { ...FIELDS, proofHash: h('g') }, { ...FIELDS, coreDigest: 'x' }];
  for (const fields of bad) assert.throws(() => commitmentFields(fields), /PROOF_BUNDLE_INVALID/);
  assert.deepEqual(Object.keys(commitmentFields(FIELDS).vkHashes), ['atom-v1', 'timestamps-v1']);
});

test('any evidence type commits with only provider, claim and proofHash', async () => {
  const example = { provider: 'example', claim: 'example:example-claim', proofHash: h('f') };
  assert.deepEqual(commitmentFields(example), example);
  assert.match(await bundleCommitment(example), /^[0-9a-f]{64}$/);
  assert.notEqual(await bundleCommitment(example), await bundleCommitment({ ...example, window: 90 }));
});
