import test from 'node:test';
import assert from 'node:assert/strict';
import { AZURE_ACTIVITY_PROFILES, validateAzureAttempt, sanitizeAzurePrivateResult, azureProofFields, eraseAzureInputs } from './browser-result.mjs';

const attempt = () => ({ proofId: '11111111-1111-4111-8111-111111111111', pluginSha256: 'a'.repeat(64),
  nonceMac: 'b'.repeat(43), challenge: 'c'.repeat(64), cutoffMs: 1000, issuedAt: 1000, expiresAt: 3601000 });
const proof = () => ({ circuitId: 'identity-link-v1', proof: 'AQID', publicInputs: Array(96).fill('0x01') });
const bundle = () => ({ kind: 'AZURE_PRIVATE_RESULT', version: 1, claim: 'AZURE_NSG_RULE_OPERATION',
  sessionIds: [1, 2, 3].map(i => `${i}1111111-1111-4111-8111-111111111111`),
  bindings: { graphActorHash: 'a'.repeat(64), identityBinding: 'b'.repeat(64), selectedRow: 0,
    claims: [{ stateHashes: ['c'.repeat(64), 'd'.repeat(64)], identityHashes: ['e'.repeat(64), 'f'.repeat(64)] }] },
  proofs: [proof()] });

test('attempt allows measured multi-minute work but bounds lifetime and clock', () => {
  validateAzureAttempt(attempt(), 2000);
  for (const patch of [{ cutoffMs: 1001 }, { issuedAt: 2001, cutoffMs: 2001 }, { expiresAt: 2000 },
    { expiresAt: 3601001 }, { challenge: 'c'.repeat(63) }, { nonceMac: '0'.repeat(64) },
    { method: 'AZURE_WORK_PRIVATE' }, { issuedAt: -1, cutoffMs: -1 }]) {
    assert.throws(() => validateAzureAttempt({ ...attempt(), ...patch }, 2000));
  }
});

test('public envelope is copied and preserves only committed identity/state metadata', () => {
  const source = bundle(), clean = sanitizeAzurePrivateResult(source);
  assert.deepEqual(clean, source);
  source.bindings.claims[0].stateHashes[0] = 'PRIVATE'; source.proofs[0].publicInputs[0] = 'PRIVATE';
  assert.equal(clean.bindings.claims[0].stateHashes[0], 'c'.repeat(64));
  assert.equal(clean.proofs[0].publicInputs[0], '0x01');
});

test('rejects private extras, sparse envelopes, unknown circuits and duplicate sessions', () => {
  const mutations = [b => { b.privateWitness = 'SECRET'; }, b => { b.proofs[0].inputs = [1]; },
    b => { b.bindings.claims[0].actor = 'SECRET'; }, b => { b.bindings.selectedRow = 1; },
    b => { b.sessionIds[1] = b.sessionIds[0]; }, b => { b.proofs[0].circuitId = 'caller-circuit'; },
    b => { b.proofs = new Array(1); }, b => { b.bindings.claims = new Array(1); },
    b => { b.bindings.claims[0].stateHashes = new Array(2); }, b => { b.proofs = Array(129).fill(proof()); },
    b => { Object.defineProperty(b, 'secret', { value: 1 }); }, b => { b.bindings[Symbol('secret')] = 1; }];
  for (const change of mutations) { const b = bundle(); change(b); assert.throws(() => sanitizeAzurePrivateResult(b)); }
});

test('proof shape requires exact public counts, bounded integers and canonical base64', () => {
  assert.equal(azureProofFields(proof()).length, 96);
  for (const changed of [ { proof: 'AR==' }, { proof: 'AAAA'.repeat(8193) },
    { publicInputs: Array(95).fill('1') }, { publicInputs: new Array(96) },
    { publicInputs: Array(96).fill('0x10000000000000000') },
    { publicInputs: Array(96).fill('secret@example.test') }, { verificationKey: 'caller-key' }]) {
    assert.throws(() => azureProofFields({ ...proof(), ...changed }));
  }
});

test('cleanup erases nested witness values, typed arrays and cycles', () => {
  const input = { bytes: new Uint8Array([1, 2]), rows: [[3, 4], ['secret']], scalar: 'secret' };
  input.self = input; eraseAzureInputs(input);
  assert.deepEqual([...input.bytes], [0, 0]); assert.deepEqual(input.rows, [[0, 0], ['']]);
  assert.equal(input.scalar, '');
});

test('catalog envelope exposes only an approved claim and fixed circuit public inputs', () => {
  for (const [claim, profile] of Object.entries(AZURE_ACTIVITY_PROFILES)) {
    if (profile.code === undefined) continue;
    const value = bundle(); value.claim = claim;
    value.proofs = [{ circuitId: 'catalog-activity-atoms-v1', proof: 'AQID', publicInputs: [...Array(715).fill('0'), String(profile.code)] }];
    assert.equal(sanitizeAzurePrivateResult(value).claim, claim);
    assert.throws(() => sanitizeAzurePrivateResult({ ...value, profile_code: profile.code }));
    value.proofs[0].publicInputs.pop(); assert.throws(() => sanitizeAzurePrivateResult(value));
  }
  for (const claim of ['__proto__', 'constructor', 'AZURE_UNSUPPORTED_ACTION']) {
    assert.throws(() => sanitizeAzurePrivateResult({ ...bundle(), claim }));
  }
});
