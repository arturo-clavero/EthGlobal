import assert from 'node:assert/strict';
import test from 'node:test';
import { identityFixture } from './identity-fixture.mjs';
import { eventFixture, fixtureNow } from './event-fixture.mjs';
import { inspectAwsIdentitySession } from './identity-structure.mjs';
import { inspectAwsEventSession } from './event-structure.mjs';
import { assembleAwsBundleExpectations, sanitizeAwsPrivateResult, validateAwsBundleShape, verifyAwsBundle } from './verify-bundle.mjs';

// Orchestration tests use a controlled verifier double, never native/cryptographic acceptance.
function fixture(large = false) {
  const identity = identityFixture(), event = eventFixture({ mutateEvent: value => {
    value.userIdentity.arn = 'arn:aws:iam::111122223333:user/engineering/AWS_PRIVATE_USER_SENTINEL';
    if (large) value.userAgent = 'X'.repeat(80);
  }, mutateRow: row => { if (large) row.Username = 'X'.repeat(80); },
  mutateHeaders: headers => { if (large) headers.find(([name]) => name.toLowerCase() === 'authorization')[1] = 'X'.repeat(80); } });
  event.expected.sessionId = '33333333-3333-4333-8333-333333333333';
  event.receipt.session.id = event.expected.sessionId;
  const sessions = [identity, event].map(({ receipt, expected }) => ({ receipt, expected }));
  const expectations = assembleAwsBundleExpectations(
    inspectAwsIdentitySession(identity.receipt, identity.expected, fixtureNow),
    inspectAwsEventSession(event.receipt, event.expected, event.claims, fixtureNow), identity.expected.issuedAt);
  const bundle = { kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: sessions.map(session => session.expected.sessionId),
    proofs: expectations.map(({ circuitId, publicInputs }) => ({ circuitId,
      proof: Buffer.from('synthetic test double only').toString('base64'), publicInputs: publicInputs.map(String) })) };
  const calls = [];
  const runtime = { verify: async (proof, expected) => {
    calls.push(proof.circuitId);
    assert.deepEqual(proof.publicInputs.map(BigInt), expected.map(BigInt));
    return true;
  } };
  return { sessions, bundle, runtime, now: fixtureNow, calls };
}
const rejects = value => assert.rejects(verifyAwsBundle(value), /AWS_PRIVATE_BUNDLE_INVALID/);

test('reconstructs every obligation and returns only the approved fixed claim', async () => {
  const value = fixture();
  assert.deepEqual(await verifyAwsBundle(value), { taskType: 'iam-role-trust-update', attribution: 'iam-user', windowDays: 90 });
  assert.equal(value.calls.length, value.bundle.proofs.length);
  assert.deepEqual(value.calls.slice(0, 2), ['aws-identity-link-v1', 'aws-event-link-v1']);
  assert.ok(value.calls.includes('aws-xml-text-v1') && value.calls.includes('aws-escaped-atoms-small-v1'));
  assert.doesNotMatch(JSON.stringify(value.bundle), /AWS_PRIVATE_USER_SENTINEL|111122223333|AIDAEXAMPLESYNTHETIC01|openings|preimage/);
});

test('requires affirmative cryptographic verification for every individual obligation', async () => {
  for (const failedId of new Set(fixture(true).bundle.proofs.map(proof => proof.circuitId))) {
    const value = fixture(true); value.runtime.verify = async proof => proof.circuitId !== failedId;
    await rejects(value);
  }
  const value = fixture(); value.runtime.verify = async () => ({ verified: false }); await rejects(value);
  value.runtime.verify = async () => { throw new Error('private error must not escape'); }; await rejects(value);
});

test('rejects missing, duplicate and reordered proof obligations', async () => {
  for (const id of new Set(fixture(true).bundle.proofs.map(proof => proof.circuitId))) {
    const value = fixture(true), index = value.bundle.proofs.findIndex(proof => proof.circuitId === id);
    value.bundle.proofs.splice(index, 1); await rejects(value);
  }
  const duplicate = fixture(); duplicate.bundle.proofs.push(duplicate.bundle.proofs[2]); await rejects(duplicate);
  const reordered = fixture(); reordered.bundle.proofs.reverse(); await rejects(reordered);
});

test('binds semantic hashes, lengths and cutoff to authenticated positions and the server attempt', async () => {
  for (const [proofIndex, fieldIndex] of [[0, 0], [0, 128], [0, 224], [0, 256], [1, 0], [1, 96], [1, 192], [1, 198]]) {
    const value = fixture(), fields = value.bundle.proofs[proofIndex].publicInputs;
    fields[fieldIndex] = String(BigInt(fields[fieldIndex]) ^ 1n); await rejects(value);
  }
});

test('rejects transplanted native ranges and forged decoded atom commitments', async () => {
  for (const field of [0, 256, 264, 520, 528]) {
    const value = fixture(), proof = value.bundle.proofs.find(proof => proof.circuitId === 'aws-escaped-atoms-small-v1');
    proof.publicInputs[field] = String(BigInt(proof.publicInputs[field]) ^ 1n); await rejects(value);
  }
  const value = fixture(), proof = value.bundle.proofs.find(proof => proof.circuitId === 'atoms-small-v1');
  proof.publicInputs[0] = '256'; await rejects(value);
});

test('batches small values and retains complete large-value fallback obligations', async () => {
  const value = fixture(true);
  assert.deepEqual(await verifyAwsBundle(value), { taskType: 'iam-role-trust-update', attribution: 'iam-user', windowDays: 90 });
  for (const id of ['header-v1', 'atom-v1', 'aws-escaped-atom-v1', 'headers-small-v1', 'atoms-small-v1', 'aws-escaped-atoms-small-v1']) {
    assert.ok(value.calls.includes(id), id);
  }
  assert.ok(fixture().bundle.proofs.length < 20);
});

test('rejects inactive metadata, omitted batch slots, duplicate slots and swapped slots', async () => {
  for (const id of ['headers-small-v1', 'atoms-small-v1', 'aws-escaped-atoms-small-v1']) {
    for (const mutate of [fields => { fields[0] = '255'; }, fields => { fields[32] = fields[0]; },
      fields => { [fields[0], fields[32]] = [fields[32], fields[0]]; },
      fields => { fields[id === 'headers-small-v1' ? 512 : 256] = '0'; }]) {
      const value = fixture(), proof = value.bundle.proofs.find(proof => proof.circuitId === id);
      mutate(proof.publicInputs); await rejects(value);
    }
  }
  // Unbound tail values need the real encoding proof; this double checks native placement only.
  for (const field of [0, 32]) {
    const value = fixture(), proof = value.bundle.proofs.find(proof => proof.circuitId === 'aws-escaped-atom-small-v1');
    proof.publicInputs[field] = String(BigInt(proof.publicInputs[field]) ^ 1n); await rejects(value);
  }
});

test('uses the identity relation for its four XML spans and retains unrelated XML proofs', async () => {
  const value = fixture(), identity = inspectAwsIdentitySession(value.sessions[0].receipt, value.sessions[0].expected, fixtureNow);
  const text = value.bundle.proofs.filter(proof => proof.circuitId === 'aws-xml-text-v1');
  assert.equal(text.length, identity.obligations.filter(slot => slot.circuitId === 'aws-xml-text-v1').length - 4);
  const relation = value.bundle.proofs[0].publicInputs;
  for (const [index, name] of ['UserId', 'Arn', 'Path', 'UserName'].entries()) {
    const digest = identity.bindings[name].hash;
    assert.equal(Buffer.from(relation.slice(index * 32, (index + 1) * 32).map(Number)).toString('hex'), digest);
    assert.ok(text.every(proof => Buffer.from(proof.publicInputs.slice(0, 32).map(Number)).toString('hex') !== digest));
  }
  value.bundle.proofs.shift(); await rejects(value);
});

test('requires distinct ordered sessions with one challenge, policy, plugin and lifetime', async () => {
  for (const [key, replacement] of [['proofId', '44444444-4444-4444-8444-444444444444'], ['nonceMac', 'x'.repeat(43)],
    ['pluginSha256', 'cd'.repeat(32)], ['issuedAt', fixtureNow - 2000], ['expiresAt', fixtureNow + 2000],
    ['identityService', 'sts'], ['region', 'us-west-2'], ['step', 'identity']]) {
    const value = fixture(); value.sessions[1].expected[key] = replacement; await rejects(value);
  }
  const duplicate = fixture(); duplicate.bundle.sessionIds[1] = duplicate.bundle.sessionIds[0]; await rejects(duplicate);
  const reordered = fixture(); reordered.sessions.reverse(); await rejects(reordered);
  const missing = fixture(); missing.sessions.pop(); await rejects(missing);
});

test('expired sessions and transcript substitution fail before proof verification', async () => {
  const expired = fixture(); expired.now = fixtureNow + 1001; await rejects(expired); assert.equal(expired.calls.length, 0);
  const swapped = fixture(); swapped.sessions[1].receipt = swapped.sessions[0].receipt; await rejects(swapped);
  assert.equal(swapped.calls.length, 0);
});

test('bounded wire shape rejects unknown circuits, fields, versions and proof encodings', () => {
  for (const mutate of [value => { value.rawWitness = 'private'; }, value => { value.version = 2; },
    value => { value.proofs[0].circuitId = '__proto__'; }, value => { value.proofs[0].witness = 'private'; },
    value => { value.proofs[0].proof = '%invalid'; }, value => { value.proofs[0].proof = 'AAAA'.repeat(8193); },
    value => { value.proofs[0].publicInputs[0] = '18446744073709551616'; },
    value => { value.proofs[0].publicInputs[0] = -1; }, value => { value.proofs[0].publicInputs.pop(); },
    value => { value.proofs = Array(129).fill(value.proofs[0]); }]) {
    const { bundle } = fixture(); mutate(bundle); assert.throws(() => validateAwsBundleShape(bundle), /AWS_PRIVATE_BUNDLE_INVALID/);
  }
});

test('wire preflight rejects missing session IDs and case aliases of the same native session', () => {
  for (const sessionIds of [Array(2), [fixture().bundle.sessionIds[0], ,],
    ['abcdefab-cdef-4abc-8def-abcdefabcdef', 'ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF']]) {
    const { bundle } = fixture(); bundle.sessionIds = sessionIds;
    assert.throws(() => validateAwsBundleShape(bundle), /AWS_PRIVATE_BUNDLE_INVALID/);
  }
});

test('completion sanitizer owns all public arrays and rejects private extras', () => {
  const { bundle } = fixture(), expected = structuredClone(bundle);
  const result = sanitizeAwsPrivateResult(bundle);
  bundle.sessionIds.reverse(); bundle.proofs[0].publicInputs[0] = '0'; bundle.proofs.pop();
  assert.deepEqual(result, expected);
  expected.proofs[0].privateWitness = 'PRIVATE_SENTINEL';
  assert.throws(() => sanitizeAwsPrivateResult(expected), /AWS_PRIVATE_BUNDLE_INVALID/);
});
