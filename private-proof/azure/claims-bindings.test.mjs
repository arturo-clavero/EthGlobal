import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { claimsProofExpectations } from './claims-bindings.mjs';
import { prepareClaimsChunks } from './claims-plan.mjs';

const hash = byte => byte.toString(16).padStart(2, '0').repeat(32);
const field = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
const hex = bytes => Buffer.from(bytes).toString('hex');
function fixture(length = 1100) {
  const start = 120, count = Math.ceil(length / 512);
  return { descriptor: { start, end: start + length, length,
    chunks: Array.from({ length: count }, (_, i) => ({ start: start + i * 512,
      end: start + Math.min((i + 1) * 512, length), kind: 6, hash: hash(i + 1) })) },
    states: Array.from({ length: count + 1 }, (_, i) => hash(i + 10)), identities: [hash(100), hash(101)] };
}
const build = value => claimsProofExpectations(value.descriptor, value.states, value.identities);
const rejected = value => assert.throws(() => build(value), { message: 'AZURE_PRIVATE_CLAIMS_BINDINGS_INVALID' });

test('reconstructs all native chunks and shared carry boundaries in the exact 163-field ABI', () => {
  const f = fixture(), result = build(f);
  assert.deepEqual(result.references, { actorHash: f.identities[0], tenantHash: f.identities[1] });
  assert.equal(result.proofs.length, 3);
  for (const [i, proof] of result.proofs.entries()) {
    assert.equal(proof.circuitId, 'claims-chunk-v1'); assert.equal(proof.publicInputs.length, 163);
    const groups = [i + 1, i + 10, i + 11, 100, 101].flatMap(byte => Array(32).fill(field(byte)));
    assert.deepEqual(proof.publicInputs, [...groups, ...[Math.min(512, 1100 - i * 512), i * 512, 1100].map(field)]);
    if (i) assert.deepEqual(proof.publicInputs.slice(32, 64), result.proofs[i - 1].publicInputs.slice(64, 96));
  }
  assert.equal(Object.hasOwn(result, 'verified'), false);
});

test('accepts exact full chunks and a maximum-size final partial chunk', () => {
  for (const length of [2, 512, 1024, 2304]) {
    const result = build(fixture(length));
    assert.equal(result.proofs.length, Math.ceil(length / 512));
    assert.equal(result.proofs.at(-1).publicInputs[160], field(length % 512 || 512));
  }
});

test('missing, reordered, overlapping, gapped and short nonfinal native coverage rejects', () => {
  for (const mutate of [
    f => f.descriptor.chunks.pop(), f => f.descriptor.chunks.reverse(),
    f => f.descriptor.chunks.push(f.descriptor.chunks[0]), f => delete f.descriptor.chunks[1],
    f => f.descriptor.chunks[0].end--, f => f.descriptor.chunks[1].start++,
    f => f.descriptor.chunks[1].start--, f => f.descriptor.chunks.at(-1).end++,
    f => f.descriptor.chunks[0].kind = 1,
  ]) { const f = fixture(); mutate(f); rejected(f); }
});

test('malformed counts, ranges, extra metadata and syntactic merged hash substitutes reject', () => {
  for (const mutate of [
    f => f.descriptor.length++, f => f.descriptor.start--, f => f.descriptor.end++,
    f => f.descriptor.start = -1, f => f.descriptor.end = Infinity,
    f => f.descriptor.length = 2305, f => f.descriptor.length = 0,
    f => f.descriptor.hash = hash(0), f => f.descriptor.chunks[0].publicInputs = [],
    f => f.states.pop(), f => f.states.push(hash(9)), f => delete f.states[1],
    f => f.identities.pop(), f => f.identities.push(hash(9)), f => delete f.identities[0],
  ]) { const f = fixture(); mutate(f); rejected(f); }
  const f = fixture();
  f.descriptor.start += 16384; f.descriptor.end += 16384;
  rejected(f);
});

test('all three hash roles require canonical complete digests', () => {
  for (const invalid of [null, [], hash(10).toUpperCase(), '0x' + hash(1), 'a'.repeat(63), 'g'.repeat(64)]) {
    for (const mutate of [f => f.descriptor.chunks[0].hash = invalid,
      f => f.states[0] = invalid, f => f.identities[0] = invalid]) {
      const f = fixture(); mutate(f); rejected(f);
    }
  }
});

test('changed native, carry or identity commitments change expectations rather than authenticating themselves', () => {
  const f = fixture(), previous = build(f);
  f.descriptor.chunks[0].hash = hash(200);
  assert.notDeepEqual(build(f).proofs[0].publicInputs.slice(0, 32), previous.proofs[0].publicInputs.slice(0, 32));
  f.states[1] = hash(201);
  const changed = build(f);
  assert.notDeepEqual(changed.proofs[0].publicInputs.slice(64, 96), previous.proofs[0].publicInputs.slice(64, 96));
  assert.deepEqual(changed.proofs[0].publicInputs.slice(64, 96), changed.proofs[1].publicInputs.slice(32, 64));
  f.identities[0] = hash(202);
  for (const proof of build(f).proofs) assert.deepEqual(proof.publicInputs.slice(96, 128), Array(32).fill(field(202)));
  assert.equal(previous.references.actorHash, hash(100));
});

test('independent expectations agree with the private witness planner without consuming its publicInputs', async () => {
  const bytes = new TextEncoder().encode(JSON.stringify({ privateEmployerKey: 'x'.repeat(900),
    'http://schemas.microsoft.com/identity/claims/objectidentifier': 'aaaaaaaa-1111-2222-3333-444444444444',
    'http://schemas.microsoft.com/identity/claims/tenantid': 'bbbbbbbb-1111-2222-3333-444444444444' }));
  const start = 80;
  const openings = Array.from({ length: Math.ceil(bytes.length / 512) }, (_, i) => {
    const offset = i * 512, part = bytes.subarray(offset, offset + 512), blinder = new Uint8Array(16).fill(i + 1);
    return { start: start + offset, end: start + offset + part.length, blinder,
      hash: new Uint8Array(createHash('sha256').update(part).update(blinder).digest()) };
  });
  const plan = await prepareClaimsChunks(bytes, openings, { start });
  try {
    const descriptor = { start, end: start + bytes.length, length: bytes.length,
      chunks: openings.map(({ start, end, hash }) => ({ start, end, kind: 6, hash: hex(hash) })) };
    const states = [hex(plan.chunks[0].inputs.hashes[1]), ...plan.chunks.map(chunk => hex(chunk.inputs.hashes[2]))];
    const result = claimsProofExpectations(descriptor, states, plan.identities.map(identity => hex(identity.hash)));
    assert.deepEqual(result.proofs.map(proof => proof.publicInputs), plan.chunks.map(chunk => chunk.publicInputs));
    assert.equal(JSON.stringify(result).includes('privateEmployerKey'), false);
    plan.chunks[0].publicInputs.fill(field(0));
    assert.notDeepEqual(result.proofs[0].publicInputs, plan.chunks[0].publicInputs);
  } finally { plan.clear(); bytes.fill(0); }
});
