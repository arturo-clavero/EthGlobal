import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { createGcpPrivateClient, planGcpSession, summarizeGcpPlan } from './client-plan.mjs';

import { fixture, committed, options, policy, projectId, email, mockPublicInputs as publicInputs } from './client-fixture.mjs';

const encoder = new TextEncoder(), decoder = new TextDecoder();
const sha = bytes => createHash('sha256').update(bytes).digest();
function moduleFor(proveCircuit = async (id, inputs) => ({ circuitId: id, proof: 'YQ==', publicInputs: publicInputs(id, inputs) })) {
  return createGcpPrivateClient({ projectId, policy, crypto: webcrypto, proveCircuit });
}

test('all six sessions partition exact bytes and hide UTF-8 atoms, credentials, scopes and timestamps', () => {
  const raws = fixture(), inspections = [];
  for (const raw of raws) {
    const planned = planGcpSession(raw, raw, options); inspections.push(planned.inspection);
    for (const direction of ['sent', 'recv']) {
      const ranges = planned.plan[`${direction}RangesWithHandlers`];
      let cursor = 0;
      const disclosed = new Uint8Array(raw[direction]);
      for (const range of ranges) {
        assert.equal(range.start, cursor); assert(range.end > cursor);
        cursor = range.end;
        if (range.handler.action.kind === 'HASH') disclosed.fill(0, range.start, range.end);
      }
      assert.equal(cursor, raw[direction].length);
      for (const value of [email, projectId, '12345', 'Private employer', '👩‍💻', '2023-12-31T12:00:00Z', 'SAPISIDHASH']) {
        assert.equal(decoder.decode(disclosed).includes(value), false);
      }
      assert(disclosed.every(byte => byte < 128));
    }
  }
  assert.equal(inspections.slice(1).flatMap(inspection => inspection.groups).length, 23);
  assert.deepEqual(summarizeGcpPlan(inspections), { circuits: { 'header-v1': 6, 'atom-v1': 0,
    'identity-scope-v1': 1, 'query-scope-v1': 5, 'timestamps-v1': 5, 'headers-small-v1': 2, 'atoms-small-v1': 1 },
  lengths: { header: { 64: 17, 2048: 6 }, atom: { 64: 4 } }, proofCount: 20 });
});

test('capacity fixture covers the six-session live workload using synthetic values', () => {
  const inspections = fixture({ capacity: true }).map(raw => {
    const planned = planGcpSession(raw, raw, options);
    for (const direction of ['sent', 'recv']) assert(planned.plan[`${direction}RangesWithHandlers`].length <= 256);
    return planned.inspection;
  });
  assert.deepEqual(summarizeGcpPlan(inspections), { circuits: { 'header-v1': 7, 'atom-v1': 1,
    'identity-scope-v1': 1, 'query-scope-v1': 5, 'timestamps-v1': 5, 'headers-small-v1': 14, 'atoms-small-v1': 1 },
  lengths: { header: { 64: 220, 1024: 1, 2048: 6 }, atom: { 64: 8, 256: 1 } }, proofCount: 34 });
  const groups = inspections.slice(1).flatMap(inspection => inspection.groups);
  assert.equal(groups.length, 23);
  assert.equal(groups.filter(group => group.status === 'observed').length, 8);
  assert.equal(groups.filter(group => group.status === 'empty').length, 15);
});

test('medium header commitments cover every byte and preserve lexical and range bounds', () => {
  for (const length of [1, 64, 65, 128, 255, 256, 257, 2048, 2049]) {
    const raw = fixture({ cookieLength: length })[0], planned = planGcpSession(raw, raw, options);
    const start = Buffer.from(raw.sent).indexOf('Cookie: ') + 'Cookie: '.length, end = start + length;
    const chunks = planned.privateSlots.sent.filter(slot => slot.start >= start && slot.end <= end);
    const capacity = length <= 256 ? 64 : 2048;
    assert.equal(chunks.length, Math.ceil(length / capacity));
    assert.equal(chunks[0].start, start); assert.equal(chunks.at(-1).end, end);
    chunks.forEach((chunk, index) => {
      assert.equal(chunk.start, start + index * capacity);
      assert.equal(chunk.end, Math.min(chunk.start + capacity, end));
    });
    for (const byte of [0, 127, 128]) {
      const changed = { ...raw, sent: new Uint8Array(raw.sent) };
      changed.sent[end - 1] = byte;
      assert.throws(() => planGcpSession(changed, changed, options), /GCP_PRIVATE_CLIENT_INVALID/);
    }
  }
  const raw = fixture()[0];
  raw.recv = encoder.encode(decoder.decode(raw.recv).replace('\r\n\r\n',
    `${`\r\nX-Repeated: ${'s'.repeat(193)}`.repeat(60)}\r\n\r\n`));
  const fallback = planGcpSession(raw, raw, options);
  assert(fallback.plan.recvRangesWithHandlers.length <= 256);
  assert.equal(fallback.inspection.obligations.filter(slot => slot.predicate === 'header-v1' && slot.length === 193).length, 60);
  const row = ['gaia.l.a', 'name', 'avatar', email, 'a', 'b', 'c', 'd', 'e', 1, '12345', 'f', 'g', 'h', 0, 1];
  const oversized = fixture({ identityBody: JSON.stringify(['gaia.l.a.r', Array(10).fill(row)]) })[0];
  oversized.recv = encoder.encode(decoder.decode(oversized.recv).replace('\r\n\r\n',
    `${'\r\nX-Repeated: s'.repeat(16)}\r\n\r\n`));
  assert.throws(() => planGcpSession(oversized, oversized, options), /GCP_PRIVATE_CLIENT_INVALID/);
});

test('reordered native openings produce matching scope and exact five circuit ABIs; inputs are erased', async () => {
  const witnesses = fixture().map(committed), retained = [], snapshots = [];
  const module = moduleFor(async (id, inputs, signal) => {
    assert.equal(signal.aborted, false); retained.push(inputs); snapshots.push(structuredClone(inputs));
    return { circuitId: id, proof: 'YQ==', publicInputs: publicInputs(id, inputs) };
  });
  assert.equal(module.identityEmail(witnesses[0]), email);
  const result = await module.prove(witnesses, new AbortController().signal);
  assert.equal(result.proofs.length, 20);
  assert.deepEqual(Object.keys(result), ['proofs']);
  for (const input of retained) {
    const arrays = Object.values(input).filter(Array.isArray);
    assert(arrays.every(array => array.every(value => value === 0)));
  }
  const scopes = snapshots.filter(input => input.scope_hash);
  assert.equal(scopes.length, 6);
  for (const scope of scopes) assert.deepEqual(scope.scope_hash, scopes[0].scope_hash);
  const reference = scopes[0];
  assert.deepEqual(Array.from(sha(Uint8Array.from([...encoder.encode('gcp-private-scope-v1'), ...reference.nonce,
    ...reference.salt, reference.account, reference.project_len, ...reference.project, reference.email_len,
    ...reference.email, reference.id_len, ...reference.id]))), reference.scope_hash);
  await assert.rejects(module.prove(witnesses, new AbortController().signal), /GCP_PRIVATE_CLIENT_INVALID/);
});

test('complete private error metadata preserves denied status', () => {
  const plans = fixture({ denied: true }).map(raw => planGcpSession(raw, raw, options));
  assert(plans.slice(1).every(plan => plan.inspection.groups.every(group => group.status === 'denied')));
  assert.equal(summarizeGcpPlan(plans.map(plan => plan.inspection)).circuits['atoms-small-v1'], 10);
});

test('a private UTF-8 atom may not cross HTTP chunk framing', () => {
  const body = JSON.stringify(['gaia.l.a.r', [['gaia.l.a', 'Private 👩‍💻', null, email,
    null, null, null, null, null, 1, '12345', null, null, null, null, 1]]]);
  const inside = encoder.encode(body.slice(0, body.indexOf('Private') + 2)).length;
  const raw = fixture({ identityBody: body, chunkAt: inside })[0];
  assert.throws(() => planGcpSession(raw, raw, options), /GCP_PRIVATE_CLIENT_INVALID/);
  const atBoundary = fixture({ identityBody: body, chunkAt: 14 })[0];
  assert.equal(planGcpSession(atBoundary, atBoundary, options).selected.email, email);
});

test('reject oversized atoms, malformed UTF-8 and changed query predicates', () => {
  const raw = fixture()[0];
  const body = ['gaia.l.a.r', [['gaia.l.a', 'x'.repeat(511), null, email,
    null, null, null, null, null, 1, '12345', null, null, null, null, 1]]];
  const oversized = fixture({ identityBody: JSON.stringify(body) })[0];
  assert.throws(() => planGcpSession(oversized, oversized, options), /GCP_PRIVATE_CLIENT_INVALID/);
  const invalid = structuredClone(raw), at = Buffer.from(invalid.recv).indexOf(Buffer.from('👩'));
  invalid.recv[at] = 255;
  assert.throws(() => planGcpSession(invalid, invalid, options), /GCP_PRIVATE_CLIENT_INVALID/);
  const changed = fixture()[1], position = Buffer.from(changed.sent).indexOf(Buffer.from('sample-project'));
  changed.sent[position] = 120;
  assert.throws(() => planGcpSession(changed, changed, options), /GCP_PRIVATE_CLIENT_INVALID/);
});

test('wrong blinder, opening range, duplicate session and account mismatch fail before proving', async () => {
  for (const mutate of [
    witnesses => { witnesses[0].openings.sent[0].blinder[0] ^= 1; },
    witnesses => { witnesses[0].openings.sent[0].start++; },
    witnesses => { witnesses[2].sessionId = witnesses[1].sessionId; },
    witnesses => { witnesses[2].nonceMac = 'B'.repeat(43); },
    witnesses => { witnesses[2].serverName = 'attacker.invalid'; },
    witnesses => { witnesses[1].selections.sent[0].end--; },
    witnesses => {
      const raw = { ...witnesses[1], sent: new Uint8Array(witnesses[1].sent) };
      const at = Buffer.from(raw.sent).indexOf(Buffer.from('X-Goog-Authuser: 0')) + 'X-Goog-Authuser: '.length;
      raw.sent[at] = 49; witnesses[1] = committed(raw);
    },
  ]) {
    const witnesses = fixture().map(committed), module = moduleFor(async () => assert.fail('proving must not begin'));
    module.identityEmail(witnesses[0]); mutate(witnesses);
    await assert.rejects(module.prove(witnesses, new AbortController().signal), /GCP_PRIVATE_CLIENT_INVALID/);
  }
});

test('aborts reject before proving and a late result is rejected with input cleanup', async () => {
  const witnesses = fixture().map(committed), already = new AbortController(), module = moduleFor();
  module.identityEmail(witnesses[0]); already.abort();
  await assert.rejects(module.prove(witnesses, already.signal), /GCP_PRIVATE_CLIENT_INVALID/);
  const controller = new AbortController(); let retained;
  const late = moduleFor(async (id, inputs) => {
    retained = inputs; controller.abort();
    return { circuitId: id, proof: 'YQ==', publicInputs: publicInputs(id, inputs) };
  });
  late.identityEmail(witnesses[0]);
  await assert.rejects(late.prove(witnesses, controller.signal), /GCP_PRIVATE_CLIENT_INVALID/);
  assert(retained.salt.every(byte => byte === 0));
});

test('a prover result with incorrect public fields cannot complete', async () => {
  const witnesses = fixture().map(committed), module = moduleFor(async (id, input) => {
    const fields = publicInputs(id, input); fields[0] = String(Number(fields[0]) + 1);
    return { circuitId: id, proof: 'YQ==', publicInputs: fields };
  });
  module.identityEmail(witnesses[0]);
  await assert.rejects(module.prove(witnesses, new AbortController().signal), /GCP_PRIVATE_CLIENT_INVALID/);
});
