import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { assembleBundleExpectations, validateBundleShape, verifyBundle } from './verify-bundle.mjs';
import { inspectGcpSession } from './gcp-structure.mjs';
import { BATCHES, CATALOG_DIGEST } from './policy.mjs';
import { gcpFixture, groupPart, fixtureNonce, fixturePolicy, identityRow, secret, fragments } from './gcp-fixtures.mjs';

// Synthetic receipts and a deliberately fake verifier isolate orchestration.
// Actual TLS provenance and ZK verification have separate integration checks.
const steps = ['identity', ...BATCHES.map(batch => batch.step)];
const field = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
const fakeProof = (id, values) => createHash('sha256').update(JSON.stringify([id, values.map(field)])).digest('base64');
const expectedError = { message: 'GCP_PRIVATE_BUNDLE_INVALID' };

function nativeReceipt(fixture, index) {
  const expected = { sessionId: `11111111-1111-4111-8111-${String(index + 1).padStart(12, '0')}`,
    proofId: '22222222-2222-4222-8222-222222222222', pluginSha256: 'ab'.repeat(32),
    nonceMac: fixtureNonce, step: fixture.meta.step };
  const receipt = { server_name: index === 0 ? 'accounts.google.com' : 'logging.clients6.google.com',
    session: { id: expected.sessionId, proofId: expected.proofId, pluginSha256: expected.pluginSha256,
      nonceMac: expected.nonceMac, step: expected.step, method: 'GCP_WORK', mode: 'Proxy' },
    config: {}, results: [], transcript: {} };
  for (const [name, value] of Object.entries(fixture.directions)) {
    const ranges = [], type = name.toUpperCase();
    const append = (start, end, hash) => {
      const action = hash ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' };
      const handler = { type, part: 'BODY', action };
      ranges.push({ start, end, handler });
      receipt.results.push({ ...handler, value: hash ?? new TextDecoder().decode(value.bytes.slice(start, end)) });
    };
    let cursor = 0;
    for (const slot of value.privateRanges) {
      if (cursor < slot.start) append(cursor, slot.start);
      append(slot.start, slot.end, slot.hash);
      cursor = slot.end;
    }
    if (cursor < value.bytes.length) append(cursor, value.bytes.length);
    receipt.config[name] = ranges;
    receipt.transcript[name] = String.fromCharCode(...value.bytes);
    receipt.transcript[`${name}_length`] = value.bytes.length;
  }
  return { receipt, expected };
}

function bundleFixture({ empty = false } = {}) {
  const fixtures = steps.map((step, index) => {
    const options = index === 0 ? { rows: [identityRow(0, '1', secret(`"${'x'.repeat(100)}"`, 1)), identityRow(1, '0')],
      responseHeaders: fragments('X-Transport: ', secret('first synthetic value'), '\r\nX-Transport: ', secret('second synthetic value'), '\r\n') }
      : empty ? { parts: BATCHES[index - 1].groupIds.map(id => groupPart(id, 'empty')) } : {};
    const fixture = gcpFixture(step, options), replacements = new Map();
    for (const direction of Object.values(fixture.directions)) {
      for (const slot of direction.privateRanges) {
        const hash = ((BigInt(index + 1) << 32n) + BigInt(`0x${slot.hash}`)).toString(16).padStart(64, '0');
        replacements.set(slot.hash, hash); slot.hash = hash;
      }
    }
    for (const claim of fixture.atomicClaims) claim.hash = replacements.get(claim.hash);
    return fixture;
  });
  const sessions = fixtures.map(nativeReceipt);
  const inspections = fixtures.map(fixture => inspectGcpSession(fixture.directions, fixture.meta, fixture.policy, fixture.atomicClaims));
  const expectations = assembleBundleExpectations(inspections, Array(32).fill(7), fixturePolicy, fixtureNonce);
  const bundle = { kind: 'GCP_PRIVATE_RESULT', version: 1, sessionIds: sessions.map(session => session.expected.sessionId),
    proofs: expectations.map(value => ({ circuitId: value.circuitId, proof: fakeProof(value.circuitId, value.publicInputs),
      publicInputs: value.publicInputs.map(field) })) };
  return { sessions, policy: fixturePolicy, bundle, inspections, expectations };
}

function runtime(rejectAt = -1) {
  let calls = 0;
  return { get calls() { return calls; }, async verify(entry, expected) {
    const call = calls++;
    return call !== rejectAt && entry.proof === fakeProof(entry.circuitId, expected) && entry.publicInputs.length === expected.length &&
      entry.publicInputs.every((value, index) => BigInt(value) === BigInt(expected[index]));
  } };
}

const good = bundleFixture(), verifier = runtime();
const accepted = await verifyBundle({ ...good, runtime: verifier });
assert.equal(verifier.calls, good.bundle.proofs.length);
assert.equal(accepted.catalogDigest, CATALOG_DIGEST);
assert.deepEqual(accepted.policy, fixturePolicy);
assert.deepEqual(accepted.groups.map(group => group.id), BATCHES.flatMap(batch => batch.groupIds));
assert.equal(accepted.groups.length, 23);
assert.ok(accepted.groups.some(group => group.status === 'observed'));
assert.ok(accepted.groups.some(group => group.status === 'empty'));
assert.ok(accepted.groups.some(group => group.status === 'denied'));
assert.deepEqual(Object.keys(accepted).sort(), ['catalogDigest', 'groups', 'policy']);
for (const group of accepted.groups) assert.deepEqual(Object.keys(group).sort(), ['id', 'status']);
assert.ok(!JSON.stringify(accepted).includes('sample-project'));
assert.ok(!JSON.stringify(accepted).includes('@'));

const identity = good.expectations[0];
assert.equal(identity.circuitId, 'identity-scope-v1');
assert.equal(identity.publicInputs.length, 778);
assert.deepEqual(identity.publicInputs.slice(0, 43), Array(43).fill(78));
assert.deepEqual(identity.publicInputs.slice(43, 75), Array(32).fill(7));
assert.equal(identity.publicInputs[107], 2); // Complete account row count.
assert.deepEqual(identity.publicInputs.slice(768), [1, 0, ...Array(8).fill(0)]);
assert.equal(good.expectations.filter(item => item.circuitId === 'query-scope-v1').length, 5);
assert.equal(good.expectations.filter(item => item.circuitId === 'timestamps-v1').length, 5);
for (const expectation of good.expectations) {
  if (expectation.circuitId === 'query-scope-v1') assert.equal(expectation.publicInputs.length, 734);
  if (expectation.circuitId === 'headers-small-v1') assert.equal(expectation.publicInputs.length, 528);
  if (expectation.circuitId === 'atoms-small-v1') assert.equal(expectation.publicInputs.length, 272);
  if (expectation.circuitId === 'timestamps-v1') {
    assert.equal(expectation.publicInputs.length, 200);
    assert.deepEqual(expectation.publicInputs.slice(198), [fixturePolicy.cutoff, fixturePolicy.windowDays]);
  }
  for (const slot of expectation.slots) assert.deepEqual(Object.keys(slot).sort(), ['direction', 'end', 'hash', 'length', 'start', 'step']);
}

const noEvents = bundleFixture({ empty: true });
const absent = noEvents.bundle.proofs.filter(entry => entry.circuitId === 'timestamps-v1');
assert.equal(absent.length, 5);
assert.ok(absent.every(entry => JSON.stringify(entry) === JSON.stringify(absent[0])));
assert.ok((await verifyBundle({ ...noEvents, runtime: runtime() })).groups.every(group => group.status === 'empty'));

const find = (value, id) => value.bundle.proofs.find(entry => entry.circuitId === id) ??
  (id === 'header-v1' ? value.bundle.proofs.find(entry => entry.circuitId === 'headers-small-v1') : undefined);
const mutations = [
  value => { value.sessions[0].receipt.results.filter(result => result.type === 'RECV' && result.action.kind === 'HASH')[1].value = 'cd'.repeat(32); },
  value => { const receipt = value.sessions[0].receipt;
    const second = receipt.results.filter(result => result.type === 'RECV' && result.action.kind === 'HASH')[1];
    receipt.results.splice(receipt.results.indexOf(second), 1); },
  value => { value.bundle.proofs.pop(); },
  value => { value.bundle.proofs.push(structuredClone(find(value, 'header-v1'))); },
  value => { value.bundle.proofs[0].circuitId = 'caller-circuit'; },
  value => { value.bundle.proofs[0].verificationKey = 'caller-key'; },
  value => { value.bundle.extra = 'unrequested'; },
  value => { value.bundle.kind = 'PLAINTEXT_RESULT'; },
  value => { value.bundle.version = 2; },
  value => { value.bundle.proofs[0].publicInputs[0] = field(65); },
  value => { find(value, 'query-scope-v1').publicInputs[43] = field(8); },
  value => { find(value, 'query-scope-v1').publicInputs[75] = field(0); },
  value => { find(value, 'query-scope-v1').publicInputs[76] = field(1); },
  value => { find(value, 'timestamps-v1').publicInputs[198] = field(fixturePolicy.cutoff + 1); },
  value => { find(value, 'timestamps-v1').publicInputs[199] = field(7); },
  value => { find(value, 'atom-v1').publicInputs[0] = field(255); },
  value => { find(value, 'atom-v1').publicInputs[32] = field(1); },
  value => { find(value, 'atom-v1').publicInputs[33] = field(2); },
  value => { find(value, 'header-v1').publicInputs[0] = field(255); },
  value => { const entry = find(value, 'header-v1'); entry.publicInputs[entry.circuitId === 'header-v1' ? 32 : 512] = field(1); },
  value => { find(value, 'header-v1').proof = 'AQ=='; },
  value => { const indices = value.bundle.proofs.flatMap((entry, index) => ['atom-v1', 'atoms-small-v1'].includes(entry.circuitId) ? [index] : []);
    value.bundle.proofs[indices[1]] = structuredClone(value.bundle.proofs[indices[0]]); },
  value => { const index = value.bundle.proofs.findIndex(entry => entry.circuitId === 'atom-v1'); value.bundle.proofs.splice(index, 1); },
  value => { [value.bundle.proofs[0], value.bundle.proofs[1]] = [value.bundle.proofs[1], value.bundle.proofs[0]]; },
  value => { [value.bundle.sessionIds[0], value.bundle.sessionIds[1]] = [value.bundle.sessionIds[1], value.bundle.sessionIds[0]]; },
  value => { value.bundle.sessionIds.pop(); },
  value => { value.sessions[1].expected.sessionId = value.sessions[0].expected.sessionId;
    value.sessions[1].receipt.session.id = value.sessions[0].expected.sessionId;
    value.bundle.sessionIds[1] = value.sessions[0].expected.sessionId; },
  value => { value.sessions[1].expected.proofId = '33333333-3333-4333-8333-333333333333';
    value.sessions[1].receipt.session.proofId = value.sessions[1].expected.proofId; },
  value => { value.sessions[1].receipt.server_name = 'attacker.invalid'; },
  value => { value.sessions[0].receipt.transcript.sent = value.sessions[0].receipt.transcript.sent.replace('\0', 'X'); },
  value => { const hash = value.sessions[0].receipt.results.find(result => result.action.kind === 'HASH').value;
    value.sessions[1].receipt.results.find(result => result.action.kind === 'HASH').value = hash; },
  value => { value.policy = { ...fixturePolicy, cutoff: fixturePolicy.cutoff + 1 }; },
  value => { value.bundle.proofs[0].publicInputs[43] = '-1'; },
  value => { value.bundle.proofs[0].publicInputs[43] = field(256); },
  value => { value.bundle.proofs[0].publicInputs[43] = 7; },
  value => { value.bundle.proofs[0].publicInputs.push(field(0)); },
  value => { find(value, 'atoms-small-v1').publicInputs[0] = field(255); },
  value => { find(value, 'atoms-small-v1').publicInputs[256] = field(1); },
  value => { find(value, 'atoms-small-v1').publicInputs[264] = field(2); },
  value => { const entry = value.bundle.proofs.filter(item => item.circuitId === 'atoms-small-v1').at(-1);
    const inactive = entry.publicInputs.slice(256, 264).findIndex(item => BigInt(item) === 0n);
    assert.ok(inactive >= 0); entry.publicInputs[264 + inactive] = field(1); },
];
for (const [index, mutate] of mutations.entries()) {
  const value = structuredClone(good); mutate(value);
  await assert.rejects(verifyBundle({ ...value, runtime: runtime() }), expectedError, `Mutation ${index}`);
}
const stop = runtime(0);
await assert.rejects(verifyBundle({ ...good, runtime: stop }), expectedError);
assert.equal(stop.calls, 1); // A forged identity scope never authorizes later proofs.
await assert.rejects(verifyBundle({ ...good, runtime: runtime(good.bundle.proofs.length - 1) }), expectedError);
assert.throws(() => assembleBundleExpectations(good.inspections.slice(1), Array(32).fill(7), fixturePolicy, fixtureNonce), expectedError);
assert.throws(() => validateBundleShape({ ...good.bundle, proofs: Array(129).fill(good.bundle.proofs[0]) }), expectedError);
assert.throws(() => validateBundleShape({ ...good.bundle,
  proofs: Array(128).fill({ ...good.bundle.proofs[0], proof: 'A'.repeat(32768) }) }), expectedError);
console.log(JSON.stringify({ suite: 'GCP private proof bundle binding', accepted: 2,
  rejected: mutations.length + 5, groups: accepted.groups.length, proofs: good.bundle.proofs.length }));
