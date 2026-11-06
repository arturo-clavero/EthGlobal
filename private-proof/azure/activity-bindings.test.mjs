import assert from 'node:assert/strict';
import test from 'node:test';
import { activityProofExpectations } from './activity-bindings.mjs';
import { AZURE_ACTIVITY_PROFILES } from './browser-result.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const field = n => `0x${BigInt(n).toString(16).padStart(64, '0')}`;
const digestFields = value => Array.from(Buffer.from(value, 'hex'), field);
function fixture() {
  let serial = 1;
  const ref = length => ({ start: 100, end: 100 + length, length, hash: hash(serial++) });
  const rows = Array.from({ length: 2 }, (_, i) => ({
    claims: { start: 1000 + i * 2000, end: 1600 + i * 2000, length: 600, chunks: [
      { start: 1000 + i * 2000, end: 1512 + i * 2000, kind: 6, hash: hash(serial++) },
      { start: 1512 + i * 2000, end: 1600 + i * 2000, kind: 6, hash: hash(serial++) },
    ] },
    subscription: ref(38), eventId: ref(38), operationId: ref(38), correlationId: ref(38),
    event: ref(12), operation: ref(61), status: ref(11), timestamp: ref(22), resource: ref(180),
  }));
  const headers = () => [{ circuitId: 'header-v1', ...ref(25) }];
  const uuidLink = reference => ({ predicate: 'request-uuid', request: ref(36), reference });
  const body = { subscription: ref(38), tenant: ref(38), state: ref(9) };
  return {
    tenant: { body, headerObligations: headers(), requestUuidObligations: [uuidLink(body.subscription)] },
    activity: { body: { rows }, headerObligations: headers(),
      requestUuidObligations: rows.flatMap(row => [uuidLink(row.subscription), uuidLink(row.correlationId)]) },
    context: { challenge: hash(90), cutoffMs: 1793404800000 },
    bindings: { graphActorHash: hash(91), identityBinding: hash(92), selectedRow: 1,
      claims: rows.map(() => ({ stateHashes: [hash(serial++), hash(serial++), hash(serial++)],
        identityHashes: [hash(serial++), hash(serial++)] })) },
  };
}
const compose = (f, claim = 'AZURE_NSG_RULE_OPERATION') => activityProofExpectations(f.tenant, f.activity, f.context, f.bindings, claim);

test('requires every native header/request link, every claims chunk and every correlation row', () => {
  const f = fixture(), { proofs, references } = compose(f);
  assert.equal(proofs.length, 16);
  assert.deepEqual(proofs.map(p => p.circuitId), [
    'headers-small-v1', 'request-uuid-v1', 'headers-small-v1', ...Array(4).fill('request-uuid-v1'),
    'subscription-state-v1', 'identity-link-v1', ...Array(4).fill('claims-chunk-v1'),
    'scope-link-v1', 'activity-atoms-v1', 'activity-atoms-v1',
  ]);
  const pairs = proofs.filter(p => p.circuitId === 'activity-atoms-v1');
  for (const [i, pair] of pairs.entries()) {
    assert.equal(pair.publicInputs.length, 715);
    assert.deepEqual(pair.publicInputs.slice(0, 32), digestFields(f.bindings.claims[1].identityHashes[0]));
    assert.deepEqual(pair.publicInputs.slice(352, 384), digestFields(f.bindings.claims[i].identityHashes[0]));
    assert.equal(pair.publicInputs.at(-1), field(f.context.cutoffMs));
  }
  assert.equal(references.resource.hash, f.activity.body.rows[1].resource.hash);
  assert.equal(references.correlationId.hash, f.activity.body.rows[1].correlationId.hash);
  assert.equal(Object.hasOwn(references, 'accepted'), false);
});

test('scope ties Graph, tenant and selected Activity identities to the same claims commitments', () => {
  const f = fixture(), result = compose(f);
  const scope = result.proofs.find(p => p.circuitId === 'scope-link-v1');
  assert.deepEqual(scope.publicInputs, [f.bindings.graphActorHash, f.bindings.claims[1].identityHashes[0],
    f.tenant.body.tenant.hash, f.bindings.claims[1].identityHashes[1], f.tenant.body.subscription.hash,
    f.activity.body.rows[1].subscription.hash].flatMap(digestFields));
  const identity = result.proofs.find(p => p.circuitId === 'identity-link-v1');
  assert.deepEqual(identity.publicInputs, [f.bindings.graphActorHash, f.context.challenge, f.bindings.identityBinding].flatMap(digestFields));
});

test('rejects missing rows/chunks, unsupported fields, invalid selection and malformed commitments', () => {
  const mutations = [
    f => { f.bindings.claims.pop(); }, f => { f.bindings.claims[0].stateHashes.pop(); },
    f => { f.bindings.claims[0].identityHashes[0] = 'employer-name'; },
    f => { f.bindings.claims[1].extra = 'private'; }, f => { f.bindings.extra = 'private'; },
    f => { f.bindings.selectedRow = 2; }, f => { f.bindings.selectedRow = -1; },
    f => { f.bindings.selectedRow = 0.5; }, f => { f.bindings.graphActorHash = 'AB'.repeat(32); },
    f => { f.context.challenge = 'short'; }, f => { f.context.cutoffMs = NaN; },
    f => { f.activity.body.rows = []; }, f => { f.activity.body.rows[0].claims.chunks.shift(); },
    f => { f.activity.body.rows[0].claims.chunks[0].hash = 'bad'; },
  ];
  for (const mutate of mutations) { const f = fixture(); mutate(f); assert.throws(() => compose(f), /AZURE_PRIVATE_ACTIVITY_BINDINGS_INVALID/); }
});

test('changing any authenticated source hash changes the mandatory proof inputs', () => {
  for (const mutate of [
    f => { f.tenant.body.state.hash = hash(250); },
    f => { f.tenant.body.subscription.hash = hash(250); },
    f => { f.activity.body.rows[0].operationId.hash = hash(250); },
    f => { f.activity.body.rows[0].claims.chunks[1].hash = hash(250); },
    f => { f.activity.headerObligations[0].hash = hash(250); },
    f => { f.activity.requestUuidObligations[3].request.hash = hash(250); },
  ]) {
    const f = fixture(), original = compose(f).proofs; mutate(f);
    assert.notDeepEqual(compose(f).proofs, original);
  }
});

test('covers every extra atom and hides the unknown tenant key/object behind linked proofs', () => {
  const f = fixture();
  f.tenant.atomObligations = Array.from({ length: 9 }, (_, i) => ({ circuitId: 'atom-v1',
    hash: hash(150 + i), length: 20 + i, kind: 1 }));
  f.activity.atomObligations = [{ circuitId: 'atom-v1', hash: hash(170), length: 270, kind: 1 }];
  f.tenant.extraObligations = [{ name: 'tenant-extra-v1',
    key: { hash: hash(180), length: 12 }, object: { hash: hash(181), length: 68 } }];
  const result = compose(f), batches = result.proofs.filter(p => p.circuitId === 'atoms-small-v1');
  assert.equal(batches.length, 2);
  for (const batch of batches) assert.equal(batch.publicInputs.length, 272);
  assert.deepEqual(batches[1].publicInputs.slice(0, 32), digestFields(hash(158)));
  assert.deepEqual(batches[1].publicInputs.slice(32, 256), Array(224).fill(field(0)));
  assert.deepEqual(batches[1].publicInputs.slice(256), [28, ...Array(7).fill(0), 1, ...Array(7).fill(0)].map(field));
  const extra = result.proofs.find(p => p.circuitId === 'tenant-extra-v1');
  assert.deepEqual(extra.publicInputs, [...digestFields(hash(180)), ...digestFields(hash(181)), field(12), field(68)]);
  assert.deepEqual(result.proofs.find(p => p.circuitId === 'atom-v1').publicInputs,
    [...digestFields(hash(170)), field(270), field(1)]);
  f.tenant.atomObligations[0].kind = 4;
  assert.throws(() => compose(f), /AZURE_PRIVATE_ACTIVITY_BINDINGS_INVALID/);
});

test('catalog claim code is fixed on every selected-versus-comparison obligation', () => {
  const f = fixture(), rule = compose(f).proofs;
  for (const [claim, profile] of Object.entries(AZURE_ACTIVITY_PROFILES)) {
    if (profile.code === undefined) continue;
    const proofs = compose(f, claim).proofs;
    assert.equal(proofs.length, rule.length);
    assert.deepEqual(proofs.slice(0, -2), rule.slice(0, -2));
    for (const [i, entry] of proofs.slice(-2).entries()) {
      assert.equal(entry.circuitId, 'catalog-activity-atoms-v1');
      assert.equal(entry.publicInputs.length, 716);
      assert.deepEqual(entry.publicInputs.slice(0, 715), rule.at(-2 + i).publicInputs);
      assert.equal(entry.publicInputs[715], field(profile.code));
    }
  }
  for (const claim of [undefined, null, '', '__proto__', 'constructor', 'AZURE_UNSUPPORTED_ACTION']) {
    assert.throws(() => activityProofExpectations(f.tenant, f.activity, f.context, f.bindings, claim));
  }
});
