import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { fixture, expected, activity } from './test-fixtures.mjs';
import { inspectActivityReceipt } from './source-receipt.mjs';
import { azureBundleExpectations, verifyAzureBundle } from './verify-bundle.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const now = Date.parse('2026-10-31T00:00:01Z');
function identityReceipt(context) {
  const prefix = `GET /v1.0/me?$select=id HTTP/1.1\r\nHost: graph.microsoft.com\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nx-azure-proof-nonce: ${context.nonceMac}\r\nx-azure-proof-step: identity\r\nAuthorization: `;
  const secret = 'Bearer SYNTHETIC_CREDENTIAL', suffix = '\r\n\r\n';
  const config = { sent: [], recv: [] }, results = [];
  const add = (direction, start, end, hidden, value) => {
    const handler = { type: direction.toUpperCase(), part: 'BODY',
      action: hidden ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' } };
    config[direction].push({ start, end, handler }); results.push({ ...handler, value });
  };
  add('sent', 0, prefix.length, false, prefix);
  add('sent', prefix.length, prefix.length + secret.length, true, hash(secret));
  add('sent', prefix.length + secret.length, prefix.length + secret.length + suffix.length, false, suffix);
  add('recv', 0, 150, true, hash('synthetic private Graph response'));
  return { server_name: 'graph.microsoft.com', session: { id: context.sessionId, proofId: context.proofId,
    pluginSha256: context.pluginSha256, nonceMac: context.nonceMac, step: 'identity', method: 'AZURE_WORK_PRIVATE', mode: 'Proxy' },
    config, results, transcript: { sent: prefix + '\0'.repeat(secret.length) + suffix,
      sent_length: prefix.length + secret.length + suffix.length, recv: '\0'.repeat(150), recv_length: 150 } };
}
function setup() {
  const contexts = ['identity', 'tenant', 'activity'].map((step, index) => ({ ...expected(step),
    sessionId: `${index + 3}1111111-1111-1111-1111-111111111111`, challenge: hash('challenge'),
    issuedAt: now - 1000, cutoffMs: now - 1000, expiresAt: now + 60000 }));
  const body = activity(); body.value.push(structuredClone(body.value[0]));
  const sessions = [
    { expected: contexts[0], receipt: identityReceipt(contexts[0]) },
    { expected: contexts[1], receipt: fixture('tenant', { context: contexts[1] }).receipt },
    { expected: contexts[2], receipt: fixture('activity', { context: contexts[2], value: body }).receipt },
  ];
  const rows = inspectActivityReceipt(sessions[2].receipt, contexts[2]).body.rows;
  const bundle = { kind: 'AZURE_PRIVATE_RESULT', version: 1, claim: 'AZURE_NSG_RULE_OPERATION',
    sessionIds: contexts.map(context => context.sessionId), bindings: {
      graphActorHash: hash('actor'), identityBinding: hash('identity binding'), selectedRow: 0,
      claims: rows.map((row, i) => ({ stateHashes: Array.from({ length: row.claims.chunks.length + 1 }, (_, n) => hash(`state${i}/${n}`)),
        identityHashes: [hash(`actor${i}`), hash(`tenant${i}`)] })),
    }, proofs: [] };
  bundle.proofs = azureBundleExpectations(sessions, bundle, now).map(target => ({ ...target, proof: 'AA==' }));
  return { sessions, bundle, now };
}

// Structural composition tests deliberately stub cryptography.
test('requires every source-derived obligation before issuing the narrow operation claim', async () => {
  const input = setup(), calls = [];
  const verdict = await verifyAzureBundle({ ...input, runtime: { verify: async entry => { calls.push(entry.circuitId); return true; } } });
  assert.deepEqual(verdict, { claim: 'AZURE_NSG_RULE_OPERATION', attribution: 'signed-in-user', windowDays: 14 });
  assert.equal(calls.length, input.bundle.proofs.length);
  assert.equal(calls.filter(id => id === 'activity-atoms-v1').length, 2);
  assert.equal(calls.filter(id => id === 'claims-chunk-v1').length, 4);
});

test('rejects source/attempt/expiry/claim substitution before expensive proof verification', async () => {
  for (const mutate of [
    f => { f.sessions[1].receipt.server_name = 'attacker.invalid'; },
    f => { f.sessions[2].receipt.session.method = 'AZURE_LOCAL_PILOT'; },
    f => { f.sessions[1].expected.challenge = hash('wrong challenge'); },
    f => { f.sessions[2].expected.cutoffMs--; },
    f => { f.sessions[2].receipt.session.nonceMac = 'x'.repeat(43); },
    f => { f.sessions[0].expected.pluginSha256 = hash('wrong plugin'); },
    f => { f.now += 3600001; }, f => { f.now -= 2000; },
    f => { f.bundle.sessionIds.reverse(); }, f => { f.bundle.sessionIds[1] = f.bundle.sessionIds[0]; },
    f => { f.bundle.claim = 'AZURE_CONFIGURATION_CHANGED'; },
    f => { f.bundle.bindings.privateEmployerName = 'should never leave browser'; },
    f => { f.sessions.pop(); },
  ]) {
    const input = setup(); mutate(input); let calls = 0;
    await assert.rejects(verifyAzureBundle({ ...input, runtime: { verify: async () => { calls++; return true; } } }), /AZURE_PRIVATE_BUNDLE_INVALID/);
    assert.equal(calls, 0);
  }
});

test('rejects missing, reordered, extra or mismatched proofs before cryptography', async () => {
  for (const mutate of [
    f => { f.bundle.proofs.pop(); }, f => { f.bundle.proofs.reverse(); },
    f => { f.bundle.proofs.push(f.bundle.proofs[0]); },
    f => { f.bundle.proofs.at(-1).publicInputs[0] = '0xff'; },
    f => { f.bundle.bindings.selectedRow = 1; },
    f => { f.bundle.bindings.claims[1].stateHashes[0] = hash('wrong carry'); },
    f => { f.bundle.bindings.graphActorHash = hash('another user'); },
    f => { f.bundle.bindings.identityBinding = hash('another binding'); },
    f => { f.bundle.proofs[0].verificationKey = 'attacker key'; },
  ]) {
    const input = setup(); mutate(input); let calls = 0;
    await assert.rejects(verifyAzureBundle({ ...input, runtime: { verify: async () => { calls++; return true; } } }), /AZURE_PRIVATE_BUNDLE_INVALID/);
    assert.equal(calls, 0);
  }
});

test('one rejected or throwing cryptographic check prevents all acceptance', async () => {
  for (const rejected of [0, 3, setup().bundle.proofs.length - 1]) {
    const input = setup(); let calls = 0;
    await assert.rejects(verifyAzureBundle({ ...input, runtime: { verify: async () => calls++ !== rejected } }), /AZURE_PRIVATE_BUNDLE_INVALID/);
    assert.equal(calls, rejected + 1);
  }
  await assert.rejects(verifyAzureBundle({ ...setup(), runtime: { verify: async () => { throw new Error('worker stopped'); } } }), /AZURE_PRIVATE_BUNDLE_INVALID/);
});

test('owns the public bundle before awaiting checks, so a caller cannot swap later obligations', async () => {
  const input = setup(); let calls = 0;
  const verdict = await verifyAzureBundle({ ...input, runtime: { verify: async () => {
    if (calls++ === 0) { input.bundle.proofs.length = 0; input.bundle.bindings.identityBinding = hash('changed during verification'); }
    return true;
  } } });
  assert.equal(verdict.claim, 'AZURE_NSG_RULE_OPERATION');
  assert.ok(calls > 3);
});

// Plumbing only: mocked crypto cannot establish catalog predicate acceptance.
test('catalog code is checked for every comparison row before crypto', async () => {
  const claims = ['AZURE_NSG_OPERATION', 'AZURE_VM_WRITE', 'AZURE_WEB_APP_WRITE', 'AZURE_AKS_CLUSTER_WRITE',
    'AZURE_VIRTUAL_NETWORK_WRITE', 'AZURE_STORAGE_ACCOUNT_WRITE', 'AZURE_KEY_VAULT_WRITE', 'AZURE_METRIC_ALERT_WRITE',
    'AZURE_SQL_DATABASE_WRITE', 'AZURE_DATA_PIPELINE_WRITE', 'AZURE_RESOURCE_GROUP_OPERATION', 'AZURE_DEPLOYMENT_WRITE', 'AZURE_ROLE_ASSIGNMENT_WRITE', 'AZURE_WEB_SLOT_SWAP'];
  for (const [index, claim] of claims.entries()) {
    const input = setup(); input.bundle.claim = claim;
    input.bundle.proofs = azureBundleExpectations(input.sessions, input.bundle, input.now).map(target => ({ ...target, proof: 'AA==' }));
    const pairs = input.bundle.proofs.filter(entry => entry.circuitId === 'catalog-activity-atoms-v1');
    assert.equal(pairs.length, 2);
    assert.ok(pairs.every(entry => entry.publicInputs.length === 716 && BigInt(entry.publicInputs[715]) === BigInt(index + 1)));
    for (const mutate of [
      bundle => { bundle.claim = claims[(index + 1) % claims.length]; },
      bundle => { bundle.proofs.filter(entry => entry.circuitId === 'catalog-activity-atoms-v1')[1].publicInputs[715] = '0'; },
      bundle => { bundle.proofs.filter(entry => entry.circuitId === 'catalog-activity-atoms-v1')[0].publicInputs.pop(); },
      bundle => { bundle.profile_code = index + 1; },
    ]) {
      const bundle = structuredClone(input.bundle); mutate(bundle); let calls = 0;
      await assert.rejects(verifyAzureBundle({ ...input, bundle, runtime: { verify: async () => { calls++; return true; } } }));
      assert.equal(calls, 0);
    }
  }
});
