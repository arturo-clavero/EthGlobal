import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { createAzurePrivatePlan, planAzureSession } from './browser-plan.mjs';
import { AZURE_ACTIVITY_PROFILES } from './browser-result.mjs';
import { syntheticAzureAttempt, syntheticAzureSources, syntheticAzureWitnesses } from './browser-plan.fixtures.mjs';

globalThis.crypto ??= webcrypto;
const pins = JSON.parse(readFileSync(new URL('./generated/artifacts.json', import.meta.url)));
function publicFields(circuitId, inputs) {
  const artifact = JSON.parse(readFileSync(new URL(`./dist/${pins.circuits[circuitId].artifactFile}`, import.meta.url)));
  return artifact.abi.parameters.filter(p => p.visibility === 'public').flatMap(p => [inputs[p.name]].flat(Infinity))
    .map(value => `0x${BigInt(value).toString(16).padStart(64, '0')}`);
}

test('planner hides employer values and entire claims keys before native disclosure', () => {
  const attempt = syntheticAzureAttempt(), witnesses = syntheticAzureWitnesses(attempt);
  for (const witness of witnesses) {
    const receipt = JSON.stringify(witness.syntheticReceipt);
    for (const value of ['PRIVATE_', 'private-rule', 'private-group', 'employerPrivateKey', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa']) {
      assert.equal(receipt.includes(value), false);
    }
    assert.ok(witness.selections.sent.length <= 256 && witness.selections.recv.length <= 256);
  }
});

test('planner fails before disclosure on wrong source binding and unknown exposed schema', () => {
  const attempt = syntheticAzureAttempt(), source = syntheticAzureSources(attempt)[1];
  assert.throws(() => planAzureSession({ ...source.meta, nonceMac: 'z'.repeat(43) }, source, attempt));
  const changed = Buffer.from(source.recv.toString().replace('"state"', '"other"'));
  assert.throws(() => planAzureSession(source.meta, { sent: source.sent, recv: changed }, attempt));
});

test('synthetic planner binds every row and returns public metadata only; mock proofs are not acceptance', async () => {
  const attempt = syntheticAzureAttempt(), witnesses = syntheticAzureWitnesses(attempt, { rows: 2 }), calls = [];
  const planner = createAzurePrivatePlan({ attempt, proveCircuit: async (circuitId, inputs, signal, total) => {
    calls.push({ circuitId, inputs, total });
    return { circuitId, proof: 'AQID', publicInputs: publicFields(circuitId, inputs) };
  } });
  const result = await planner.prove(witnesses, new AbortController().signal);
  assert.ok(calls.every(call => call.total === result.proofs.length));
  assert.equal(result.claim, 'AZURE_NSG_RULE_OPERATION'); assert.equal(result.sessionIds.length, 3);
  assert.equal(result.bindings.claims.length, 2); assert.equal(result.bindings.selectedRow, 0);
  assert.equal(calls.filter(value => value.circuitId === 'activity-atoms-v1').length, 2);
  assert.equal(calls.filter(value => value.circuitId === 'claims-chunk-v1').length, 4);
  assert.ok(calls[0].inputs.response_preimage.every(value => value === 0));
  assert.ok(!JSON.stringify(result).includes('private-rule'));
  await assert.rejects(planner.prove(witnesses, new AbortController().signal));
});

test('altered opening and substituted session fail before proof generation', async () => {
  const attempt = syntheticAzureAttempt();
  for (const mutate of [w => { w[1].openings.recv[0].blinder[0] ^= 1; }, w => { w[2].sessionId = w[1].sessionId; }]) {
    const witnesses = syntheticAzureWitnesses(attempt); mutate(witnesses); let calls = 0;
    const planner = createAzurePrivatePlan({ attempt, proveCircuit: async () => { calls++; throw new Error(); } });
    await assert.rejects(planner.prove(witnesses, new AbortController().signal)); assert.equal(calls, 0);
  }
});

test('wrong proof public inputs reject and erase derived witness copies', async () => {
  const attempt = syntheticAzureAttempt(), witnesses = syntheticAzureWitnesses(attempt); let held;
  const planner = createAzurePrivatePlan({ attempt, proveCircuit: async (circuitId, inputs) => {
    held = inputs; const publicInputs = publicFields(circuitId, inputs); publicInputs[0] = publicInputs[0] === '0x00' ? '0x01' : '0x00';
    return { circuitId, proof: 'AQID', publicInputs };
  } });
  await assert.rejects(planner.prove(witnesses, new AbortController().signal));
  assert.ok(held.response_preimage.every(value => value === 0)); assert.ok(held.salt.every(value => value === 0));
});

function catalogSource(source, operation, operationCase = value => value) {
  if (source.meta.step !== 'activity') return source;
  const text = source.recv.toString(), boundary = text.indexOf('\r\n\r\n');
  const body = JSON.parse(text.slice(boundary + 4));
  const [provider, type] = operation.split('/');
  for (const row of body.value) {
    row.operationName.value = operationCase(operation);
    const scope = row.resourceId.split('/providers/')[0];
    if (operation === 'Microsoft.Sql/servers/databases/write') row.resourceId = `${scope}/providers/Microsoft.Sql/servers/private-server/databases/private-db`;
    else if (operation === 'Microsoft.DataFactory/factories/pipelines/write') row.resourceId = `${scope}/providers/Microsoft.DataFactory/factories/private-factory/pipelines/private-pipeline`;
    else if (operation.startsWith('Microsoft.Resources/subscriptions/resourceGroups/')) row.resourceId = scope;
    else if (operation === 'Microsoft.Authorization/roleAssignments/write') row.resourceId = `${scope}/providers/Microsoft.Authorization/roleAssignments/dddddddd-1111-2222-3333-444444444444`;
    else row.resourceId = `${scope}/providers/${provider}/${type}/private-name`;
  }
  const json = JSON.stringify(body);
  const headers = text.slice(0, boundary).replace(/Content-Length: \d+/, `Content-Length: ${Buffer.byteLength(json)}`);
  return { ...source, recv: Buffer.from(`${headers}\r\n\r\n${json}`) };
}

// Requires root's real generated ABI. Mock proofs establish plumbing only.
test('catalog producer binds every row and accepts ASCII operation casing without changing raw commitments', async () => {
  for (const operationCase of [value => value, value => value.toLowerCase(), value => value.replace(/[a-z]/g, letter => letter.toUpperCase())])
  for (const [claim, profile] of Object.entries(AZURE_ACTIVITY_PROFILES)) {
    if (profile.code === undefined) continue;
    const attempt = syntheticAzureAttempt(), calls = [];
    const witnesses = syntheticAzureWitnesses(attempt, { rows: 2, transformSource: source => catalogSource(source, profile.operations[0], operationCase) });
    const planner = createAzurePrivatePlan({ attempt, proveCircuit: async (circuitId, inputs, signal, total) => {
      calls.push({ circuitId, code: inputs.profile_code, total });
      return { circuitId, proof: 'AQID', publicInputs: publicFields(circuitId, inputs) };
    } });
    const result = await planner.prove(witnesses, new AbortController().signal);
    assert.equal(result.claim, claim);
    const pairs = calls.filter(call => call.circuitId === 'catalog-activity-atoms-v1');
    assert.equal(pairs.length, 2); assert.ok(pairs.every(call => call.code === profile.code));
    assert.ok(calls.every(call => call.total === result.proofs.length));
    assert.doesNotMatch(JSON.stringify(result), /private-[a-z]|employerPrivateKey|PRIVATE_(?:identity|tenant|activity)/);
  }
});

test('catalog producer rejects changed public code or substituted rule circuit and clears inputs', async () => {
  for (const mutation of ['code', 'circuit']) {
    const attempt = syntheticAzureAttempt(); let held;
    const planner = createAzurePrivatePlan({ attempt, proveCircuit: async (circuitId, inputs) => {
      const publicInputs = publicFields(circuitId, inputs);
      if (circuitId === 'catalog-activity-atoms-v1') {
        held = inputs;
        if (mutation === 'code') publicInputs[715] = '0';
        else circuitId = 'activity-atoms-v1';
      }
      return { circuitId, proof: 'AQID', publicInputs };
    } });
    await assert.rejects(planner.prove(syntheticAzureWitnesses(attempt, {
      transformSource: source => catalogSource(source, 'Microsoft.Network/networkSecurityGroups/write'),
    }), new AbortController().signal));
    assert.ok(held.resource.flat().every(value => value === 0));
  }
});


test('catalog operation matching rejects Unicode lookalikes and changed action suffixes before proving', async () => {
  for (const operationCase of [value => value.replace('KeyVault', 'KeyVault'), value => value + '/action']) {
    const attempt = syntheticAzureAttempt(); let calls = 0;
    const planner = createAzurePrivatePlan({ attempt, proveCircuit: async () => { calls++; throw new Error(); } });
    await assert.rejects(async () => {
      const witnesses = syntheticAzureWitnesses(attempt, { transformSource: source =>
        catalogSource(source, 'Microsoft.KeyVault/vaults/write', operationCase) });
      await planner.prove(witnesses, new AbortController().signal);
    });
    assert.equal(calls, 0); planner.clear();
  }
});
