import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { planAzureSession, createAzurePrivatePlan } from './browser-plan.mjs';
import { syntheticAzureAttempt, syntheticAzureSources, syntheticAzureWitnesses } from './browser-plan.fixtures.mjs';
import { headerProofExpectations } from './activity-bindings.mjs';
import { azureBundleExpectations, verifyAzureBundle } from './verify-bundle.mjs';

globalThis.crypto ??= webcrypto;
const pins = JSON.parse(readFileSync(new URL('./generated/artifacts.json', import.meta.url)));
const fields = (circuitId, inputs) => {
  const artifact = JSON.parse(readFileSync(new URL(`./dist/${pins.circuits[circuitId].artifactFile}`, import.meta.url)));
  return artifact.abi.parameters.filter(p => p.visibility === 'public').flatMap(p => [inputs[p.name]].flat(Infinity))
    .map(value => `0x${BigInt(value).toString(16).padStart(64, '0')}`);
};
const names = ['date', 'cache-control', 'connection', 'expires', 'pragma', 'strict-transport-security',
  'x-cache', 'x-content-type-options', 'x-ms-correlation-request-id',
  'x-ms-ratelimit-remaining-subscription-global-reads', 'x-ms-ratelimit-remaining-subscription-reads',
  'x-ms-request-id', 'x-ms-routing-request-id', 'x-msedge-ref', 'vary', 'x-ms-operation-identifier',
  'request-context', 'access-control-allow-origin', 'api-supported-versions', 'mise-correlation-id'];
function headers(source, length, count = 0) {
  return { ...source,
    sent: Buffer.from(source.sent.toString().replace(/Authorization: [^\r]+/, 'Authorization: ' + 'x'.repeat(length))),
    recv: source.meta.step === 'identity' ? source.recv : Buffer.from(source.recv.toString().replace('\r\n\r\n',
      names.slice(0, count).map(name => `\r\n${name}: ${'h'.repeat(length)}`).join('') + '\r\n\r\n')) };
}

test('existing header batching covers every original byte at 64/65/256/257 boundaries and rejects invalid bytes', () => {
  for (const length of [1, 64, 65, 128, 193, 256, 257, 2048, 2049]) {
    const attempt = syntheticAzureAttempt(), source = headers(syntheticAzureSources(attempt)[0], length);
    const planned = planAzureSession(source.meta, source, attempt), start = source.sent.indexOf('Authorization: ') + 15;
    const chunks = planned.privateSlots.sent, capacity = length <= 256 ? 64 : 2048;
    assert.equal(chunks.length, Math.ceil(length / capacity));
    assert.equal(chunks[0].start, start); assert.equal(chunks.at(-1).end, start + length);
    chunks.forEach((chunk, i) => {
      assert.equal(chunk.start, start + i * capacity); assert.equal(chunk.end, Math.min(chunk.start + capacity, start + length));
    });
    assert.equal(planned.inspection.headerObligations.reduce((sum, slot) => sum + slot.length, 0), length);
    for (const byte of [0, 127, 128]) {
      const sent = Buffer.from(source.sent); sent[start + length - 1] = byte;
      assert.throws(() => planAzureSession(source.meta, { ...source, sent }, attempt), /AZURE_PRIVATE_PLAN_INVALID/);
    }
  }
});

test('native range overflow retries the original layout and still rejects an original layout above 256 ranges', () => {
  const attempt = syntheticAzureAttempt(), source = headers(syntheticAzureSources(attempt, { rows: 8 })[2], 193, names.length);
  assert.ok(source.recv.length <= 16384);
  const planned = planAzureSession(source.meta, source, attempt);
  assert.ok(planned.selections.recv.length <= 256);
  assert.equal(planned.inspection.headerObligations.filter(slot => slot.length === 193).length, names.length + 1);
  const oversized = syntheticAzureSources(attempt, { rows: 8 })[2];
  const [head, body] = oversized.recv.toString().split('\r\n\r\n'), json = JSON.parse(body);
  for (const row of json.value) {
    row.id = 'x'; row.submissionTimestamp = 'x'; row.category = { value: 'x', localizedValue: 'x' };
    for (const key of ['eventName', 'operationName', 'status']) row[key].localizedValue = 'x';
  }
  const replacement = JSON.stringify(json);
  oversized.recv = Buffer.from(head.replace(/Content-Length: \d+/, `Content-Length: ${Buffer.byteLength(replacement)}`) + '\r\n\r\n' + replacement);
  assert.ok(oversized.recv.length <= 16384);
  assert.throws(() => planAzureSession(oversized.meta, oversized, attempt), /AZURE_PRIVATE_PLAN_INVALID/);
});

test('identity and ARM headers use the same padded batch ABI with deterministic order and strict input bounds', () => {
  const refs = Array.from({ length: 17 }, (_, i) => ({ circuitId: 'header-v1', hash: (i + 1).toString(16).padStart(64, '0'), length: 64 }));
  refs.push({ circuitId: 'header-v1', hash: 'a'.repeat(64), length: 257 });
  const result = headerProofExpectations(refs);
  assert.deepEqual(result.map(row => row.circuitId), ['headers-small-v1', 'headers-small-v1', 'header-v1']);
  assert.equal(result[0].publicInputs.length, 528);
  assert.equal(BigInt(result[1].publicInputs[512]), 64n);
  assert.ok(result[1].publicInputs.slice(513).every(value => BigInt(value) === 0n));
  for (const bad of [{ ...refs[0], length: 2049 }, { ...refs[0], length: 0 }, { ...refs[0], circuitId: 'atom-v1' }, { ...refs[0], hash: 'bad' }]) {
    assert.throws(() => headerProofExpectations([bad]));
  }
});

test('client openings and server receipt-derived expectations agree for medium headers without new circuits', async () => {
  const attempt = syntheticAzureAttempt(), witnesses = syntheticAzureWitnesses(attempt, { transformSource: source => headers(source, 193, 6) });
  const snapshots = [], retained = [];
  const planner = createAzurePrivatePlan({ attempt, proveCircuit: async (circuitId, inputs) => {
    if (circuitId === 'headers-small-v1') {
      retained.push(inputs);
      for (let i = 0; i < 16; i++) if (inputs.lengths[i]) {
        const hash = createHash('sha256').update(Uint8Array.from(inputs.preimages[i].slice(0, inputs.lengths[i] + 16))).digest();
        assert.deepEqual(Array.from(hash), inputs.hashes[i]);
        assert.ok(inputs.lengths[i] <= 64);
      }
    }
    snapshots.push(circuitId);
    return { circuitId, proof: 'AQID', publicInputs: fields(circuitId, inputs) };
  } });
  const result = await planner.prove(witnesses, new AbortController().signal);
  // Seven medium values per ARM session -> 28 chunks -> two batches; identity -> one batch.
  assert.equal(snapshots.filter(id => id === 'headers-small-v1').length, 5);
  assert.equal(snapshots.filter(id => id === 'header-v1').length, 0);
  assert.ok(retained.every(inputs => inputs.preimages.flat().every(value => value === 0)));
  const sessions = witnesses.map(witness => ({ receipt: witness.syntheticReceipt,
    expected: { ...attempt, step: witness.step, sessionId: witness.sessionId } }));
  assert.deepEqual(result.proofs.map(({ circuitId, publicInputs }) => ({ circuitId, publicInputs })), azureBundleExpectations(sessions, result));
  const calls = [];
  await verifyAzureBundle({ sessions, bundle: result, runtime: { verify: async proof => { calls.push(proof.circuitId); return true; } } });
  assert.equal(calls.length, result.proofs.length); // Structural mock only, not real cryptographic acceptance.
  const changed = structuredClone(result), changedHeader = changed.proofs.find(proof => proof.circuitId === 'headers-small-v1');
  changedHeader.publicInputs[0] = '0x' + (BigInt(changedHeader.publicInputs[0]) ^ 1n).toString(16).padStart(64, '0');
  let verifies = 0;
  await assert.rejects(verifyAzureBundle({ sessions, bundle: changed, runtime: { verify: async () => { verifies++; return true; } } }));
  assert.equal(verifies, 0);
});

test('a changed opening in any newly split header rejects before proving', async () => {
  const attempt = syntheticAzureAttempt(), witnesses = syntheticAzureWitnesses(attempt, { transformSource: source => headers(source, 193, 6) });
  witnesses[0].openings.sent[1].blinder[0] ^= 1;
  let calls = 0;
  const planner = createAzurePrivatePlan({ attempt, proveCircuit: async () => { calls++; throw new Error(); } });
  await assert.rejects(planner.prove(witnesses, new AbortController().signal));
  assert.equal(calls, 0);
});
