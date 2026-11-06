import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { parseJsonStructure } from '../gcp/json-structure.mjs';
import { inspectActivityBody } from './activity-structure.mjs';

const uuid = digit => `${digit.repeat(8)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(12)}`;
const fixture = () => ({ value: [{
  claims: { 'http://schemas.microsoft.com/identity/claims/objectidentifier': uuid('1'),
    'http://schemas.microsoft.com/identity/claims/tenantid': uuid('2'), 'employer-secret-label': 'private' },
  eventDataId: uuid('3'), eventName: { value: 'EndRequest' }, eventTimestamp: '2026-10-28T00:00:00Z',
  operationId: uuid('4'), operationName: { value: 'Microsoft.Network/networkSecurityGroups/securityRules/write' },
  status: { value: 'Succeeded' }, correlationId: uuid('5'), resourceId: `/subscriptions/${uuid('6')}/resourceGroups/private/providers/Microsoft.Network/networkSecurityGroups/private/securityRules/employer-rule`,
  subscriptionId: uuid('6'),
}] });

function redacted(input) {
  const bytes = Buffer.from(typeof input === 'string' ? input : JSON.stringify(input));
  const root = parseJsonStructure(bytes).root;
  const slots = [];
  for (const row of root.entries.find(entry => entry.key.value === 'value').value.items) {
    for (const { key, value } of row.entries) {
      const node = key.value === 'claims' ? value : value.type === 'object' ? value.entries[0].value : value;
      const step = key.value === 'claims' ? 512 : node.end - node.start;
      for (let start = node.start; start < node.end; start += step) {
        const end = Math.min(start + step, node.end);
        slots.push({ start, end, kind: key.value === 'claims' ? 6 : 1,
          hash: createHash('sha256').update(bytes.subarray(start, end)).update(Buffer.alloc(16, slots.length)).digest('hex') });
      }
    }
  }
  for (const { start, end } of slots) bytes.fill(0, start, end);
  return { bytes, slots };
}

test('inspects complete rows without exposing employer keys, resource names or values', () => {
  const input = fixture(); input.value.push(structuredClone(input.value[0]));
  const { bytes, slots } = redacted(input);
  const result = inspectActivityBody(bytes, slots);
  assert.equal(result.rows.length, 2);
  assert.equal(result.requiresClaimsProofs, true);
  assert.equal(result.requiresCompleteCoverageProofs, true);
  assert.deepEqual(result.rows[0].claims, { start: slots[0].start, end: slots[0].end,
    length: slots[0].end - slots[0].start, chunks: [slots[0]] });
  for (const secret of ['employer-secret-label', 'employer-rule', uuid('1'), 'Succeeded', '2026-10-28']) {
    assert.ok(!JSON.stringify(result).includes(secret));
    assert.ok(!bytes.toString().includes(secret));
  }
});

test('opaque claims preserve exact contiguous native chunks without inventing an object hash', () => {
  const input = fixture(); input.value[0].claims.padding = 'x'.repeat(900);
  const { bytes, slots } = redacted(input), chunks = slots.filter(slot => slot.kind === 6);
  const claims = inspectActivityBody(bytes, slots).rows[0].claims;
  assert.equal(chunks.length, 3); assert.deepEqual(claims.chunks, chunks);
  assert.equal(claims.length, chunks.at(-1).end - chunks[0].start);
  assert.equal(Object.hasOwn(claims, 'hash'), false);
  for (const mutate of [x => x[0].end--, x => x[1].start--, x => x[0].end++,
    x => x[1].hash = 'not-a-hash', x => x.splice(1, 1), x => x.reverse()]) {
    const changed = structuredClone(slots); mutate(changed);
    assert.throws(() => inspectActivityBody(bytes, changed), /AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID/);
  }
});

test('missing coverage, continuation and unprojected fields fail closed', () => {
  for (const mutation of [
    input => { input.nextLink = 'private-url'; },
    input => { input.value[0].unexpected = 'private'; },
    input => { delete input.value[0].correlationId; },
    input => { input.value = []; },
    input => { input.value = Array.from({ length: 9 }, () => input.value[0]); },
  ]) {
    const input = fixture(); mutation(input);
    const { bytes, slots } = redacted(input);
    assert.throws(() => inspectActivityBody(bytes, slots), /AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID/);
  }
});

test('public employer values or a non-object claims proof cannot pass inspection', () => {
  const input = fixture();
  const { bytes, slots } = redacted(input);
  const raw = Buffer.from(JSON.stringify(input));
  const exposed = bytes.slice(); raw.copy(exposed, slots[0].start, slots[0].start, slots[0].end);
  assert.throws(() => inspectActivityBody(exposed, slots.slice(1)), /AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID/);
  assert.throws(() => inspectActivityBody(bytes, slots.map((slot, i) => i === 0 ? { ...slot, kind: 1 } : slot)),
    /AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID/);
});

test('opaque row substitution, wrong field ownership and noncanonical UUID length fail', () => {
  const input = fixture();
  input.value[0].eventDataId = 'short';
  let hidden = redacted(input);
  assert.throws(() => inspectActivityBody(hidden.bytes, hidden.slots), /AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID/);
  const row = JSON.stringify(fixture().value[0]);
  const bytes = Buffer.from(`{"value":[${row}]}`);
  const slot = { start: 10, end: 10 + row.length, kind: 6, hash: 'ab'.repeat(32) };
  bytes.fill(0, slot.start, slot.end);
  assert.throws(() => inspectActivityBody(bytes, [slot]), /AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID/);
  const moved = fixture(); moved.value[0].eventName = { wrong: 'EndRequest' };
  hidden = redacted(moved);
  assert.throws(() => inspectActivityBody(hidden.bytes, hidden.slots), /AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID/);
});

test('malformed public framing and exposed field names containing employer data fail', () => {
  const { bytes, slots } = redacted(fixture());
  const extra = Buffer.concat([bytes, Buffer.from('{}')]);
  assert.throws(() => inspectActivityBody(extra, slots), /AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID/);
  const changed = bytes.slice(); changed[0] = 91;
  assert.throws(() => inspectActivityBody(changed, slots), /AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID/);
  const renamed = fixture(); renamed.value[0]['employer-name'] = renamed.value[0].subscriptionId;
  delete renamed.value[0].subscriptionId;
  const hidden = redacted(renamed);
  assert.throws(() => inspectActivityBody(hidden.bytes, hidden.slots), /AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID/);
});
