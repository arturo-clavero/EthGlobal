import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { parseJsonStructure } from '../gcp/json-structure.mjs';
import { inspectTenantBody } from './tenant-structure.mjs';

const fixture = () => ({ subscriptionId: 'aaaaaaaa-1111-2222-3333-444444444444',
  tenantId: 'bbbbbbbb-1111-2222-3333-444444444444', state: 'Enabled' });
const invalid = /AZURE_PRIVATE_TENANT_STRUCTURE_INVALID/;
function redacted(input = fixture()) {
  const bytes = Buffer.from(typeof input === 'string' ? input : JSON.stringify(input));
  const slots = parseJsonStructure(bytes).root.entries.map(({ value }, index) => ({
    start: value.start, end: value.end, kind: value.kind ?? 6,
    hash: createHash('sha256').update(bytes.subarray(value.start, value.end)).update(Buffer.alloc(16, index)).digest('hex'),
  }));
  for (const { start, end } of slots) bytes.fill(0, start, end);
  return { bytes, slots };
}

test('returns private slot references and required predicates without disclosing values', () => {
  const { bytes, slots } = redacted(), result = inspectTenantBody(bytes, slots);
  assert.deepEqual(result.subscription, { ...slots[0], length: 38, requiredPredicate: 'quoted-uuid' });
  assert.deepEqual(result.tenant, { ...slots[1], length: 38, requiredPredicate: 'quoted-uuid' });
  assert.deepEqual(result.state, { ...slots[2], length: 9, requiredPredicate: 'subscription-enabled' });
  for (const value of Object.values(fixture())) {
    assert.ok(!JSON.stringify(result).includes(value)); assert.ok(!bytes.toString().includes(value));
  }
});

test('rejects exposed values, wrong kinds, invalid lengths and extra native ranges', () => {
  const { bytes, slots } = redacted(), original = Buffer.from(JSON.stringify(fixture()));
  for (let i = 0; i < slots.length; i++) {
    const exposed = Buffer.from(bytes), slot = slots[i];
    original.copy(exposed, slot.start, slot.start, slot.end);
    assert.throws(() => inspectTenantBody(exposed, slots.filter((_, j) => j !== i)), invalid);
  }
  const changed = structuredClone(slots); changed[0].kind = 2;
  assert.throws(() => inspectTenantBody(bytes, changed), invalid);
  for (const input of [{ ...fixture(), subscriptionId: 'short' }, { ...fixture(), state: 'Disabled' }]) {
    const value = redacted(input); assert.throws(() => inspectTenantBody(value.bytes, value.slots), invalid);
  }
  assert.throws(() => inspectTenantBody(bytes, [...slots, slots[2]]), invalid);
});

test('rejects missing fields, alternate tenant source, unknown ARM extras and private keys', () => {
  for (const input of [
    { subscriptionId: fixture().subscriptionId, state: 'Enabled' },
    { subscriptionId: fixture().subscriptionId, managedByTenants: [{ tenantId: fixture().tenantId }], state: 'Enabled' },
    { ...fixture(), displayName: 'private-employer' },
    { ...fixture(), id: '/subscriptions/private' },
    { ...fixture(), subscriptionPolicies: {} },
  ]) {
    const value = redacted(input); assert.throws(() => inspectTenantBody(value.bytes, value.slots), invalid);
  }
  const { bytes, slots } = redacted();
  bytes.fill(0, 1, 17);
  assert.throws(() => inspectTenantBody(bytes, [{ start: 1, end: 17, kind: 1, hash: 'ab'.repeat(32) }, ...slots]), invalid);
});

test('semantic proof remains mandatory for a same-length false state', () => {
  const { bytes, slots } = redacted({ ...fixture(), state: 'Revoked' });
  assert.equal(inspectTenantBody(bytes, slots).state.requiredPredicate, 'subscription-enabled');
});

test('rejects malformed syntax, duplicate fields and malformed slot metadata', () => {
  const { bytes, slots } = redacted();
  const malformed = Buffer.from(bytes); malformed[malformed.length - 1] = 93;
  assert.throws(() => inspectTenantBody(malformed, slots), invalid);
  assert.throws(() => inspectTenantBody(Buffer.from('{"state":0,"state":0,"tenantId":0}'), []), invalid);
  for (const mutate of [s => s.reverse(), s => { s[0].hash = 'bad'; }, s => { s[0].start--; }]) {
    const changed = structuredClone(slots); mutate(changed);
    assert.throws(() => inspectTenantBody(bytes, changed), invalid);
  }
});
