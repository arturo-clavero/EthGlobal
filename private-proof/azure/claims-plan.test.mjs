import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { prepareClaimsChunks } from './claims-plan.mjs';

const actorKey = 'http://schemas.microsoft.com/identity/claims/objectidentifier';
const tenantKey = 'http://schemas.microsoft.com/identity/claims/tenantid';
const actor = 'aaaaaaaa-1111-2222-3333-444444444444';
const tenant = 'bbbbbbbb-1111-2222-3333-444444444444';
const identity = { [actorKey]: actor.toUpperCase(), [tenantKey]: tenant };
const encode = text => new TextEncoder().encode(text);
const fixture = extra => encode(JSON.stringify({ 'private-rule-name': 'private-employer-value', ...extra, ...identity }));
function openings(bytes, start = 0) {
  return Array.from({ length: Math.ceil(bytes.length / 512) }, (_, i) => {
    const offset = i * 512, part = bytes.subarray(offset, offset + 512), blinder = new Uint8Array(16).fill(i + 1);
    return { start: start + offset, end: start + offset + part.length, blinder,
      hash: new Uint8Array(createHash('sha256').update(part).update(blinder).digest()) };
  });
}
const rejected = async (bytes, native = openings(bytes), options) => {
  await assert.rejects(prepareClaimsChunks(bytes, native, options), { message: 'AZURE_PRIVATE_CLAIMS_PLAN_INVALID' });
};

test('native chunks and private carries bind every byte and expose only commitments', async () => {
  const bytes = fixture({ padding: 'x'.repeat(900) }), original = bytes.slice();
  const native = openings(bytes, 120), plan = await prepareClaimsChunks(bytes, native, { start: 120 });
  assert.equal(plan.chunks.length, 3);
  for (const [i, { inputs, publicInputs }] of plan.chunks.entries()) {
    assert.equal(publicInputs.length, 163);
    assert.deepEqual(inputs.hashes[0], [...native[i].hash]);
    assert.equal(inputs.offset, i * 512); assert.equal(inputs.total, bytes.length);
    assert.equal(inputs.length, Math.min(512, bytes.length - i * 512));
    assert.equal(new DataView(Uint8Array.from(inputs.state_preimages[0]).buffer).getUint32(79), i * 512);
    if (i) assert.deepEqual(inputs.hashes[1], plan.chunks[i - 1].inputs.hashes[2]);
    assert.deepEqual(inputs.hashes.slice(3), plan.identities.map(value => value.hash));
  }
  const first = plan.chunks[0].inputs.state_preimages[0].slice(0, 83);
  const expected = new Array(83).fill(0); expected[77] = 128; expected[78] = 191;
  assert.deepEqual(first, expected);
  const last = plan.chunks.at(-1).inputs.state_preimages[1];
  assert.equal(last[0], 8); assert.deepEqual(last.slice(68, 70), [1, 1]);
  assert.equal(new TextDecoder().decode(Uint8Array.from(plan.identities[0].preimage.slice(0, 38))), JSON.stringify(actor));
  const publicText = JSON.stringify(plan.chunks.map(value => value.publicInputs));
  for (const value of [actor, tenant, 'private-rule-name', 'private-employer-value', actorKey]) assert.ok(!publicText.includes(value));
  plan.clear();
  for (const { inputs } of plan.chunks) {
    for (const value of [inputs.chunk_preimage, ...inputs.state_preimages, ...inputs.identity_preimages]) assert.ok(value.every(byte => byte === 0));
  }
  assert.deepEqual(bytes, original); assert.ok(native[0].blinder.every(byte => byte === 1));
});

test('UTF-8 and escape sequences carry across native chunk boundaries privately', async () => {
  for (const [suffix, expectedAt, expectedValue] of [['😀', 76, 3], ['\\u0041', 74, 1]]) {
    const prefix = '{"padding":"';
    const body = prefix + 'x'.repeat(511 - prefix.length) + suffix + '",' + JSON.stringify(identity).slice(1);
    const bytes = encode(body), plan = await prepareClaimsChunks(bytes, openings(bytes));
    assert.equal(plan.chunks[0].inputs.state_preimages[1][expectedAt], expectedValue);
    assert.deepEqual(plan.chunks[0].inputs.state_preimages[1], plan.chunks[1].inputs.state_preimages[0]);
    plan.clear();
  }
});

test('changed hashes, ranges, blinders and missing or reordered chunks reject', async () => {
  const bytes = fixture({ padding: 'x'.repeat(700) });
  for (const mutate of [x => x[0].hash[0] ^= 1, x => x[0].blinder[0] ^= 1,
    x => x[0].start++, x => x[0].end--, x => x.reverse(), x => x.pop(), x => x.push(x[0])]) {
    const native = openings(bytes); mutate(native); await rejected(bytes, native);
  }
  await rejected(bytes, openings(bytes), { start: 1 });
});

test('duplicate identities, escaped aliases, malformed UTF-8 and unsupported shapes reject', async () => {
  const normal = JSON.stringify(identity);
  const invalid = [
    normal.slice(0, -1) + `,"${actorKey}":"${actor}"}`,
    normal.replace('http://', 'http:\\u002f/'),
    normal.replace('AAAAAAAA', '\\u0041AAAAAAA'),
    JSON.stringify({ ...identity, setting: true }), JSON.stringify({ ...identity, nested: {} }),
    JSON.stringify({ [actorKey]: actor }), normal + '{}', '{}', normal.slice(0, -1) + ',}',
    JSON.stringify({ ...identity, [tenantKey]: 'not-a-uuid' }),
  ];
  for (const value of invalid) await rejected(encode(value));
  const malformed = fixture({ padding: 'x' }); malformed[malformed.indexOf(120)] = 255;
  await rejected(malformed);
  await rejected(new Uint8Array()); await rejected(new Uint8Array(2305));
});

test('fresh private identity and state blinders prevent stable public linkage', async () => {
  const bytes = fixture(), native = openings(bytes);
  const first = await prepareClaimsChunks(bytes, native), second = await prepareClaimsChunks(bytes, native);
  assert.deepEqual(first.chunks[0].inputs.hashes[0], second.chunks[0].inputs.hashes[0]);
  for (let i = 1; i < 5; i++) assert.notDeepEqual(first.chunks[0].inputs.hashes[i], second.chunks[0].inputs.hashes[i]);
  first.clear(); second.clear();
});
