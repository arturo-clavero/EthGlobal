import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { parseCloudTrailStructure } from './nested-json.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const child = (node, name) => node.entries.find(entry => entry.key.value === name)?.value;
const encode = value => JSON.stringify(value).slice(1, -1);
const raw = event => Buffer.from(JSON.stringify({ Events: [{ EventId: 'outer-event', CloudTrailEvent: event }] }));
const reject = (bytes, slots = []) => assert.throws(() => parseCloudTrailStructure(bytes, slots), { message: 'AWS_PRIVATE_STRUCTURE_INVALID' });

// Synthetic digests stand in for independently authenticated receipts/proof outputs.
function hidden(event, atoms, hideOuterId = false) {
  const bytes = raw(event), slots = [];
  const eventStart = bytes.indexOf(Buffer.from('"CloudTrailEvent":"')) + Buffer.byteLength('"CloudTrailEvent":"');
  for (const [atom, kind = 1] of atoms) {
    const wire = Buffer.from(encode(atom));
    const start = bytes.indexOf(wire, eventStart);
    assert.ok(start >= eventStart);
    slots.push({ layer: 'event', start, end: start + wire.length, kind, hash: hash(wire),
      decodedHash: hash(atom), decodedLength: Buffer.byteLength(atom) });
  }
  if (hideOuterId) {
    const atom = '"outer-event"', start = bytes.indexOf(atom);
    slots.push({ layer: 'outer', start, end: start + atom.length, kind: 1, hash: hash(atom) });
  }
  slots.sort((a, b) => a.start - b.start);
  for (const slot of slots) bytes.fill(0, slot.start, slot.end);
  return { bytes, slots };
}

test('reconstructs both layers with byte offsets and provisional private value bindings', () => {
  const sentinel = 'AWS_PRIVATE_名_"_\\_sentinel';
  const atom = JSON.stringify(sentinel);
  const fixture = hidden(`{"eventName":"UpdateAssumeRolePolicy","actor":${atom},"ok":true}`, [[atom]], true);
  const result = parseCloudTrailStructure(fixture.bytes, fixture.slots);
  assert.equal(child(result.event, 'eventName').value, 'UpdateAssumeRolePolicy');
  assert.equal(child(result.event, 'actor').privateSlot, 0);
  assert.equal(child(result.event, 'actor').value, undefined);
  assert.equal(result.eventAtoms[0].decoded.end - result.eventAtoms[0].decoded.start, Buffer.byteLength(atom));
  assert.equal(result.eventAtoms[0].encoded.start, fixture.slots[1].start);
  assert.equal(result.eventAtoms[0].encoded.hash, fixture.slots[1].hash);
  assert.equal(result.eventAtoms[0].decoded.hash, fixture.slots[1].decodedHash);
  assert.equal(result.outerAtoms.length, 1);
  assert.equal(result.requiresAtomicProofs, true);
  assert.ok(!JSON.stringify(result).includes(sentinel));
  assert.equal(child(child(result.outer, 'Events').items[0], 'CloudTrailEvent').type, 'embedded-json');
});

test('retains hidden error fields; parsing makes no success or attribution claim', () => {
  const fixture = hidden('{"errorCode":"AccessDenied","userIdentity":{"principalId":"wrong-user"}}',
    [['"AccessDenied"'], ['"wrong-user"']]);
  const result = parseCloudTrailStructure(fixture.bytes, fixture.slots);
  assert.equal(child(result.event, 'errorCode').privateSlot, 0);
  assert.equal(child(child(result.event, 'userIdentity'), 'principalId').privateSlot, 1);
  assert.equal(result.accepted, undefined);
});

test('supports adjacent private scalars separated by authenticated punctuation', () => {
  const fixture = hidden('{"v":[true,false,null,-1.25e+3,""]}', [['true', 3], ['false', 4], ['null', 5], ['-1.25e+3', 2], ['""', 1]]);
  assert.deepEqual(child(parseCloudTrailStructure(fixture.bytes, fixture.slots).event, 'v').items.map(node => node.kind), [3, 4, 5, 2, 1]);
});

test('decodes Unicode-escaped inner keys before duplicate checking', () => {
  reject(raw('{"errorCode":null,"error\\u0043ode":"AccessDenied"}'));
  reject(raw('{"userIdentity":{"principalId":"a","principal\\u0049d":"b"}}'));
});

test('rejects duplicate decoded outer keys', () => {
  reject(Buffer.from('{"Events":[],"Ev\\u0065nts":[]}'));
  reject(Buffer.from('{"Events":[{"CloudTrailEvent":"{}","CloudTrail\\u0045vent":"{}"}]}'));
});

test('rejects hidden inner and outer keys even when their atom grammar could be proven', () => {
  const fixture = hidden('{"secretKey":"value"}', [['"secretKey"']]);
  reject(fixture.bytes, fixture.slots);
  const bytes = raw('{}'), start = bytes.indexOf('"EventId"');
  const slot = { layer: 'outer', start, end: start + 9, kind: 1, hash: hash('key') };
  bytes.fill(0, slot.start, slot.end);
  reject(bytes, [slot]);
});

test('rejects a hidden whole embedded document or inner container', () => {
  const bytes = raw('{}'), start = bytes.indexOf('"{}"');
  const slot = { layer: 'outer', start, end: start + 4, kind: 1, hash: hash('{}') };
  bytes.fill(0, slot.start, slot.end);
  reject(bytes, [slot]);
  const fixture = hidden('{"x":{}}', [['{}', 6]]);
  reject(fixture.bytes, fixture.slots);
});

test('rejects event holes placed outside the direct CloudTrailEvent value', () => {
  const bytes = raw('{"x":1}'), start = bytes.indexOf('outer-event');
  const slot = { layer: 'event', start, end: start + 5, kind: 2, hash: hash('outer'), decodedHash: hash('1'), decodedLength: 1 };
  bytes.fill(0, start, slot.end);
  reject(bytes, [slot]);
  reject(Buffer.from(JSON.stringify({ Events: [{ nested: { CloudTrailEvent: '{}' } }] })));
});

test('rejects omitted pagination, multiple events, trailing documents and non-object inner JSON', () => {
  for (const value of [{ Events: [], NextToken: 'private-page' }, { Events: [] },
    { Events: [{ CloudTrailEvent: '{}' }, { CloudTrailEvent: '{}' }] }]) reject(Buffer.from(JSON.stringify(value)));
  reject(Buffer.concat([raw('{}'), Buffer.from('{}')]));
  reject(raw('{}{}'));
  reject(raw('[]'));
  reject(raw('{'));
});

test('rejects noncanonical outer escapes and lone-surrogate conversion', () => {
  reject(Buffer.from(raw('{"a":"x"}').toString().replace('\\"a', '\\u0022a')));
  reject(Buffer.from(raw('{"a":"/"}').toString().replace('/', '\\/')));
  reject(Buffer.from('{"Events":[{"CloudTrailEvent":"{\\"a\\":\\"\\ud800\\"}"}]}'));
});

test('rejects escape-boundary splitting even when the hidden fragment looks like a scalar', () => {
  const bytes = raw('{"a":"x"}');
  const start = bytes.indexOf(Buffer.from('\\"x')) + 1;
  const slot = { layer: 'event', start, end: start + 1, kind: 2, hash: hash('x'), decodedHash: hash('1'), decodedLength: 1 };
  bytes.fill(0, start, slot.end);
  reject(bytes, [slot]);
});

test('rejects malformed or unused slot metadata and visible private bytes', () => {
  const { bytes, slots } = hidden('{"a":"private"}', [['"private"']]);
  for (const patch of [{ start: -1 }, { end: bytes.length + 1 }, { decodedLength: 0 }, { decodedLength: 513 },
    { kind: 0 }, { kind: 6 }, { hash: 'x' }, { decodedHash: 'A'.repeat(64) }, { layer: 'other' }, { extra: 'private' }]) {
    reject(bytes, [{ ...slots[0], ...patch }]);
  }
  reject(bytes, [...slots, ...slots]);
  reject(bytes, []);
  const visible = Buffer.from(bytes); visible[slots[0].start] = 65;
  reject(visible, slots);
  reject(bytes, Array(257).fill(slots[0]));
});

test('rejects oversize, malformed UTF-8 and invalid input without echoing source data', () => {
  reject(new Uint8Array(16385));
  reject('private-source');
  reject(Buffer.from([255]));
  const bytes = raw('{"a":"private"}'); bytes[bytes.indexOf('private')] = 255;
  reject(bytes);
});

test('handles public UTF-8 before hidden values without character-based offset drift', () => {
  const fixture = hidden('{"名":"public","secret":"hidden"}', [['"hidden"']]);
  const result = parseCloudTrailStructure(fixture.bytes, fixture.slots);
  assert.equal(child(result.event, '名').value, 'public');
  assert.equal(result.eventAtoms[0].decoded.start, Buffer.byteLength('{"名":"public","secret":'));
});
