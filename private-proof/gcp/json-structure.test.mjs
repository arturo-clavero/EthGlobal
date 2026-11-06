import assert from 'node:assert/strict';
import test from 'node:test';
import { JsonStructureError, JSON_STRUCTURE_LIMITS, parseJsonStructure } from './json-structure.mjs';

const encoder = new TextEncoder();
const encode = value => encoder.encode(value);
const hash = 'ab'.repeat(32);
const parse = text => parseJsonStructure(encode(text));
const fails = (bytes, slots = [], code) => assert.throws(
  () => parseJsonStructure(typeof bytes === 'string' ? encode(bytes) : bytes, slots),
  error => error instanceof JsonStructureError && (!code || error.code === code),
);
function hidden(text, tokens) {
  const bytes = encode(text);
  let cursor = 0;
  const slots = tokens.map(([token, kind]) => {
    const needle = encode(token);
    let start = -1;
    for (let at = cursor; at + needle.length <= bytes.length; at++) {
      if (needle.every((byte, i) => bytes[at + i] === byte)) { start = at; break; }
    }
    assert.notEqual(start, -1, 'fixture token absent');
    const end = start + needle.length;
    bytes.fill(0, start, end);
    cursor = end;
    return { start, end, kind, hash };
  });
  return { bytes, slots };
}

test('public JSON uses byte offsets, standard scalar decoding and entry lists', () => {
  const text = ' {"a":[1,-2.5e2,true,false,null,"Å😊\\n"],"__proto__":0} ';
  const { root, requiresAtomicProofs } = parse(text);
  assert.equal(root.type, 'object');
  assert.equal(root.start, 1);
  assert.equal(root.end, encode(text).length - 1);
  assert.equal(root.hasPrivateKeys, false);
  assert.equal(requiresAtomicProofs, false);
  const values = root.entries[0].value.items;
  assert.deepEqual(values.map(node => node.value), [1, -250, true, false, null, 'Å😊\n']);
  assert.equal(values[1].raw, '-2.5e2');
  assert.equal(new TextDecoder().decode(encode(text).slice(values[5].start, values[5].end)), '"Å😊\\n"');
  assert.equal(root.entries[1].key.value, '__proto__');
  assert.equal(Object.getPrototypeOf(root), Object.prototype);
  assert.equal(parse('9007199254740993').root.raw, '9007199254740993');
});

test('each explicit private kind is an unverified atom with no exposed value', () => {
  const { bytes, slots } = hidden('["secret",12,true,false,null]',
    [['"secret"', 1], ['12', 2], ['true', 3], ['false', 4], ['null', 5]]);
  const result = parseJsonStructure(bytes, slots);
  assert.equal(result.requiresAtomicProofs, true);
  assert.deepEqual(result.root.items.map(node => node.kind), [1, 2, 3, 4, 5]);
  assert.deepEqual(result.root.items.map(node => node.privateSlot), [0, 1, 2, 3, 4]);
  for (const node of result.root.items) assert.equal(Object.hasOwn(node, 'value'), false);
  assert.deepEqual(result.slots, slots);
  slots[0].start = 99;
  assert.equal(result.slots[0].start, 1);
  assert.equal(JSON.stringify(result).includes('secret'), false);
});

test('private keys remain unknown and public duplicate keys are always rejected', () => {
  const { bytes, slots } = hidden('{"hidden":0,"public":1}', [['"hidden"', 1]]);
  const { root } = parseJsonStructure(bytes, slots);
  assert.equal(root.hasPrivateKeys, true);
  assert.equal(root.entries[0].key.privateSlot, 0);
  assert.equal(Object.hasOwn(root.entries[0].key, 'value'), false);
  assert.equal(root.entries[1].key.value, 'public');
  for (const text of ['{"a":0,"a":1}', '{"a":0,"\\u0061":1}', '{"__proto__":0,"__proto__":1}']) {
    fails(text, [], 'DUPLICATE_KEY');
  }
  const badKey = hidden('{true:0}', [['true', 3]]);
  fails(badKey.bytes, badKey.slots, 'EXPECTED_STRING_KEY');
});

test('opaque objects require trusted opt-in and remain unverified without internal fields', () => {
  const { bytes, slots } = hidden('{"claims":{"employer-key":"private"},"other":1}',
    [['{"employer-key":"private"}', 6]]);
  fails(bytes, slots, 'SLOT_KIND');
  const result = parseJsonStructure(bytes, slots, true);
  assert.equal(result.requiresAtomicProofs, true);
  assert.equal(result.requiresObjectProofs, true);
  assert.deepEqual(result.root.entries[0].value,
    { type: 'object', kind: 6, start: slots[0].start, end: slots[0].end, privateSlot: 0 });
  assert.equal(JSON.stringify(result).includes('employer-key'), false);
  assert.equal(result.root.entries[1].value.value, 1);
  assert.throws(() => parseJsonStructure(bytes, slots, 'true'), /OBJECT_POLICY/);
});

test('opaque object opt-in does not permit object keys, uncovered bytes or interior spans', () => {
  for (const [text, token] of [['{{}:0}', '{}'], ['{"claims":{}}', '{'], ['{"claims":{}}', '{}']]) {
    const { bytes, slots } = hidden(text, [[token, 6]]);
    if (token === '{}' && text === '{"claims":{}}') bytes[slots[0].start] = 123;
    assert.throws(() => parseJsonStructure(bytes, slots, true), JsonStructureError);
  }
  const partial = hidden('{"claims":{"x":1}}', [['"x":1', 6]]);
  assert.throws(() => parseJsonStructure(partial.bytes, partial.slots, true), /EXPECTED_STRING_KEY/);
});

test('slots cannot replace a string interior, escape fragment or partial public token', () => {
  for (const [text, token, kind] of [
    ['["secret"]', 'secret', 1],
    ['["a\\"b"]', '\\"', 1],
    ['[1234]', '23', 2],
    ['[true]', 'ru', 2],
    ['["abc"]', '"ab', 1],
  ]) {
    const { bytes, slots } = hidden(text, [[token, kind]]);
    fails(bytes, slots);
  }
});

test('commas and container syntax cannot be smuggled across a public boundary', () => {
  for (const [text, token, kind] of [
    ['[1,2]', ',', 2],
    ['["a",2]', '"a",', 1],
    ['["a",{"x":1}]', '"a",{', 1],
    ['{"a":1}', ':', 2],
    ['[1,2]', '[1', 2],
  ]) {
    const { bytes, slots } = hidden(text, [[token, kind]]);
    fails(bytes, slots);
  }
  const container = hidden('[[]]', [['[]', 6]]);
  fails(container.bytes, container.slots, 'SLOT_KIND');
});

test('opaque bytes are not grammar proofs: mislabelled containers remain only provisional atoms', () => {
  // The parser cannot know these zeroed bytes were an array. Accepting the
  // resulting string as verified would be a caller bug; atomic-kind ZK must fail.
  const { bytes, slots } = hidden('[[]]', [['[]', 1]]);
  const result = parseJsonStructure(bytes, slots);
  assert.equal(result.requiresAtomicProofs, true);
  assert.equal(result.root.items[0].type, 'string');
  assert.equal(Object.hasOwn(result.root.items[0], 'items'), false);
  assert.equal(Object.hasOwn(result.root.items[0], 'value'), false);
});

test('invalid, missing and impossible private kinds are rejected', () => {
  const { bytes, slots } = hidden('[true]', [['true', 3]]);
  for (const kind of [undefined, null, 0, 6, '3', 1.5, NaN, Infinity]) {
    fails(bytes, [{ ...slots[0], kind }], 'SLOT_KIND');
  }
  fails(bytes, [{ ...slots[0], kind: 4 }], 'SLOT_LENGTH');
  const tooShort = hidden('[0]', [['0', 1]]);
  fails(tooShort.bytes, tooShort.slots, 'SLOT_LENGTH');
});

test('private spans are sorted, disjoint, bounded, zeroed and bound to canonical hash metadata', () => {
  const { bytes, slots } = hidden('[11,22]', [['11', 2], ['22', 2]]);
  fails(bytes, slots.toReversed(), 'SLOT_ORDER');
  fails(bytes, [slots[0], { ...slots[1], start: slots[0].start }], 'SLOT_ORDER');
  for (const replacement of [{ start: -1 }, { start: 1.5 }, { end: bytes.length + 1 }, { end: slots[0].start }]) {
    fails(bytes, [{ ...slots[0], ...replacement }], 'SLOT_RANGE');
  }
  for (const badHash of ['', 'AB'.repeat(32), 'ab'.repeat(31), null]) {
    fails(bytes, [{ ...slots[0], hash: badHash }], 'SLOT_HASH');
  }
  const revealedSecret = bytes.slice();
  revealedSecret[slots[0].start] = 49;
  fails(revealedSecret, slots, 'PRIVATE_NOT_ZERO');
  fails(bytes, [null], 'SLOT_METADATA');
  fails(bytes, {}, 'SLOTS_TYPE');
  const adjacent = hidden('[1122]', [['11', 2], ['22', 2]]);
  fails(adjacent.bytes, adjacent.slots);
});

test('truncated JSON, malformed scalars, invalid UTF8 and trailing bytes fail without echoing input', () => {
  for (const text of ['', ' ', '[', '{', '[1,]', '{"a":}', '{"a" 1}', '"secret',
    '"\\q"', '"\n"', '[01]', '[1e]', '[+1]', '[NaN]', '[true false]', '{}x', '{}{}', '\ufeff{}']) {
    fails(text);
  }
  fails(new Uint8Array([34, 0xc3, 0x28, 34]), [], 'INVALID_UTF8');
  fails('null', [{ start: 0, end: 4, kind: 5, hash }], 'PRIVATE_NOT_ZERO');
  assert.throws(() => parse('"secret\\q"'), error => !error.message.includes('secret'));
});

test('resource limits apply to bytes, container depth, total nodes and private slots', () => {
  fails([], [], 'INPUT_TYPE');
  parse('"' + 'a'.repeat(JSON_STRUCTURE_LIMITS.bytes - 2) + '"');
  fails('"' + 'a'.repeat(JSON_STRUCTURE_LIMITS.bytes - 1) + '"', [], 'INPUT_LIMIT');
  parse('['.repeat(32) + '0' + ']'.repeat(32));
  fails('['.repeat(33) + '0' + ']'.repeat(33), [], 'DEPTH_LIMIT');
  parse('[' + Array(511).fill('0').join(',') + ']');
  fails('[' + Array(512).fill('0').join(',') + ']', [], 'NODE_LIMIT');
  const text = '[' + Array(256).fill('0').join(',') + ']';
  const { bytes, slots } = hidden(text, Array.from({ length: 256 }, () => ['0', 2]));
  assert.equal(parseJsonStructure(bytes, slots).slots.length, 256);
  fails(bytes, [...slots, slots[0]], 'SLOT_LIMIT');
});
