import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectGcpSession, parseMultipartStructure } from './gcp-structure.mjs';
import { BATCHES } from './policy.mjs';
import { fixtureNonce, fixturePolicy, fragments, literal, secret, identityRow, identityFragments,
  groupPart, groupFragments, redactFixture, gcpFixture } from './gcp-fixtures.mjs';

const inspect = fixture => inspectGcpSession(fixture.directions, fixture.meta, fixture.policy, fixture.atomicClaims);
const reject = fixture => assert.throws(() => inspect(fixture));
function changePublic(part, before, after) {
  const at = part.text.indexOf(before); assert.notEqual(at, -1);
  assert.ok(part.hidden.every(range => range.end <= at || range.start >= at + before.length));
  const delta = after.length - before.length;
  return { text: part.text.slice(0, at) + after + part.text.slice(at + before.length),
    hidden: part.hidden.map(range => range.start > at ? { ...range, start: range.start + delta, end: range.end + delta } : range) };
}
const fromRaw = (raw, step = 'identity') => redactFixture(raw.sent, raw.recv, step);
const groupBody = (body, status = 'observed') => {
  const ids = BATCHES[0].groupIds;
  return gcpFixture('groups:0', { parts: ids.map((id, index) => groupPart(id, index ? 'empty' : status, index ? undefined : body)) });
};

test('identity derives all rows and native slot references without exposing private values', () => {
  const metadata = fragments('{', secret('"employer-key"', 1), ':', secret('12345', 2), ', ',
    secret('"another-key"', 1), ':[null,true,false,', secret('"private name"', 1), ']}');
  const input = gcpFixture('identity', { rows: [identityRow(0), identityRow(1, '0', metadata)] });
  const result = inspect(input);
  assert.deepEqual(result.identity.rows.map(row => row.rowValid), [true, false]);
  assert.equal(result.identity.rows[0].emailSlot.length, '"member0@example.test"'.length);
  assert.equal(result.identity.authuserSlot.length, 1);
  assert.equal(result.obligations.length, input.directions.sent.privateRanges.length + input.directions.recv.privateRanges.length);
  assert.equal(result.obligations.filter(slot => slot.predicate === 'identity-scope-v1').length, 1);
  assert.equal(result.obligations.filter(slot => slot.predicate === 'header-v1').length, 1);
  const output = JSON.stringify(result);
  for (const value of ['member0', '123450', 'employer-key', 'private name', 'synthetic-cookie']) assert.ok(!output.includes(value));
  const slots = result.obligations.filter(slot => slot.direction === 'RECV');
  assert.ok(slots.every((slot, index) => !index || slots[index - 1].end <= slot.start));
});

test('all fixed batches have exact query roles and deterministic category ordering', () => {
  for (const batch of BATCHES) {
    const input = gcpFixture(batch.step), result = inspect(input);
    assert.deepEqual(result.groups.map(group => group.id), batch.groupIds);
    assert.equal(result.query.project.length, batch.groupIds.length * 2);
    assert.equal(result.query.email.length, batch.groupIds.length);
    assert.equal(result.query.apiKeySlot.length, 39);
    assert.equal(result.query.authuserSlot.length, 1);
    assert.deepEqual(result.groups.map(group => group.status), batch.groupIds.map((_, index) => ['observed', 'empty', 'denied'][index % 3]));
    for (const group of result.groups.filter(group => group.timestampSlot)) {
      const native = input.directions.recv.privateRanges.find(slot => slot.hash === group.timestampSlot.hash);
      assert.equal(group.timestampSlot.start, native.start);
      assert.equal(group.timestampSlot.end, native.end);
    }
  }
  const reversed = gcpFixture('groups:0', { parts: [...BATCHES[0].groupIds].reverse().map(id => groupPart(id, 'empty')) });
  assert.deepEqual(inspect(reversed).groups.map(group => group.id), BATCHES[0].groupIds);
});

test('chunked outer response preserves each original native timestamp coordinate', () => {
  const fixture = gcpFixture('groups:0', { chunked: true });
  const result = inspect(fixture);
  for (const group of result.groups.filter(group => group.timestampSlot)) {
    const source = fixture.directions.recv.privateRanges.find(slot => slot.hash === group.timestampSlot.hash);
    assert.equal(source.start, group.timestampSlot.start);
    assert.equal(source.end, group.timestampSlot.end);
  }
  const empty = groupBody(literal('{}'));
  assert.equal(inspect(empty).groups[0].status, 'empty');
});

test('identity and batch Origins match the producer and cannot substitute each other', () => {
  for (const [step, origin, other] of [
    ['identity', 'https://www.google.com', 'https://console.cloud.google.com'],
    ['groups:0', 'https://console.cloud.google.com', 'https://www.google.com'],
  ]) {
    const input = value => gcpFixture(step, { requestHeaders: `Origin: ${value}\r\n` });
    assert.equal(inspect(input(origin)).step, step);
    for (const wrong of [other, 'https://attacker.invalid']) reject(input(wrong));
  }
});

test('repeated opaque response headers require independent complete private coverage', () => {
  const repeated = second => fragments('X-Transport: ', secret('first synthetic value'),
    '\r\nx-transport: ', second, '\r\n');
  for (const step of ['identity', 'groups:0']) {
    const input = gcpFixture(step, { responseHeaders: repeated(secret('second synthetic value')) });
    const result = inspect(input), slots = input.directions.recv.privateRanges.slice(0, 2);
    assert.equal(slots.length, 2);
    for (const slot of slots) assert.deepEqual(result.obligations.find(item => item.hash === slot.hash),
      { ...slot, direction: 'RECV', length: slot.end - slot.start, predicate: 'header-v1' });
    for (const second of [literal('uncovered value'), fragments(secret('hidden'), ' exposed')]) {
      reject(gcpFixture(step, { responseHeaders: repeated(second) }));
    }
    const missing = structuredClone(input);
    missing.directions.recv.privateRanges.splice(1, 1); reject(missing);
    const corrupted = structuredClone(input);
    corrupted.directions.recv.bytes[slots[1].start] = 120; reject(corrupted);
  }
});

test('request, framing and semantic headers remain singleton even with private values', () => {
  const repeated = (name, value) => fragments(`${name}: `, value, `\r\n${name.toLowerCase()}: `, value, '\r\n');
  reject(gcpFixture('identity', { requestHeaders: repeated('X-Transport', secret('private')) }));
  reject(gcpFixture('groups:0', { requestHeaders: fragments('X-Goog-AuthUser: ', secret('0'), '\r\n') }));
  for (const step of ['identity', 'groups:0']) {
    for (const [name, value] of [['Content-Type', 'application/json'], ['Connection', 'close'],
      ['Content-Length', '1'], ['Content-Encoding', 'identity'], ['Transfer-Encoding', 'chunked']]) {
      reject(gcpFixture(step, { responseHeaders: repeated(name, literal(value)) }));
    }
  }
  reject(gcpFixture('identity', { responseHeaders: repeated('Connection', secret('close')) }));
});

test('nested repeated metadata keeps each original native wire coordinate', () => {
  const input = name => {
    const parts = BATCHES[0].groupIds.map(id => groupPart(id)), part = parts[0];
    const at = part.text.indexOf('Content-Length:');
    assert.ok(part.hidden.every(range => range.start >= at));
    const headers = fragments(`${name}: `, secret('first'), `\r\n${name.toLowerCase()}: `, secret('second'), '\r\n');
    parts[0] = { text: part.text.slice(0, at) + headers.text + part.text.slice(at), hidden: [
      ...headers.hidden.map(range => ({ ...range, start: range.start + at, end: range.end + at })),
      ...part.hidden.map(range => ({ ...range, start: range.start + headers.text.length, end: range.end + headers.text.length })),
    ] };
    return gcpFixture('groups:0', { parts });
  };
  const fixture = input('X-Transport'), result = inspect(fixture);
  for (const slot of fixture.directions.recv.privateRanges.slice(0, 2)) {
    assert.deepEqual(result.obligations.find(item => item.hash === slot.hash),
      { ...slot, direction: 'RECV', length: slot.end - slot.start, predicate: 'header-v1' });
  }
  reject(input('Connection'));
});

test('request method, origin, nonce, target, duplicate headers and disclosure privacy are strict', () => {
  for (const [before, after] of [
    ['POST ', 'GET '], ['accounts.google.com', 'example.invalid'],
    [fixtureNonce, 'X'.repeat(43)], ['Connection: close', 'Connection: keep-alive'],
    ['/ListAccounts?', '/OtherAccount?'], ['json=standard', 'json=nonstand'],
    ['application/x-www-form-urlencoded', 'application/json'],
  ]) {
    const raw = identityFragments(); raw.sent = changePublic(raw.sent, before, after); reject(fromRaw(raw));
  }
  for (const requestHeaders of ['Host: accounts.google.com\r\n', 'Connection: close\r\n',
    'X-16Signals-Nonce: ' + fixtureNonce + '\r\n', 'Origin: https://attacker.invalid\r\n',
    'Accept: text/html\r\n', 'X-Employer: private-company\r\n']) reject(gcpFixture('identity', { requestHeaders }));
  for (const responseHeaders of ['Content-Type: application/json\r\n', 'Server: private-company\r\n',
    'Set-Cookie: raw-secret\r\n', 'Connection: keep-alive\r\n']) reject(gcpFixture('identity', { responseHeaders }));
  const raw = identityFragments();
  const cookie = raw.sent.hidden[1]; cookie.start += 4; // Partial public credential is not permitted.
  reject(fromRaw(raw));
});

test('identity complete-array shape and flags reject ambiguous or public employer fields', () => {
  const valid = identityRow();
  const badRows = [
    changePublic(valid, '"gaia.l.a"', '"other"'),
    changePublic(valid, ',0,1]', ',0,1.0]'),
    changePublic(valid, ',0,1]', ',2,1]'),
    fragments('["gaia.l.a",null,null,', literal('"public@example.test"'),
      ',null,null,null,null,null,1,', secret('"123"', 1), ',null,null,null,0,1]'),
    identityRow(0, '1', literal('123')),
    identityRow(0, '1', literal('"employer name"')),
    identityRow(0, '1', literal('{"unknown-employer-key":null}')),
  ];
  for (const row of badRows) reject(gcpFixture('identity', { rows: [row] }));
  for (const root of [literal('[]'), literal('["gaia.l.a.r",[]]'),
    fragments('["wrong",[', valid, ']]'), fragments('["gaia.l.a.r",[', valid, '],null]'),
    fragments('["gaia.l.a.r",', secret('"opaque rows"', 1), ']')]) reject(gcpFixture('identity', { root }));
  reject(gcpFixture('identity', { rows: Array.from({ length: 11 }, (_, index) => identityRow(index)) }));
  assert.equal(inspect(gcpFixture('identity', { rows: [identityRow(0, '0')] })).identity.rows[0].rowValid, false);
});

test('query scope slots require exact canonical body, account header and fixed key length', () => {
  for (const [before, after] of [['POST ', 'PUT '], ['logging.clients6.google.com', 'accounts.google.com'],
    ['/batch?key=', '/other?key='], ['pageSize', 'pageSizE'], ['entries(timestamp)', 'entries(resource)'],
    ['X-Goog-AuthUser', 'X-Other-AuthUser']]) {
    const raw = groupFragments(); raw.sent = changePublic(raw.sent, before, after); reject(fromRaw(raw, 'groups:0'));
  }
  reject(gcpFixture('groups:0', { requestHeaders: 'X-Goog-AuthUser: 0\r\n' }));
  const raw = groupFragments(); raw.sent.hidden.splice(3, 1); reject(fromRaw(raw, 'groups:0'));
  const fixture = gcpFixture('groups:0'); fixture.policy = { ...fixture.policy, cutoff: fixture.policy.cutoff + 1 }; reject(fixture);
});

test('successful entries schema cannot hide semantic keys, containers, extra events or public dates', () => {
  const timestamp = secret('"2026-10-12T12:34:56Z"', 1);
  const bodies = [
    literal('{"entries":null}'), literal('{"entries":[{},{}]}'), literal('{"entries":[{}]}'),
    literal('{"unknown":[]}'), literal('{"entries":[],"entries":[]}'),
    literal('{"entries":[{"timestamp":"2026-10-12T12:34:56Z"}]}'),
    fragments('{', secret('"entries"', 1), ':[]}'),
    fragments('{"entries":[{', secret('"timestamp"', 1), ':', timestamp, '}]}'),
    fragments('{"entries":[{"timestamp":', timestamp, ',"resource":null}]}'),
    fragments('{"entries":', secret('"not array"', 1), '}'),
    fragments('{"entries":[{"timestamp":', secret('123', 2), '}]}'),
  ];
  for (const body of bodies) reject(groupBody(body));
});

test('denied response requires public exact status and cannot substitute unknown semantic keys', () => {
  for (const body of [literal('{"error":{"code":403.0,"status":"PERMISSION_DENIED"}}'),
    literal('{"error":{"code":401,"status":"PERMISSION_DENIED"}}'),
    literal('{"error":{"code":403,"status":"NOT_FOUND"}}'),
    literal('{"error":{"code":403,"status":"PERMISSION_DENIED","other":null}}'),
    literal('{"error":{"code":403,"status":"PERMISSION_DENIED","message":"employer name"}}'),
    fragments('{"error":{"code":403,"status":', secret('"PERMISSION_DENIED"', 1), '}}'),
    fragments('{', secret('"error"', 1), ':{"code":403,"status":"PERMISSION_DENIED"}}')]) reject(groupBody(body, 'denied'));
  const body = fragments('{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{',
    secret('"employer-specific-key"', 1), ':', secret('"private-value"', 1), '}],"message":', secret('"no access"', 1), '}}');
  assert.equal(inspect(groupBody(body, 'denied')).groups[0].status, 'denied');
});

test('multipart rejects missing, duplicate or foreign IDs and unaccounted private framing', () => {
  const ids = BATCHES[0].groupIds;
  for (const selected of [ids.slice(1), [...ids, ids[0]], ['g999', ...ids.slice(1)]]) {
    reject(gcpFixture('groups:0', { parts: selected.map(id => groupPart(id, 'empty')) }));
  }
  const bad = groupPart(ids[0], 'empty');
  for (const [before, after] of [['application/http', 'application/json'], ['200 OK', '201 OK'],
    ['Content-ID:', 'Content-Id: <response-g999>\r\nContent-ID:'], ['Content-Type: application/json', 'Content-Type: text/plain']]) {
    const parts = [changePublic(bad, before, after), ...ids.slice(1).map(id => groupPart(id, 'empty'))];
    reject(gcpFixture('groups:0', { parts }));
  }
  const part = groupPart(ids[0], 'empty');
  const at = part.text.indexOf('<response-'); part.hidden.push({ start: at, end: at + '<response-g0>'.length, kind: 1 });
  reject(gcpFixture('groups:0', { parts: [part, ...ids.slice(1).map(id => groupPart(id, 'empty'))] }));
  assert.throws(() => parseMultipartStructure({ bytes: Uint8Array.of(0xff), wireIndices: Uint32Array.of(0), privateRanges: [] }, 'b'));
});

test('atom claims are exact range/hash proposals, all used once, with capacity and policy bounds', () => {
  for (const mutate of [
    fixture => fixture.atomicClaims.pop(),
    fixture => fixture.atomicClaims.push({ ...fixture.atomicClaims[0] }),
    fixture => { fixture.atomicClaims[0].hash = 'f'.repeat(64); },
    fixture => { fixture.atomicClaims[0].start++; },
    fixture => { fixture.atomicClaims[0].kind = 6; },
    fixture => { fixture.atomicClaims[0].kind = 2; },
    fixture => { fixture.meta.nonceMac = 'short'; },
    fixture => { fixture.meta.step = 'groups:5'; },
    fixture => { fixture.policy = { ...fixturePolicy, windowDays: 1 }; },
  ]) { const fixture = gcpFixture(); mutate(fixture); reject(fixture); }
  reject(gcpFixture('identity', { rows: [identityRow(0, '1', secret('"' + 'x'.repeat(511) + '"', 1))] }));
  const raw = identityFragments();
  const token = raw.sent.hidden[1];
  const before = raw.sent.text.slice(0, token.start), after = raw.sent.text.slice(token.end);
  raw.sent = fragments(before, secret('x'.repeat(2049)), after);
  // Reattach the target slot, which is still required and precedes the header.
  raw.sent.hidden.unshift({ start: raw.sent.text.indexOf('authuser=') + 9, end: raw.sent.text.indexOf('authuser=') + 10 });
  reject(fromRaw(raw));
});
