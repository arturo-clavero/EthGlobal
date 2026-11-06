import assert from 'node:assert/strict';
import test from 'node:test';
import { gcpCredentialScanView } from './credential-scan-view.mjs';
import { fragments, gcpFixture, literal, secret } from './gcp-fixtures.mjs';

function nativeFixture(step = 'identity', options = {}) {
  const { directions, meta } = gcpFixture(step, options);
  const expected = { sessionId: '11111111-1111-4111-8111-111111111111',
    proofId: '22222222-2222-4222-8222-222222222222', pluginSha256: 'ab'.repeat(32),
    nonceMac: meta.nonceMac, step };
  const receipt = { server_name: step === 'identity' ? 'accounts.google.com' : 'logging.clients6.google.com',
    session: { id: expected.sessionId, proofId: expected.proofId, pluginSha256: expected.pluginSha256,
      nonceMac: expected.nonceMac, step, method: 'GCP_WORK', mode: 'Proxy' },
    config: {}, results: [], transcript: {} };
  for (const direction of ['sent', 'recv']) {
    const { bytes, privateRanges } = directions[direction], ranges = receipt.config[direction] = [];
    const add = (start, end, hash) => {
      if (start === end) return;
      const handler = { type: direction.toUpperCase(), part: 'BODY',
        action: hash ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' } };
      ranges.push({ start, end, handler });
      receipt.results.push({ ...handler, value: hash ?? String.fromCharCode(...bytes.subarray(start, end)) });
    };
    let cursor = 0;
    for (const range of privateRanges) { add(cursor, range.start); add(range.start, range.end, range.hash); cursor = range.end; }
    add(cursor, bytes.length);
    receipt.transcript[direction] = String.fromCharCode(...bytes);
    receipt.transcript[`${direction}_length`] = bytes.length;
  }
  return { receipt, expected };
}

function splitReveal(receipt, direction, offset) {
  const ranges = receipt.config[direction], index = ranges.findIndex(range =>
    range.handler.action.kind === 'REVEAL' && range.start < offset && offset < range.end);
  assert.notEqual(index, -1);
  const range = ranges[index], result = receipt.results.filter(result => result.type === direction.toUpperCase())[index];
  ranges.splice(index, 1, { ...range, end: offset }, { ...range, start: offset });
  receipt.results.splice(receipt.results.indexOf(result), 1,
    { ...result, value: result.value.slice(0, offset - range.start) },
    { ...result, value: result.value.slice(offset - range.start) });
}

function assertOnlyNamesChanged(receipt, view, names) {
  for (const direction of ['sent', 'recv']) {
    const before = receipt.transcript[direction], after = view.transcript[direction];
    assert.equal(after.length, before.length);
    const changed = new Set();
    for (const name of names[direction] ?? []) {
      const needle = '\r\n' + name + ':';
      let start = before.indexOf(needle);
      assert.notEqual(start, -1);
      while (start !== -1) {
        for (let at = start + 2; at < start + 2 + name.length; at++) changed.add(at);
        start = before.indexOf(needle, start + needle.length);
      }
    }
    for (let at = 0; at < before.length; at++) assert.equal(after[at], changed.has(at) ? '\0' : before[at]);
  }
}

test('only fully hidden credential header names change; source and HASH values remain intact', () => {
  const { receipt, expected } = nativeFixture('identity', {
    requestHeaders: fragments('Authorization:\t ', secret('first'), secret('second'), ' \t\r\nProxy-Authorization: ', secret('proxy'), '\r\n'),
    responseHeaders: fragments('Set-Cookie: ', secret('one'), '\r\nSet-Cookie: ', secret('two'), '\r\n'),
  });
  const before = structuredClone(receipt), view = gcpCredentialScanView(receipt, expected);
  assertOnlyNamesChanged(receipt, view, { sent: ['Cookie', 'Authorization', 'Proxy-Authorization'], recv: ['Set-Cookie'] });
  assert.deepEqual(receipt, before);
  assert.deepEqual(view.results.filter(result => result.action.kind === 'HASH'), receipt.results.filter(result => result.action.kind === 'HASH'));
  for (const result of view.results.filter(result => result.action.kind === 'REVEAL')) assert.doesNotMatch(result.value, /(?:Cookie|Authorization):/);
});

test('fragmented names, interleaved directions and unsorted range order retain exact offset mapping', () => {
  const { receipt, expected } = nativeFixture('identity', { responseHeaders: fragments('Set-Cookie: ', secret('cookie'), '\r\n') });
  splitReveal(receipt, 'sent', receipt.transcript.sent.indexOf('Cookie:') + 3);
  splitReveal(receipt, 'recv', receipt.transcript.recv.indexOf('Set-Cookie:') + 4);
  const sent = receipt.results.filter(result => result.type === 'SENT');
  const recv = receipt.results.filter(result => result.type === 'RECV');
  receipt.config.sent.reverse(); sent.reverse();
  receipt.results = Array.from({ length: Math.max(sent.length, recv.length) }, (_, index) => [recv[index], sent[index]]).flat().filter(Boolean);
  const view = gcpCredentialScanView(receipt, expected);
  assertOnlyNamesChanged(receipt, view, { sent: ['Cookie'], recv: ['Set-Cookie'] });
  const positions = { sent: 0, recv: 0 };
  for (const result of view.results) {
    const direction = result.type.toLowerCase(), range = receipt.config[direction][positions[direction]++];
    if (result.action.kind === 'REVEAL') assert.equal(result.value, view.transcript[direction].slice(range.start, range.end));
  }
});

for (const [label, header] of [
  ['public', literal('Authorization: public-token\r\n')],
  ['partly public', fragments('Authorization: ', secret('hidden'), 'public-token\r\n')],
  ['gap', fragments('Authorization: ', secret('hidden'), ' ', secret('hidden'), '\r\n')],
  ['empty', literal('Authorization: \t\r\n')],
  ['unexpected direction', fragments('Set-Cookie: ', secret('hidden'), '\r\n')],
  ['unrecognized name', fragments('X-Authorization: ', secret('hidden'), '\r\n')],
]) test(`leaves ${label} header untouched for the existing scanner`, () => {
  const { receipt, expected } = nativeFixture('identity', { requestHeaders: header });
  const view = gcpCredentialScanView(receipt, expected);
  assertOnlyNamesChanged(receipt, view, { sent: ['Cookie'] });
  assert.ok(view.transcript.sent.includes(header.text.split(':')[0] + ':'));
});

test('response Authorization and Cookie remain untouched', () => {
  const { receipt, expected } = nativeFixture('identity', { responseHeaders: fragments(
    'Authorization: ', secret('hidden'), '\r\nCookie: ', secret('hidden'), '\r\n') });
  const view = gcpCredentialScanView(receipt, expected);
  assert.equal(view.transcript.recv, receipt.transcript.recv);
});

test('body credentials and token markers retain every byte, including split REVEAL fragments', () => {
  const body = 'Authorization: public-token\r\nuser_session=token ghp_secret csrf current_user';
  const { receipt, expected } = nativeFixture('identity', { root: literal(body) });
  splitReveal(receipt, 'recv', receipt.transcript.recv.indexOf('user_session') + 4);
  const view = gcpCredentialScanView(receipt, expected);
  assert.equal(view.transcript.recv, receipt.transcript.recv);
  assert.ok(view.transcript.recv.includes(body));
});

for (const chunked of [false, true]) test(`nested Set-Cookie uses native wire offsets (chunked=${chunked})`, () => {
  const part = fragments('--fixture_boundary\r\nContent-Type: application/http\r\nContent-ID: <response-g1>\r\n\r\n',
    'HTTP/1.1 200 OK\r\nSet-Cookie: ', secret('nested-cookie'), '\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{"entries":[]}\r\n');
  const { receipt, expected } = nativeFixture('groups:0', { parts: [part], chunked });
  const view = gcpCredentialScanView(receipt, expected);
  assertOnlyNamesChanged(receipt, view, { sent: ['Authorization'], recv: ['Set-Cookie'] });
});

test('MIME envelope credentials are not treated as HTTP response headers', () => {
  const part = fragments('--fixture_boundary\r\nContent-Type: application/http\r\nSet-Cookie: exposed\r\nContent-ID: <response-g1>\r\n\r\n',
    'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{"entries":[]}\r\n');
  const { receipt, expected } = nativeFixture('groups:0', { parts: [part] });
  assert.throws(() => gcpCredentialScanView(receipt, expected), { message: 'GCP_PRIVATE_TRANSCRIPT_INVALID' });
});

for (const [label, mutate] of [
  ['wrong method', receipt => { receipt.session.method = 'AWS_WORK'; }],
  ['wrong mode', receipt => { receipt.session.mode = 'MPC'; }],
  ['wrong pin', receipt => { receipt.session.pluginSha256 = 'cd'.repeat(32); }],
  ['wrong nonce', receipt => { receipt.session.nonceMac = 'X'.repeat(43); }],
  ['mismatched transcript', receipt => { receipt.transcript.sent = receipt.transcript.sent.replace('\0', 'X'); }],
  ['gapped range', receipt => { receipt.config.sent[1].start++; }],
  ['overlapping range', receipt => { receipt.config.sent[1].start--; }],
  ['public NUL', receipt => {
    const result = receipt.results.find(result => result.type === 'SENT' && result.action.kind === 'HASH');
    const range = receipt.config.sent.find(range => range.handler.action.kind === 'HASH');
    result.action = { kind: 'REVEAL' }; result.value = '\0'.repeat(range.end - range.start); range.handler.action = { kind: 'REVEAL' };
  }],
  ['extra result', receipt => { receipt.results.push({ ...receipt.results[0], value: 'Authorization: public' }); }],
]) test(`rejects ${label} before a scanner view exists`, () => {
  const { receipt, expected } = nativeFixture(); mutate(receipt);
  assert.throws(() => gcpCredentialScanView(receipt, expected), { message: 'GCP_PRIVATE_TRANSCRIPT_INVALID' });
});

for (const header of [' Cookie: folded\r\n', 'Cookie : invalid\r\n', 'Content-Length: 1\r\n']) {
  test(`rejects malformed header framing ${JSON.stringify(header)}`, () => {
    const { receipt, expected } = nativeFixture('identity', { requestHeaders: header });
    assert.throws(() => gcpCredentialScanView(receipt, expected), { message: 'GCP_PRIVATE_TRANSCRIPT_INVALID' });
  });
}
