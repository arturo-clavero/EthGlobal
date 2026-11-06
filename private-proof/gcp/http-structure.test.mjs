import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpStructureError, parseHttpStructure } from './http-structure.mjs';
import { parseJsonStructure } from './json-structure.mjs';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const input = text => ({ bytes: encoder.encode(text), privateRanges: [] });
const parse = (text, kind = 'response') => parseHttpStructure(typeof text === 'string' ? input(text) : text, { kind });
const fails = (text, kind = 'response', code) => assert.throws(() => parse(text, kind),
  error => error instanceof HttpStructureError && (!code || error.code === code));
const response = (body, headers = '') => `HTTP/1.1 200 OK\r\n${headers}\r\n${body}`;
function hidden(text, tokens) {
  const packet = input(text);
  let cursor = 0;
  for (const secret of tokens) {
    const at = text.indexOf(secret, cursor);
    assert.notEqual(at, -1);
    const start = encoder.encode(text.slice(0, at)).length;
    const end = start + encoder.encode(secret).length;
    packet.bytes.fill(0, start, end);
    packet.privateRanges.push({ start, end, hash: (packet.privateRanges.length + 1).toString(16).padStart(64, '0') });
    cursor = at + secret.length;
  }
  return packet;
}

test('request target, private header and private JSON atom remain separately classified', () => {
  const body = '{"value":"private"}';
  const raw = `POST /batch?key=private-api HTTP/1.1\r\nHost: example.invalid\r\nAuthorization: Bearer private-token\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
  const source = hidden(raw, ['private-api', 'private-token', '"private"']);
  const result = parse(source, 'request');
  assert.equal(result.startLine.method, 'POST');
  assert.equal(result.startLine.target.text, undefined);
  assert.equal(result.startLine.text, undefined);
  assert.deepEqual(result.privateRanges.map(range => range.location), ['request-target', 'header-value', 'body']);
  assert.deepEqual(result.privateRanges.map(range => range.requiredPredicate), ['request-target-grammar', 'header-ascii', 'body-grammar']);
  assert.equal(result.headers[0].value.text, 'example.invalid');
  assert.equal(result.headers[1].value.text, undefined);
  assert.equal(result.headers[1].privateIndices[0], 1);
  const atom = result.body.privateRanges[0];
  assert.equal(atom.sourceIndex, 2);
  assert.equal(atom.wireStart, source.privateRanges[2].start);
  assert.equal(atom.wireEnd, source.privateRanges[2].end);
  assert.equal(result.body.wireIndices[atom.start], atom.wireStart);
  assert.equal(result.body.wireIndices[atom.end - 1], atom.wireEnd - 1);
  const json = parseJsonStructure(result.body.bytes, result.body.privateRanges.map(range => ({ ...range, kind: 1 })));
  assert.equal(json.root.entries[0].key.value, 'value');
  assert.equal(json.root.entries[0].value.privateSlot, 0);
  source.privateRanges[2].start = 0;
  source.bytes.fill(42);
  assert.notEqual(result.body.privateRanges[0].wireStart, 0);
  assert.equal(result.body.bytes[atom.start], 0);
});

test('Content-Length, empty requests and EOF responses consume one complete message', () => {
  assert.equal(parse('GET / HTTP/1.1\r\nHost: test.invalid\r\n\r\n', 'request').framing, 'none');
  assert.equal(parse('POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n', 'request').body.bytes.length, 0);
  const result = parse(response('{}', 'Content-Length:\t2 \t\r\nContent-Encoding: identity\r\n'));
  assert.equal(result.startLine.status, 200);
  assert.equal(result.startLine.reason.text, 'OK');
  assert.equal(decoder.decode(result.body.bytes), '{}');
  assert.equal(result.framing, 'content-length');
  assert.equal(parse(response('{}')).framing, 'eof');
  assert.equal(parse('HTTP/1.1 204 No Content\r\n\r\n').body.bytes.length, 0);
  assert.equal(parse('HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n').body.bytes.length, 0);
  fails('POST / HTTP/1.1\r\n\r\nx', 'request', 'REQUEST_BODY_FRAMING');
  fails(response('{}', 'Content-Length: 1\r\n'), 'response', 'CONTENT_LENGTH_MISMATCH');
  fails(response('{}', 'Content-Length: 3\r\n'), 'response', 'CONTENT_LENGTH_MISMATCH');
  fails('HTTP/1.1 204 No Content\r\n\r\nx', 'response', 'BODY_FORBIDDEN');
  fails('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n', 'response', 'BODY_FORBIDDEN');
});

test('chunked decoding preserves exact wire positions for a complete private atom', () => {
  const prefix = '{"v":';
  const atom = '"secret"';
  const raw = response(`${prefix.length.toString(16)}\r\n${prefix}\r\n${atom.length.toString(16)}\r\n${atom}\r\n1\r\n}\r\n0\r\n\r\n`, 'Transfer-Encoding: chunked\r\n');
  const packet = hidden(raw, [atom]);
  const result = parse(packet);
  assert.equal(result.framing, 'chunked');
  assert.equal(result.chunks.length, 3);
  assert.equal(result.body.privateRanges[0].start, prefix.length);
  assert.equal(result.body.privateRanges[0].end, prefix.length + atom.length);
  assert.equal(result.body.privateRanges[0].wireStart, packet.privateRanges[0].start);
  for (let index = 0; index < result.body.bytes.length; index++) {
    assert.equal(result.body.bytes[index], packet.bytes[result.body.wireIndices[index]]);
  }
  const json = parseJsonStructure(result.body.bytes, result.body.privateRanges.map(range => ({ ...range, kind: 1 })));
  assert.equal(json.root.entries[0].value.privateSlot, 0);
});

test('private reason phrases are provisional header text, not public status', () => {
  const result = parse(hidden('HTTP/1.1 403 private-reason\r\n\r\n', ['private-reason']));
  assert.equal(result.startLine.status, 403);
  assert.equal(result.startLine.reason.text, undefined);
  assert.equal(result.privateRanges[0].location, 'reason-phrase');
  assert.equal(result.privateRanges[0].requiredPredicate, 'header-ascii');
});

test('framing headers are public singletons with no transfer/length ambiguity', () => {
  for (const headers of [
    'Content-Length: 0\r\ncontent-length: 0\r\n',
    'Transfer-Encoding: chunked\r\nTRANSFER-ENCODING: chunked\r\n',
    'Content-Encoding: identity\r\nCONTENT-ENCODING: identity\r\n',
    'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n',
    'Content-Length: +0\r\n', 'Content-Length: 0,0\r\n', 'Content-Length: 1e0\r\n',
    'Content-Length: 99999999999999999999999\r\n',
    'Transfer-Encoding: gzip, chunked\r\n', 'Transfer-Encoding: identity\r\n',
    'Content-Encoding: gzip\r\n',
  ]) fails(response('', headers));
  for (const [name, value] of [['Content-Length', '0000'], ['Transfer-Encoding', 'chunked'], ['Content-Encoding', 'identity']]) {
    fails(hidden(response('', `${name}: ${value}\r\n`), [value]), 'response', 'PRIVATE_FRAMING');
  }
  const repeated = parse(response('', 'Vary: A\r\nVary: B\r\n'));
  assert.deepEqual(repeated.headers.map(header => header.value.text), ['A', 'B']);
});

test('method, version, status, header names and delimiters cannot be private', () => {
  for (const [raw, secret, kind] of [
    ['GET / HTTP/1.1\r\n\r\n', 'GET', 'request'],
    ['GET / HTTP/1.1\r\n\r\n', 'HTTP/1.1', 'request'],
    ['HTTP/1.1 200 OK\r\n\r\n', '200', 'response'],
    ['HTTP/1.1 200 OK\r\n\r\n', 'HTTP/1.1', 'response'],
    ['HTTP/1.1 200 OK\r\nSecret: value\r\n\r\n', 'Secret', 'response'],
    ['HTTP/1.1 200 OK\r\nX: value\r\n\r\n', ':', 'response'],
    ['GET / HTTP/1.1\r\nHost: a\r\n\r\n', 'HTTP/1.1\r\nHost', 'request'],
  ]) fails(hidden(raw, [secret]), kind);
});

test('chunk sizes, delimiters, extensions and trailers fail closed', () => {
  for (const body of ['1;name=x\r\na\r\n0\r\n\r\n', '1\r\na\r\n0\r\nX: y\r\n\r\n',
    '1\r\na\r\n0\r\n\r\nx', '2\r\na\r\n0\r\n\r\n', '1\r\naX\n0\r\n\r\n',
    'g\r\na\r\n0\r\n\r\n', 'ffffffff\r\na\r\n0\r\n\r\n', '1\r\na\r\n']) {
    fails(response(body, 'Transfer-Encoding: chunked\r\n'));
  }
  const raw = response('1\r\na\r\n0\r\n\r\n', 'Transfer-Encoding: chunked\r\n');
  fails(hidden(raw, ['1\r\n']), 'response');
  fails(hidden(raw, ['a\r\n0']), 'response');
  // A contiguous wire commitment over two chunks includes their framing.
  const split = response('2\r\n"a\r\n2\r\nb"\r\n0\r\n\r\n', 'Transfer-Encoding: chunked\r\n');
  fails(hidden(split, ['"a\r\n2\r\nb"']), 'response');
});

test('strict HTTP/1.1 ASCII rejects malformed lines and control bytes', () => {
  for (const raw of ['HTTP/1.0 200 OK\r\n\r\n', 'HTTP/1.1 200\r\n\r\n',
    'HTTP/1.1 600 Nope\r\n\r\n', 'HTTP/1.1 200 OK\n\n', 'HTTP/1.1 200 OK\rX\r\n',
    'HTTP/1.1 200 OK\r\n X: folded\r\n\r\n', 'HTTP/1.1 200 OK\r\nX : value\r\n\r\n',
    'HTTP/1.1 200 OK\r\nX: value\u007f\r\n\r\n', response('é'), response('\0')]) fails(raw);
  for (const raw of ['GET /a b HTTP/1.1\r\n\r\n', 'GET\t/ HTTP/1.1\r\n\r\n',
    'GET /\t HTTP/1.1\r\n\r\n', 'GET  HTTP/1.1\r\n\r\n']) fails(raw, 'request');
});

test('private metadata is bounded, sorted, disjoint, zeroed and not aliased', () => {
  const packet = hidden(response('private-one private-two'), ['private-one', 'private-two']);
  parse(packet);
  for (const mutate of [
    value => value.privateRanges.reverse(),
    value => { value.privateRanges[1].start = value.privateRanges[0].start; },
    value => { value.privateRanges[0].start = -1; },
    value => { value.privateRanges[0].end = value.bytes.length + 1; },
    value => { value.privateRanges[0].hash = 'AB'.repeat(32); },
    value => { value.bytes[value.privateRanges[0].start] = 65; },
  ]) {
    const changed = structuredClone(packet);
    mutate(changed);
    fails(changed);
  }
  fails({ bytes: [], privateRanges: [] });
  fails({ bytes: packet.bytes, privateRanges: Array(257).fill(packet.privateRanges[0]) });
  assert.throws(() => parseHttpStructure(packet, { kind: 'other' }), HttpStructureError);
});

test('resource limits include headers, data chunks and total transcript bytes', () => {
  parse(response('', 'X: a\r\n'.repeat(64)));
  fails(response('', 'X: a\r\n'.repeat(65)), 'response', 'HEADER_LIMIT');
  const chunks = count => response('1\r\na\r\n'.repeat(count) + '0\r\n\r\n', 'Transfer-Encoding: chunked\r\n');
  assert.equal(parse(chunks(64)).body.bytes.length, 64);
  fails(chunks(65), 'response', 'CHUNK_LIMIT');
  const prefix = response('');
  assert.equal(parse(prefix + 'a'.repeat(16384 - prefix.length)).body.bytes.length, 16384 - prefix.length);
  fails(prefix + 'a'.repeat(16385 - prefix.length), 'response', 'INPUT_LIMIT');
});
