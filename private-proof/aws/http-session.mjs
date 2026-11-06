import { authenticatedAwsTranscript } from './authenticated-transcript.mjs';
import { parseHttpStructure } from '../gcp/http-structure.mjs';

const key = slot => `${slot.direction}:${slot.start}:${slot.end}:${slot.hash}`;
const fail = () => { throw new Error('AWS_PRIVATE_HTTP_INVALID'); };
const framing = new Set(['content-length', 'transfer-encoding', 'content-encoding']);

// Shared transport inspection for the two fixed AWS steps; obligations remain unverified.
export function inspectAwsHttpSession(receipt, expected, now) {
  return inspectAwsHttpDirections(authenticatedAwsTranscript(receipt, expected, now), expected);
}

/** Structural inspection for local planning; directions alone have no native provenance. */
export function inspectAwsHttpDirections(directions, expected) {
  const sent = parseHttpStructure(directions.sent, { kind: 'request' });
  const recv = parseHttpStructure(directions.recv, { kind: 'response' });
  if (sent.startLine.method !== 'POST' || sent.startLine.target.text !== '/' || recv.startLine.status !== 200 ||
      recv.startLine.reason.text !== 'OK') fail();
  const native = new Map(), obligations = [];
  for (const [direction, message] of [['SENT', sent], ['RECV', recv]]) {
    for (const range of message.privateRanges) {
      const slot = { direction, start: range.start, end: range.end, hash: range.hash, length: range.end - range.start };
      native.set(key(slot), slot);
    }
  }
  const obligeHeader = (message, direction, header) => {
    let cursor = header.value.start;
    for (const range of message.privateRanges.filter(range => range.start >= cursor && range.end <= header.value.end)) {
      if (range.start !== cursor || range.end - range.start > 2048) fail();
      obligations.push({ circuitId: 'header-v1', ...native.get(key({ ...range, direction })) });
      cursor = range.end;
    }
    if (cursor !== header.value.end) fail();
  };
  const headers = (message, direction, approved, required) => {
    const seen = new Set();
    for (const header of message.headers) {
      if (seen.has(header.name) && (direction === 'SENT' || framing.has(header.name) || approved.has(header.name))) fail();
      seen.add(header.name);
      if (framing.has(header.name)) continue;
      if (approved.has(header.name)) {
        const value = approved.get(header.name);
        if (typeof value === 'string' ? header.value.text !== value : !value.test(header.value.text ?? '')) fail();
      } else {
        if (required.includes(header.name) && header.value.start === header.value.end) fail();
        obligeHeader(message, direction, header);
      }
    }
    if (required.some(name => !seen.has(name))) fail();
  };
  const identity = expected.step === 'identity';
  const requestHeaders = new Map([
    ['host', identity ? 'iam.amazonaws.com' : 'cloudtrail.us-east-1.amazonaws.com'],
    ['connection', 'close'], ['accept-encoding', 'identity'], ['x-16signals-nonce', expected.nonceMac],
    ['content-type', identity ? 'application/x-www-form-urlencoded' : 'application/x-amz-json-1.1'],
  ]);
  if (!identity) requestHeaders.set('x-amz-target', 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents');
  headers(sent, 'SENT', requestHeaders, [...requestHeaders.keys(), 'content-length', 'authorization', 'x-amz-date', 'x-amz-security-token']);
  headers(recv, 'RECV', new Map([['content-type', identity ? /^text\/xml(?:; ?charset=utf-8)?$/i : 'application/x-amz-json-1.1'],
    ['connection', 'close']]), ['content-type']);
  return { sent, recv, native, obligations };
}
