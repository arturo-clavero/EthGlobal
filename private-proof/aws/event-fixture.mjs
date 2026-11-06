import { createHash } from 'node:crypto';
import { parseJsonStructure } from '../gcp/json-structure.mjs';

// Synthetic receipts only: these helpers make no AWS requests and authenticate no TLS.
export const fixtureNow = 1_800_000_000_000;
export const fixtureExpected = { sessionId: '11111111-1111-4111-8111-111111111111', proofId: '22222222-2222-4222-8222-222222222222',
  pluginSha256: 'ab'.repeat(32), nonceMac: 'N'.repeat(43), step: 'E0', identityService: 'iam', region: 'us-east-1',
  issuedAt: fixtureNow - 1000, expiresAt: fixtureNow + 1000 };

/** Reconstruct local plaintext/openings for tests only; never native authentication. */
export function syntheticWitness({ receipt, openings }) {
  const witness = { sessionId: receipt.session.id, serverName: receipt.server_name, step: receipt.session.step,
    proofId: receipt.session.proofId, nonceMac: receipt.session.nonceMac, selections: {}, openings: {} };
  for (const direction of ['sent', 'recv']) {
    const bytes = Uint8Array.from(Buffer.from(receipt.transcript[direction]));
    const results = receipt.results.filter(row => row.type === direction.toUpperCase());
    witness.selections[direction] = structuredClone(receipt.config[direction]); witness.openings[direction] = [];
    receipt.config[direction].forEach((range, index) => {
      if (range.handler.action.kind !== 'HASH') return;
      const hash = results[index].value, preimage = openings.get(hash), length = range.end - range.start;
      if (preimage?.length !== length + 16) throw new Error('SYNTHETIC_OPENING_INVALID');
      bytes.set(preimage.subarray(0, length), range.start);
      witness.openings[direction].push({ start: range.start, end: range.end,
        hash: Uint8Array.from(Buffer.from(hash, 'hex')), blinder: Uint8Array.from(preimage.subarray(length)) });
    });
    witness[direction] = bytes;
  }
  return witness;
}
export function eventFixture(options = {}) {
  const eventId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const event = { eventVersion: '1.11', eventTime: '2026-10-29T08:00:00Z', eventID: eventId,
    eventName: 'UpdateAssumeRolePolicy', eventSource: 'iam.amazonaws.com', awsRegion: 'us-east-1',
    eventType: 'AwsApiCall', eventCategory: 'Management', managementEvent: true, readOnly: false,
    recipientAccountId: '111122223333', userIdentity: { type: 'IAMUser', principalId: 'AIDAEXAMPLESYNTHETIC01',
      arn: 'arn:aws:iam::111122223333:user/synthetic', accountId: '111122223333', userName: 'AWS_PRIVATE_USER_SENTINEL',
      accessKeyId: 'AWS_PRIVATE_KEY_SENTINEL', sessionContext: { attributes: { creationDate: '2026-10-29T07:00:00Z', mfaAuthenticated: 'true' } } },
    requestParameters: { roleName: 'AWS_PRIVATE_ROLE_SENTINEL', policyDocument: '{"Version":"2012-10-17","Statement":[]}' },
    responseElements: null, sourceIPAddress: '192.0.2.1', userAgent: 'AWS_PRIVATE_AGENT_SENTINEL', requestID: eventId,
    tlsDetails: { tlsVersion: 'TLSv1.2', cipherSuite: 'SYNTHETIC', clientProvidedHostHeader: 'iam.amazonaws.com' } };
  options.mutateEvent?.(event);
  const request = { LookupAttributes: [{ AttributeKey: 'EventId', AttributeValue: eventId }], MaxResults: 1 };
  options.mutateRequest?.(request);
  const row = { EventId: eventId, EventName: 'UpdateAssumeRolePolicy', EventSource: 'iam.amazonaws.com',
    EventTime: Date.parse('2026-10-29T08:00:00Z') / 1000, ReadOnly: 'false', Username: 'AWS_PRIVATE_USER_SENTINEL',
    CloudTrailEvent: JSON.stringify(event), Resources: [{ ResourceName: 'AWS_PRIVATE_RESOURCE_SENTINEL', ResourceType: 'AWS::IAM::Role' }] };
  options.mutateRow?.(row);
  const requestBody = Buffer.from(JSON.stringify(request)), responseBody = Buffer.from(JSON.stringify({ Events: [row] }));
  const eventBody = Buffer.from(row.CloudTrailEvent);
  let sequence = 0;
  const openings = new Map();
  const digest = bytes => {
    const preimage = Buffer.concat([bytes, Buffer.alloc(16, ++sequence)]);
    const hash = createHash('sha256').update(preimage).digest('hex');
    openings.set(hash, preimage);
    return hash;
  };
  const slots = (bytes, publicPaths) => {
    const output = [];
    const visit = (node, path) => {
      if (publicPaths.has(path)) return;
      if (node.type === 'object') for (const entry of node.entries) visit(entry.value, path ? `${path}.${entry.key.value}` : entry.key.value);
      else if (node.type === 'array') node.items.forEach((item, index) => visit(item, `${path}.${index}`));
      else output.push({ start: node.start, end: node.end, kind: node.kind, hash: digest(bytes.subarray(node.start, node.end)), layer: 'outer' });
    };
    visit(parseJsonStructure(bytes).root, '');
    return output;
  };
  const requestSlots = slots(requestBody, new Set(['LookupAttributes.0.AttributeKey', 'MaxResults']));
  const responseSlots = slots(responseBody, new Set(['Events.0.EventName', 'Events.0.EventSource', 'Events.0.ReadOnly', 'Events.0.CloudTrailEvent']));
  const publicEvent = new Set(['eventVersion', 'eventName', 'eventSource', 'awsRegion', 'eventType', 'eventCategory',
    'managementEvent', 'readOnly', 'responseElements', 'userIdentity.type', 'requestParameters.dryRun', ...(options.publicEvent ?? [])]);
  const eventStart = responseBody.indexOf(Buffer.from('"CloudTrailEvent":"')) + Buffer.byteLength('"CloudTrailEvent":"');
  for (const slot of slots(eventBody, publicEvent)) {
    const prefix = JSON.stringify(eventBody.subarray(0, slot.start).toString()).slice(1, -1);
    const atom = JSON.stringify(eventBody.subarray(slot.start, slot.end).toString()).slice(1, -1);
    const start = eventStart + Buffer.byteLength(prefix);
    responseSlots.push({ start, end: start + Buffer.byteLength(atom), layer: 'event', kind: slot.kind,
      hash: digest(Buffer.from(atom)), decodedHash: slot.hash, decodedLength: slot.end - slot.start });
  }
  responseSlots.sort((a, b) => a.start - b.start);
  const requestHeaders = [
    ['host', 'cloudtrail.us-east-1.amazonaws.com'], ['connection', 'close'], ['accept-encoding', 'identity'],
    ['content-type', 'application/x-amz-json-1.1'], ['x-16signals-nonce', fixtureExpected.nonceMac],
    ['x-amz-target', 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents'],
    ['authorization', 'SYNTHETIC_PRIVATE_AUTHORIZATION', true], ['x-amz-date', '20261029T080000Z', true],
    ['x-amz-security-token', 'SYNTHETIC_PRIVATE_SESSION_TOKEN', true],
  ];
  const responseHeaders = [['content-type', 'application/x-amz-json-1.1'], ['connection', 'close'],
    ['x-amzn-requestid', 'SYNTHETIC_PRIVATE_REQUEST_ID', true], ['date', 'Thu, 29 Oct 2026 08:00:00 GMT', true]];
  options.mutateHeaders?.(requestHeaders, responseHeaders);
  const receipt = { server_name: 'cloudtrail.us-east-1.amazonaws.com', session: {
    id: fixtureExpected.sessionId, proofId: fixtureExpected.proofId, pluginSha256: fixtureExpected.pluginSha256,
    nonceMac: fixtureExpected.nonceMac, step: 'E0', method: 'AWS_ACCOUNT', mode: 'Proxy' }, config: {}, results: [], transcript: {} };
  const claims = [];
  function direction(name, body, bodySlots, headers, startLine, chunkAt) {
    let text = startLine + '\r\n';
    const ranges = [];
    for (const [name, value, hidden] of headers) {
      const start = Buffer.byteLength(text + name + ': ');
      text += `${name}: ${value}\r\n`;
      if (hidden) ranges.push({ start, end: start + Buffer.byteLength(value), hash: digest(Buffer.from(value)) });
    }
    text += chunkAt === undefined ? `content-length: ${body.length}\r\n\r\n` : 'transfer-encoding: chunked\r\n\r\n';
    const prefix = Buffer.from(text), parts = [prefix], indices = [];
    let position = prefix.length;
    if (chunkAt === undefined) {
      parts.push(body);
      for (let i = 0; i < body.length; i++) indices.push(position + i);
    } else {
      let start = 0;
      for (const end of [chunkAt, body.length]) {
        const line = Buffer.from((end - start).toString(16) + '\r\n');
        parts.push(line, body.subarray(start, end), Buffer.from('\r\n'));
        position += line.length;
        for (let i = start; i < end; i++) indices.push(position + i - start);
        position += end - start + 2; start = end;
      }
      parts.push(Buffer.from('0\r\n\r\n'));
    }
    for (const slot of bodySlots) {
      const mapped = { ...slot, direction: name.toUpperCase(), start: indices[slot.start], end: indices[slot.end - 1] + 1 };
      claims.push(mapped); ranges.push(mapped);
    }
    const bytes = Buffer.concat(parts);
    ranges.sort((a, b) => a.start - b.start);
    for (const range of ranges) bytes.fill(0, range.start, range.end);
    const config = [];
    const append = (start, end, hash) => {
      const handler = { type: name.toUpperCase(), part: 'BODY', action: hash ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' } };
      config.push({ start, end, handler });
      receipt.results.push({ ...handler, value: hash ?? bytes.subarray(start, end).toString() });
    };
    let cursor = 0;
    for (const range of ranges) {
      if (cursor < range.start) append(cursor, range.start);
      append(range.start, range.end, range.hash); cursor = range.end;
    }
    if (cursor < bytes.length) append(cursor, bytes.length);
    receipt.config[name] = config;
    receipt.transcript[name] = bytes.toString(); receipt.transcript[`${name}_length`] = bytes.length;
  }
  direction('sent', requestBody, requestSlots, requestHeaders, options.startLine ?? 'POST / HTTP/1.1');
  const split = options.crossChunk ? responseSlots[0].start + 1 : options.chunked ? 10 : undefined;
  direction('recv', responseBody, responseSlots, responseHeaders, options.statusLine ?? 'HTTP/1.1 200 OK', split);
  return { receipt, expected: { ...fixtureExpected }, claims, openings };
}
