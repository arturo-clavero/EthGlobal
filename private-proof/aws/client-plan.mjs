import { parseHttpStructure } from '../gcp/http-structure.mjs';
import { parseJsonStructure } from '../gcp/json-structure.mjs';
import { inspectAwsIdentityDirections } from './identity-structure.mjs';
import { inspectAwsEventDirections } from './event-structure.mjs';

const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const ZERO = '0'.repeat(64);
const fail = () => { throw new Error('AWS_PRIVATE_CLIENT_INVALID'); };
const child = (node, key) => node?.entries?.find(entry => entry.key.value === key)?.value;
const ascii = bytes => Uint8Array.from(bytes, byte => byte > 127 ? 63 : byte);

function localHttp(bytes, kind) {
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 16384) fail();
  const shadow = ascii(bytes);
  let message;
  try {
    message = parseHttpStructure({ bytes: shadow, privateRanges: [] }, { kind });
    return { ...message, body: { ...message.body,
      bytes: Uint8Array.from(message.body.wireIndices, index => bytes[index]) } };
  } finally { shadow.fill(0); message?.body.bytes.fill(0); }
}

/** Local-only selection planning. Returned offsets/hashes are provisional, never native provenance. */
export function planAwsSession(meta, transcripts) {
  const buffers = [];
  try {
    if (!meta || !['identity', 'E0', 'E1', 'E2'].includes(meta.step) || !/^[A-Za-z0-9_-]{43}$/.test(meta.nonceMac ?? '') ||
        meta.serverName !== (meta.step === 'identity' ? 'iam.amazonaws.com' : 'cloudtrail.us-east-1.amazonaws.com')) fail();
    const identity = meta.step === 'identity';
    const sent = localHttp(transcripts.sent, 'request'); buffers.push(sent.body.bytes);
    const recv = localHttp(transcripts.recv, 'response'); buffers.push(recv.body.bytes);
    const privateSlots = { sent: [], recv: [] };
    const hide = (direction, map, start, end, attributes = {}, cap = 512) => {
      if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || start >= end || end > map.length || end - start > cap) fail();
      for (let index = start + 1; index < end; index++) if (map[index] !== map[index - 1] + 1) fail();
      privateSlots[direction].push({ direction: direction.toUpperCase(), start: map[start], end: map[end - 1] + 1,
        hash: ZERO, ...attributes });
    };
    for (const [direction, message] of [['sent', sent], ['recv', recv]]) {
      const publicHeaders = new Set(['content-length', 'transfer-encoding', 'content-encoding', 'content-type', 'connection']);
      if (direction === 'sent') for (const name of ['host', 'x-16signals-nonce', 'accept-encoding', ...(!identity ? ['x-amz-target'] : [])]) publicHeaders.add(name);
      const wire = Uint32Array.from(transcripts[direction], (_, index) => index);
      for (const header of message.headers) if (!publicHeaders.has(header.name)) {
        for (let start = header.value.start; start < header.value.end; start += 2048) {
          const end = Math.min(start + 2048, header.value.end);
          for (const byte of transcripts[direction].subarray(start, end)) if (!(byte === 9 || (byte >= 32 && byte <= 126))) fail();
          hide(direction, wire, start, end, {}, 2048);
        }
      }
    }
    const walk = (node, publicValues, visit) => {
      if (publicValues.has(node)) return;
      if (node.type === 'object') for (const entry of node.entries) walk(entry.value, publicValues, visit);
      else if (node.type === 'array') for (const item of node.items) walk(item, publicValues, visit);
      else visit(node);
    };
    if (identity) {
      const shadow = ascii(recv.body.bytes); buffers.push(shadow);
      const text = decoder.decode(shadow);
      for (const match of text.matchAll(/<(Arn|UserId|Path|UserName|CreateDate|PasswordLastUsed|RequestId)>([^<]+)<\/\1>/dg)) {
        const [start, end] = match.indices[2];
        hide('recv', recv.body.wireIndices, start, end);
      }
    } else {
      const request = parseJsonStructure(sent.body.bytes).root;
      const attribute = child(request, 'LookupAttributes')?.items?.[0];
      walk(request, new Set([child(request, 'MaxResults'), child(attribute, 'AttributeKey')]), node => {
        hide('sent', sent.body.wireIndices, node.start, node.end, { layer: 'outer', kind: node.kind });
      });
      const outer = parseJsonStructure(recv.body.bytes).root, row = child(outer, 'Events')?.items?.[0];
      const embedded = child(row, 'CloudTrailEvent');
      if (embedded?.type !== 'string' || JSON.stringify(embedded.value) !== decoder.decode(recv.body.bytes.subarray(embedded.start, embedded.end))) fail();
      walk(outer, new Set([embedded, ...['EventName', 'EventSource', 'ReadOnly'].map(name => child(row, name))]), node => {
        hide('recv', recv.body.wireIndices, node.start, node.end, { layer: 'outer', kind: node.kind });
      });
      const bytes = encoder.encode(embedded.value); buffers.push(bytes);
      const event = parseJsonStructure(bytes).root;
      const publicValues = new Set(['eventVersion', 'eventName', 'eventSource', 'awsRegion', 'eventType', 'eventCategory',
        'managementEvent', 'readOnly'].map(name => child(event, name)));
      const response = child(event, 'responseElements');
      if (response?.type === 'null') publicValues.add(response);
      if (child(event, 'eventSource')?.value === 'ec2.amazonaws.com') publicValues.add(child(response, '_return'));
      publicValues.add(child(child(event, 'userIdentity'), 'type'));
      publicValues.add(child(child(event, 'requestParameters'), 'dryRun'));
      walk(event, publicValues, node => {
        const prefix = encoder.encode(JSON.stringify(decoder.decode(bytes.subarray(0, node.start))).slice(1, -1));
        const encoded = encoder.encode(JSON.stringify(decoder.decode(bytes.subarray(node.start, node.end))).slice(1, -1));
        try {
          const start = embedded.start + 1 + prefix.length;
          hide('recv', recv.body.wireIndices, start, start + encoded.length,
            { layer: 'event', kind: node.kind, decodedHash: ZERO, decodedLength: node.end - node.start });
        } finally { prefix.fill(0); encoded.fill(0); }
      });
    }
    const directions = {}, selections = {}, claims = [];
    for (const direction of ['sent', 'recv']) {
      const slots = privateSlots[direction].sort((a, b) => a.start - b.start), ranges = [];
      const bytes = new Uint8Array(transcripts[direction]); buffers.push(bytes);
      let cursor = 0;
      const add = (start, end, action) => ranges.push({ start, end, handler: { type: direction.toUpperCase(), part: 'BODY', action } });
      for (const slot of slots) {
        if (slot.start < cursor || slot.end > bytes.length) fail();
        if (slot.start > cursor) add(cursor, slot.start, { kind: 'REVEAL' });
        add(slot.start, slot.end, { kind: 'HASH', algorithm: 'SHA256' });
        bytes.fill(0, slot.start, slot.end); cursor = slot.end;
        if (slot.layer) claims.push({ ...slot });
      }
      if (cursor < bytes.length) add(cursor, bytes.length, { kind: 'REVEAL' });
      if (!ranges.length || ranges.length > 256 || !slots.length) fail();
      selections[direction] = ranges; directions[direction] = { bytes, privateRanges: slots };
    }
    if (identity) inspectAwsIdentityDirections(directions, meta); else inspectAwsEventDirections(directions, meta, claims);
    return { plan: { sentRangesWithHandlers: selections.sent, recvRangesWithHandlers: selections.recv }, privateSlots };
  } catch { fail(); }
  finally { for (const bytes of buffers) bytes.fill(0); }
}
