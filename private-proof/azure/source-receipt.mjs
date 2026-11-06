import { authenticatedSourceTranscript } from '../gcp/authenticated-transcript.mjs';
import { parseHttpStructure } from '../gcp/http-structure.mjs';
import { parseJsonStructure } from '../gcp/json-structure.mjs';
import { inspectTenantBody } from './tenant-structure.mjs';
import { inspectActivityBody } from './activity-structure.mjs';

const fail = () => { throw new Error('AZURE_PRIVATE_SOURCE_RECEIPT_INVALID'); };
const projection = 'claims,eventDataId,eventName,eventTimestamp,operationId,operationName,status,correlationId,resourceId,subscriptionId';
const subscriptionHole = '0'.repeat(36), correlationHole = '1'.repeat(36);
const hiddenResponseHeaders = new Set(['date', 'cache-control', 'connection', 'expires', 'pragma',
  'strict-transport-security', 'x-cache', 'x-content-type-options', 'x-ms-correlation-request-id',
  'x-ms-ratelimit-remaining-subscription-global-reads', 'x-ms-ratelimit-remaining-subscription-reads',
  'x-ms-request-id', 'x-ms-routing-request-id', 'x-msedge-ref', 'vary', 'x-ms-operation-identifier',
  'request-context', 'access-control-allow-origin', 'api-supported-versions', 'mise-correlation-id']);

function targetFor(step, cutoffMs) {
  if (step === 'tenant') return `/subscriptions/${subscriptionHole}?api-version=2022-12-01`;
  if (!Number.isSafeInteger(cutoffMs)) fail();
  const start = new Date(cutoffMs - 14 * 86400000).toISOString(), end = new Date(cutoffMs).toISOString();
  const url = new URL(`/subscriptions/${subscriptionHole}/providers/Microsoft.Insights/eventtypes/management/values`, 'https://management.azure.com');
  url.searchParams.set('api-version', '2015-04-01');
  url.searchParams.set('$filter', `eventTimestamp ge '${start}' and eventTimestamp le '${end}' and correlationId eq '${correlationHole}'`);
  url.searchParams.set('$select', projection);
  return url.pathname + url.search;
}

// Provisional string holes let the JSON grammar assign field roles without caller-supplied kinds.
function bodySlots(body, step) {
  const groups = [];
  for (const range of body.privateRanges) {
    const previous = groups.at(-1);
    if (previous?.end === range.start) { previous.end = range.end; previous.ranges.push(range); }
    else groups.push({ start: range.start, end: range.end, ranges: [range] });
  }
  const provisional = groups.map(group => ({ start: group.start, end: group.end, kind: 1, hash: '0'.repeat(64) }));
  const parsed = parseJsonStructure(body.bytes, provisional), claims = new Set();
  if (step === 'activity' && parsed.root.type === 'object') {
    const values = parsed.root.entries.find(entry => entry.key.value === 'value')?.value;
    if (values?.type === 'array') for (const row of values.items) {
      if (row.type !== 'object') continue;
      const value = row.entries.find(entry => entry.key.value === 'claims')?.value;
      if (Number.isInteger(value?.privateSlot)) claims.add(value.privateSlot);
    }
  }
  if (step === 'tenant' && parsed.root.type === 'object') for (const entry of parsed.root.entries) {
    if (Number.isInteger(entry.key.privateSlot) && entry.value.type === 'array' && entry.value.items.length === 1 &&
        Number.isInteger(entry.value.items[0].privateSlot)) claims.add(entry.value.items[0].privateSlot);
  }
  return groups.flatMap((group, index) => {
    const kind = claims.has(index) ? 6 : 1;
    if (kind === 1 && group.ranges.length !== 1) fail();
    return group.ranges.map(range => ({ start: range.start, end: range.end, hash: range.hash, kind }));
  });
}

/** Receipts must come from the trusted native service after live-attempt/replay checks.
 * This returns provisional proof obligations, never final work acceptance.
 */
export function inspectTenantReceipt(receipt, expected) { return inspect(receipt, expected, 'tenant'); }
export function inspectActivityReceipt(receipt, expected) { return inspect(receipt, expected, 'activity'); }

function inspect(receipt, expected, step) {
  try {
    const transcript = authenticatedSourceTranscript(receipt, expected,
      { host: 'management.azure.com', method: 'AZURE_WORK_PRIVATE', step });
    const sent = parseHttpStructure(transcript.sent, { kind: 'request' });
    const recv = parseHttpStructure(transcript.recv, { kind: 'response' });
    const used = new Set(), headerObligations = [];
    const use = (direction, range) => {
      const key = `${direction}:${range.index}`;
      if (used.has(key)) fail();
      used.add(key);
      return { direction, start: range.start, end: range.end, hash: range.hash, length: range.end - range.start };
    };
    const coverHeader = (message, direction, span) => {
      if (span.start >= span.end) fail();
      const ranges = message.privateRanges.filter(range => range.start >= span.start && range.end <= span.end);
      let cursor = span.start;
      for (const range of ranges) {
        if (range.start !== cursor || range.end - range.start > 2048) fail();
        headerObligations.push({ circuitId: 'header-v1', ...use(direction, range) });
        cursor = range.end;
      }
      if (cursor !== span.end) fail();
    };
    const fixed = new Map([
      ['host', 'management.azure.com'], ['accept', 'application/json'], ['accept-encoding', 'identity'],
      ['connection', 'close'], ['x-azure-proof-nonce', expected.nonceMac], ['x-azure-proof-step', step],
    ]);
    if (sent.startLine.method !== 'GET' || sent.body.bytes.length || sent.headers.length !== fixed.size + 1) fail();
    const requestHeaders = new Set();
    for (const header of sent.headers) {
      if (requestHeaders.has(header.name)) fail(); requestHeaders.add(header.name);
      if (fixed.has(header.name)) { if (header.value.text !== fixed.get(header.name)) fail(); }
      else if (header.name === 'authorization') coverHeader(sent, 'SENT', header.value);
      else fail();
    }
    if (!requestHeaders.has('authorization')) fail();

    const target = targetFor(step, expected.cutoffMs), actual = sent.startLine.target;
    if (actual.end - actual.start !== target.length) fail();
    const targetRanges = sent.privateRanges.filter(range => range.location === 'request-target');
    const holes = step === 'tenant' ? [subscriptionHole] : [subscriptionHole, correlationHole];
    if (targetRanges.length !== holes.length) fail();
    const requestRefs = [];
    const mask = new Uint8Array(target.length);
    for (const hole of holes) {
      const offset = target.indexOf(hole), start = actual.start + offset;
      const range = targetRanges.find(candidate => candidate.start === start && candidate.end === start + 36);
      if (offset < 0 || !range) fail();
      mask.fill(1, offset, offset + 36); requestRefs.push(use('SENT', range));
    }
    for (let i = 0; i < target.length; i++) if (!mask[i] && transcript.sent.bytes[actual.start + i] !== target.charCodeAt(i)) fail();

    if (recv.startLine.status !== 200) fail();
    if (recv.startLine.reason.text !== 'OK') coverHeader(recv, 'RECV', recv.startLine.reason);
    const responseHeaders = new Set();
    for (const header of recv.headers) {
      if (responseHeaders.has(header.name)) fail(); responseHeaders.add(header.name);
      if (header.name === 'content-type') {
        if (!/^application\/json(?:;[ \t]*charset=utf-8)?$/i.test(header.value.text ?? '')) fail();
      } else if (['content-length', 'transfer-encoding', 'content-encoding'].includes(header.name)) {
        if (header.value.text === undefined) fail();
      } else if (hiddenResponseHeaders.has(header.name)) coverHeader(recv, 'RECV', header.value);
      else fail();
    }
    if (!responseHeaders.has('content-type')) fail();
    const slots = bodySlots(recv.body, step);
    const body = step === 'tenant' ? inspectTenantBody(recv.body.bytes, slots) : inspectActivityBody(recv.body.bytes, slots);
    const wire = ref => {
      const range = recv.body.privateRanges.find(range => range.start === ref.start && range.end === ref.end && range.hash === ref.hash);
      if (!range || range.wireEnd - range.wireStart !== ref.end - ref.start) fail();
      const native = recv.privateRanges[range.sourceIndex];
      if (native.start !== range.wireStart || native.end !== range.wireEnd || native.hash !== ref.hash) fail();
      return { ...ref, start: native.start, end: native.end };
    };
    const mapRow = row => Object.fromEntries(Object.entries(row).map(([key, ref]) => {
      if (key !== 'claims') return [key, wire(ref)];
      const chunks = ref.chunks.map(wire), start = chunks[0].start, end = chunks.at(-1).end;
      // shortcut: claims must fit one contiguous wire span; upgrade bindings before accepting chunk-framing gaps.
      if (end - start !== ref.length || chunks.some((chunk, i) => i && chunks[i - 1].end !== chunk.start)) fail();
      return [key, { start, end, length: ref.length, chunks }];
    }));
    const atomObligations = body.atomObligations.map(ref => ({ circuitId: 'atom-v1', direction: 'RECV', ...wire(ref) }));
    const extraObligations = (body.extraObligations ?? []).map(extra => ({ name: extra.name,
      key: { direction: 'RECV', ...wire(extra.key) }, object: { direction: 'RECV', ...wire(extra.object) } }));
    const mapped = step === 'tenant' ? mapRow({ subscription: body.subscription, tenant: body.tenant, state: body.state })
      : { rows: body.rows.map(mapRow), requiresClaimsProofs: true, requiresCompleteCoverageProofs: true };
    for (const range of recv.privateRanges.filter(range => range.location === 'body')) use('RECV', range);
    if (used.size !== sent.privateRanges.length + recv.privateRanges.length) fail();
    const rows = step === 'tenant' ? [mapped] : mapped.rows;
    const requestUuidObligations = rows.flatMap(row => [
      { predicate: 'request-uuid', request: requestRefs[0], reference: { direction: 'RECV', ...row.subscription } },
      ...(step === 'activity' ? [{ predicate: 'request-uuid', request: requestRefs[1], reference: { direction: 'RECV', ...row.correlationId } }] : []),
    ]);
    return { body: mapped, headerObligations, requestUuidObligations, atomObligations, extraObligations };
  } catch { fail(); }
}
