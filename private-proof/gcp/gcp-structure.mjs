import { parseHttpStructure } from './http-structure.mjs';
import { parseJsonStructure } from './json-structure.mjs';
import { BATCHES, CATALOG_DIGEST, matchBatchBody, validatePolicy } from './policy.mjs';

const decoder = new TextDecoder('utf-8', { fatal: true });
const jsonType = /^application\/json(?:;[ \t]*charset=UTF-8)?$/i;
const framing = new Set(['content-length', 'transfer-encoding', 'content-encoding']);
const fail = () => { throw new Error('GCP_PRIVATE_STRUCTURE_INVALID'); };
const key = slot => `${slot.direction}:${slot.start}:${slot.end}:${slot.hash}`;
const isPrivate = node => node?.privateSlot !== undefined;
const publicValue = (node, value) => !isPrivate(node) && node?.value === value;
const exactNumber = (node, raw) => node?.type === 'number' && !isPrivate(node) && node.raw === raw;

/**
 * Inspect authenticated redacted HTTP, deriving roles from public syntax alone.
 * This is PROVISIONAL: the caller MUST verify every returned obligation and the
 * identity/query scope relation before accepting a category. atomicClaims only
 * propose atom kinds; neither their kinds nor any caller role labels are trusted.
 * Public structure reveals sizes, row/metadata cardinality, null/boolean metadata
 * and selected account flags. Private strings/numbers never appear in the output.
 * This strict profile intentionally rejects unknown public header values, private
 * semantic keys, compression, and private atoms crossing chunk framing.
 */
export function inspectGcpSession(directions, meta, policy, atomicClaims = []) {
  validatePolicy(policy);
  if (!meta || !/^[A-Za-z0-9_-]{43}$/.test(meta.nonceMac ?? '') ||
      !(meta.step === 'identity' || BATCHES.some(batch => batch.step === meta.step)) ||
      !Array.isArray(atomicClaims) || atomicClaims.length > 512) fail();
  const sent = parseHttpStructure(directions?.sent, { kind: 'request' });
  const recv = parseHttpStructure(directions?.recv, { kind: 'response' });
  const native = new Map();
  for (const [direction, message] of [['SENT', sent], ['RECV', recv]]) {
    for (const range of message.privateRanges) {
      const slot = { direction, start: range.start, end: range.end, hash: range.hash, length: range.end - range.start };
      native.set(key(slot), slot);
    }
  }
  const claims = new Map(), usedClaims = new Set(), obligations = new Map();
  for (const claim of atomicClaims) {
    if (!claim || !['SENT', 'RECV'].includes(claim.direction) || !Number.isInteger(claim.kind) ||
        claim.kind < 1 || claim.kind > 5 || !native.has(key(claim)) || claims.has(key(claim))) fail();
    claims.set(key(claim), claim.kind);
  }
  const resolve = (direction, start, end, hash) => {
    const slot = native.get(key({ direction, start, end, hash }));
    if (!slot) fail();
    return slot;
  };
  const oblige = (slot, predicate, kind) => {
    if (obligations.has(key(slot))) fail();
    if ((predicate === 'header-v1' && slot.length > 2048) || (predicate === 'atom-v1' && slot.length > 512)) fail();
    const output = { ...slot, ...(kind === undefined ? {} : { kind }) };
    obligations.set(key(slot), { ...output, predicate });
    return output;
  };
  const wireSlot = (range, direction = 'RECV') => resolve(direction, range.wireStart, range.wireEnd, range.hash);
  const cover = (message, start, end, direction, predicate) => {
    let cursor = start;
    const slots = message.privateRanges.filter(range => range.start >= start && range.end <= end);
    for (const range of slots) {
      if (range.start !== cursor) fail();
      oblige(resolve(direction, range.start, range.end, range.hash), predicate);
      cursor = range.end;
    }
    if (cursor !== end) fail();
  };
  const headers = (message, direction, expected, required = [], special = new Map()) => {
    const map = new Map();
    for (const header of message.headers) {
      if (map.has(header.name) && (direction !== 'RECV' || framing.has(header.name) || header.name === 'connection' ||
          expected.has(header.name) || required.includes(header.name) || special.has(header.name))) fail();
      map.set(header.name, header);
      if (framing.has(header.name)) continue; // Public and validated by HTTP parser.
      if (special.has(header.name)) {
        special.get(header.name)(header);
      } else if (expected.has(header.name)) {
        const rule = expected.get(header.name), value = header.value.text;
        if (value === undefined || (typeof rule === 'string' ? value !== rule : !rule.test(value))) fail();
      } else {
        // Unknown response metadata may repeat, but every occurrence's entire
        // non-OWS value must be private and every gap needs a no-CRLF proof.
        cover(message, header.value.start, header.value.end, direction, 'header-v1');
      }
    }
    for (const name of required) if (!map.has(name)) fail();
    return map;
  };
  const privateTarget = (prefix, length, predicate) => {
    const target = sent.startLine.target;
    const start = target.start + prefix.length;
    if (target.end !== start + length || decoder.decode(directions.sent.bytes.subarray(target.start, start)) !== prefix) fail();
    const candidates = sent.privateRanges.filter(range => range.location === 'request-target');
    if (candidates.length !== 1 || candidates[0].start !== start || candidates[0].end !== target.end) fail();
    return oblige(resolve('SENT', start, target.end, candidates[0].hash), predicate);
  };
  const reason = (message, direction, offsetMap) => {
    const value = message.startLine.reason;
    const expected = message.startLine.status === 200 ? 'OK' : message.startLine.status === 403 ? 'Forbidden' : undefined;
    if (value.text === expected && expected !== undefined) return;
    if (!offsetMap) cover(message, value.start, value.end, direction, 'header-v1');
    else {
      let cursor = value.start;
      for (const range of message.privateRanges.filter(range => range.location === 'reason-phrase')) {
        if (range.start !== cursor) fail();
        oblige(resolve(direction, offsetMap[range.start], offsetMap[range.end - 1] + 1, range.hash), 'header-v1');
        cursor = range.end;
      }
      if (cursor !== value.end) fail();
    }
  };
  const json = body => {
    const slots = body.privateRanges.map(range => {
      const slot = wireSlot(range), kind = claims.get(key(slot));
      if (kind === undefined || usedClaims.has(key(slot))) fail();
      usedClaims.add(key(slot));
      return { start: range.start, end: range.end, hash: range.hash, kind };
    });
    const parsed = parseJsonStructure(body.bytes, slots);
    return { root: parsed.root, slot: node => {
      if (!isPrivate(node)) fail();
      return { ...wireSlot(body.privateRanges[node.privateSlot]), kind: node.kind };
    } };
  };
  const atom = (node, parsed, predicate = 'atom-v1', kind) => {
    if (!isPrivate(node) || (kind !== undefined && node.kind !== kind)) fail();
    return oblige(parsed.slot(node), predicate, node.kind);
  };
  const metadata = (node, parsed) => {
    if (isPrivate(node)) { atom(node, parsed); return; }
    if (node.type === 'array') { for (const child of node.items) metadata(child, parsed); return; }
    if (node.type === 'object') {
      for (const entry of node.entries) { metadata(entry.key, parsed); metadata(entry.value, parsed); }
      return;
    }
    if (node.type !== 'null' && node.type !== 'boolean') fail();
  };
  const semanticObject = (node, allowed) => {
    if (node?.type !== 'object' || node.hasPrivateKeys || node.entries.some(entry => !allowed.includes(entry.key.value))) fail();
    return new Map(node.entries.map(entry => [entry.key.value, entry.value]));
  };

  if (sent.startLine.method !== 'POST' || recv.startLine.status !== 200) fail();
  const identity = meta.step === 'identity';
  const requestExpected = new Map([
    ['host', identity ? 'accounts.google.com' : 'logging.clients6.google.com'],
    ['connection', 'close'], ['x-16signals-nonce', meta.nonceMac],
    ['content-type', identity ? 'application/x-www-form-urlencoded' : 'multipart/mixed; boundary=gcp_groups_v1'],
    ['accept', identity ? 'application/json' : 'multipart/mixed'],
    ['accept-encoding', 'identity'], ['origin', identity ? 'https://www.google.com' : 'https://console.cloud.google.com'],
  ]);
  let authuserSlot;
  const special = new Map();
  if (!identity) special.set('x-goog-authuser', header => {
    const ranges = sent.privateRanges.filter(range => range.headerIndex === sent.headers.indexOf(header));
    if (ranges.length !== 1 || ranges[0].start !== header.value.start || ranges[0].end !== header.value.end ||
        header.value.end - header.value.start !== 1) fail();
    authuserSlot = oblige(resolve('SENT', ranges[0].start, ranges[0].end, ranges[0].hash), 'query-scope-v1');
  });
  headers(sent, 'SENT', requestExpected,
    ['host', 'connection', 'x-16signals-nonce', 'content-type', ...(!identity ? ['x-goog-authuser'] : [])], special);
  const responseHeaders = headers(recv, 'RECV', new Map([
    ['content-type', identity ? jsonType : /^multipart\/mixed;[ \t]*boundary=(?:[A-Za-z0-9_-]{1,70}|"[A-Za-z0-9_-]{1,70}")$/i],
    ['connection', 'close'],
  ]), ['content-type']);
  reason(recv, 'RECV');
  const output = { step: meta.step, catalogDigest: CATALOG_DIGEST };
  if (identity) {
    authuserSlot = privateTarget('/ListAccounts?json=standard&authuser=', 1, 'identity-scope-v1');
    if (sent.body.bytes.length !== 1 || sent.body.bytes[0] !== 32 || sent.body.privateRanges.length) fail();
    const parsed = json(recv.body), root = parsed.root;
    if (root.type !== 'array' || root.items.length !== 2 || !publicValue(root.items[0], 'gaia.l.a.r') ||
        root.items[1].type !== 'array' || !root.items[1].items.length || root.items[1].items.length > 10) fail();
    const rows = root.items[1].items.map(row => {
      if (row.type !== 'array' || row.items.length < 16 || !publicValue(row.items[0], 'gaia.l.a')) fail();
      const emailSlot = atom(row.items[3], parsed, 'atom-v1', 1);
      const idSlot = atom(row.items[10], parsed, 'atom-v1', 1);
      if (emailSlot.length > 256 || idSlot.length > 66) fail();
      for (const index of [9, 14, 15]) {
        const flag = row.items[index];
        if (isPrivate(flag) || !(exactNumber(flag, '0') || exactNumber(flag, '1') || publicValue(flag, null))) fail();
      }
      for (let index = 1; index < row.items.length; index++) {
        if (![3, 9, 10, 14, 15].includes(index)) metadata(row.items[index], parsed);
      }
      return { emailSlot, idSlot, rowValid: exactNumber(row.items[9], '1') && exactNumber(row.items[15], '1') &&
        (exactNumber(row.items[14], '0') || publicValue(row.items[14], null)) };
    });
    output.identity = { authuserSlot, rows };
  } else {
    const apiKeySlot = privateTarget('/batch?key=', 39, 'query-scope-v1');
    const scope = matchBatchBody(sent.body, meta.step, policy);
    output.query = { authuserSlot, apiKeySlot,
      project: scope.project.map(range => oblige(wireSlot(range, 'SENT'), 'query-scope-v1')),
      email: scope.email.map(range => oblige(wireSlot(range, 'SENT'), 'query-scope-v1')) };
    const boundary = responseHeaders.get('content-type').value.text.match(/boundary=(?:"([^"]+)"|([^; ]+))$/i);
    const batch = BATCHES.find(batch => batch.step === meta.step), found = new Map();
    for (const part of parseMultipartStructure(recv.body, boundary[1] ?? boundary[2])) {
      if (!batch.groupIds.includes(part.id) || found.has(part.id)) fail();
      const inner = parseHttpStructure(part.direction, { kind: 'response' });
      if (![200, 403].includes(inner.startLine.status)) fail();
      // Translate nested wire coordinates before assigning any proof obligation.
      const map = part.wireIndices;
      const mappedMessage = { ...inner, privateRanges: inner.privateRanges.map(range => ({ ...range,
        start: map[range.start], end: map[range.end - 1] + 1 })),
        headers: inner.headers.map(header => ({ ...header, value: { ...header.value,
          start: map[header.value.start], end: header.value.end > header.value.start ? map[header.value.end - 1] + 1 : map[header.value.start] } })) };
      headers(mappedMessage, 'RECV', new Map([['content-type', jsonType]]), ['content-type']);
      reason(inner, 'RECV', map);
      const body = { ...inner.body, privateRanges: inner.body.privateRanges.map(range => ({ ...range,
        wireStart: map[range.wireStart], wireEnd: map[range.wireEnd - 1] + 1 })) };
      const parsed = json(body);
      let result;
      if (inner.startLine.status === 200) {
        const root = semanticObject(parsed.root, ['entries']);
        const entries = root.get('entries');
        if (entries === undefined) result = { id: part.id, status: 'empty' };
        else {
          if (entries.type !== 'array' || entries.items.length > 1) fail();
          if (!entries.items.length) result = { id: part.id, status: 'empty' };
          else {
            const entry = semanticObject(entries.items[0], ['timestamp']);
            if (entry.size !== 1) fail();
            result = { id: part.id, status: 'observed', timestampSlot: atom(entry.get('timestamp'), parsed, 'timestamps-v1', 1) };
            if (result.timestampSlot.length > 48) fail();
          }
        }
      } else {
        const root = semanticObject(parsed.root, ['error']);
        if (root.size !== 1) fail();
        const error = semanticObject(root.get('error'), ['code', 'status', 'message', 'details', 'errors']);
        if (!exactNumber(error.get('code'), '403') || !publicValue(error.get('status'), 'PERMISSION_DENIED')) fail();
        for (const [name, node] of error) if (!['code', 'status'].includes(name)) metadata(node, parsed);
        result = { id: part.id, status: 'denied' };
      }
      found.set(part.id, result);
    }
    if (found.size !== batch.groupIds.length) fail();
    output.groups = batch.groupIds.map(id => found.get(id));
  }
  if (obligations.size !== native.size || usedClaims.size !== claims.size) fail();
  output.obligations = [...obligations.values()].sort((a, b) => (a.direction === b.direction ? a.start - b.start : a.direction === 'SENT' ? -1 : 1));
  return output;
}

/** Strict MIME envelope; slots cannot overlap delimiters/headers. The HTTP and
 * JSON private-byte predicates establish that hidden values cannot inject MIME.
 * Every submessage byte retains its original native transcript coordinate. */
export function parseMultipartStructure(body, boundary) {
  if (!/^[A-Za-z0-9_-]{1,70}$/.test(boundary ?? '') || !(body?.bytes instanceof Uint8Array) ||
      body.bytes.length > 16384 || !Array.isArray(body.privateRanges) ||
      !(body.wireIndices instanceof Uint32Array) || body.wireIndices.length !== body.bytes.length) fail();
  // Offsets are byte coordinates, so this entrypoint also requires the parser's
  // ASCII/zero representation. A local planner may supply an ASCII shadow only
  // for locating structure, then recover real bytes through wireIndices.
  if (body.bytes.some(byte => byte > 127)) fail();
  const text = decoder.decode(body.bytes), marker = `--${boundary}`;
  let cursor = text.startsWith('\r\n') ? 2 : 0;
  const parts = [];
  while (true) {
    if (text.slice(cursor, cursor + marker.length) !== marker) fail();
    cursor += marker.length;
    if (text.slice(cursor, cursor + 4) === '--\r\n') {
      if (cursor + 4 !== text.length) fail();
      return parts;
    }
    if (text.slice(cursor, cursor + 2) !== '\r\n' || parts.length >= 6) fail();
    cursor += 2;
    const headerEnd = text.indexOf('\r\n\r\n', cursor);
    if (headerEnd < 0) fail();
    const map = new Map();
    for (const line of text.slice(cursor, headerEnd).split('\r\n')) {
      const match = /^([A-Za-z-]+):[ \t]*([^\x00-\x1f\x7f]*)$/.exec(line);
      if (!match || map.has(match[1].toLowerCase())) fail();
      map.set(match[1].toLowerCase(), match[2].trim());
    }
    if (map.size !== 2 || map.get('content-type') !== 'application/http') fail();
    const id = /^<response-(g[0-9]+)>$/.exec(map.get('content-id') ?? '')?.[1];
    if (!id) fail();
    const start = headerEnd + 4, end = text.indexOf(`\r\n${marker}`, start);
    if (end < start) fail();
    const ranges = [];
    for (const range of body.privateRanges) {
      if (range.end <= start || range.start >= end) continue;
      if (range.start < start || range.end > end) fail();
      ranges.push({ start: range.start - start, end: range.end - start, hash: range.hash });
    }
    parts.push({ id, direction: { bytes: body.bytes.slice(start, end), privateRanges: ranges },
      wireIndices: body.wireIndices.slice(start, end) });
    cursor = end + 2;
  }
}
