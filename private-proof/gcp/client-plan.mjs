import { parseHttpStructure } from './http-structure.mjs';
import { parseJsonStructure } from './json-structure.mjs';
import { inspectGcpSession, parseMultipartStructure } from './gcp-structure.mjs';
import { BATCHES, localBatchBody, validatePolicy } from './policy.mjs';
import { assembleBundleExpectations } from './verify-bundle.mjs';

const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const ZERO_HASH = '0'.repeat(64);
const STEPS = ['identity', ...BATCHES.map(batch => batch.step)];
const fail = () => { throw new Error('GCP_PRIVATE_CLIENT_INVALID'); };
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const hashBytes = hash => Array.from({ length: 32 }, (_, index) => Number.parseInt(hash.slice(index * 2, index * 2 + 2), 16));
const same = (a, b) => a.length === b.length && a.every((byte, index) => byte === b[index]);
const zeroes = size => Array(size).fill(0);
const pad = (bytes, size) => { if (bytes.length > size) fail(); return [...bytes, ...zeroes(size - bytes.length)]; };
const asciiShadow = bytes => Uint8Array.from(bytes, byte => byte > 127 ? 63 : byte);
const slotKey = slot => `${slot.direction}:${slot.start}:${slot.end}`;
const child = (node, name) => node?.entries?.find(entry => entry.key.value === name)?.value;

function localHttp(bytes, kind, wireIndices = Uint32Array.from(bytes, (_, index) => index)) {
  if (!(bytes instanceof Uint8Array) || bytes.length > 16384) fail();
  // The shadow locates ASCII framing only. Witness bytes ALWAYS come from the
  // original transcript. Final redacted parsing rejects exposed non-ASCII bytes.
  const shadow = asciiShadow(bytes);
  let message;
  try {
    message = parseHttpStructure({ bytes: shadow, privateRanges: [] }, { kind });
    return { ...message, wireIndices, body: { ...message.body,
      bytes: Uint8Array.from(message.body.wireIndices, index => bytes[index]),
      wireIndices: Uint32Array.from(message.body.wireIndices, index => wireIndices[index]) } };
  } finally { shadow.fill(0); message?.body.bytes.fill(0); }
}

function selectedIdentity(message, target) {
  const match = /^\/ListAccounts\?json=standard&authuser=([0-9])$/.exec(target);
  if (!match) fail();
  const account = Number(match[1]), root = parseJsonStructure(message.body.bytes).root;
  const row = root.items?.[1]?.items?.[account];
  const email = row?.items?.[3], id = row?.items?.[10];
  if (root.items?.[0]?.value !== 'gaia.l.a.r' || row?.items?.[0]?.value !== 'gaia.l.a' ||
      row.items[9]?.raw !== '1' || row.items[15]?.raw !== '1' ||
      !(row.items[14]?.raw === '0' || row.items[14]?.value === null) ||
      email?.type !== 'string' || id?.type !== 'string' || !/^[0-9]{1,64}$/.test(id.value)) fail();
  for (const node of [email, id]) {
    if (decoder.decode(message.body.bytes.subarray(node.start, node.end)) !== `"${node.value}"`) fail();
  }
  return { account, email: email.value, id: id.value };
}

/** Local-only planner: no transcript or private value is returned to the webpage. */
export function planGcpSession(meta, transcripts, { projectId, policy, email }) {
  try { return plan(meta, transcripts, { projectId, policy: validatePolicy(policy), email }); }
  catch { fail(); }
}

function plan(meta, transcripts, { projectId, policy, email }, batchHeaders = true) {
  if (!meta || !STEPS.includes(meta.step) || !/^[A-Za-z0-9_-]{43}$/.test(meta.nonceMac ?? '')) fail();
  const identity = meta.step === 'identity';
  const buffers = [];
  const http = (bytes, kind, map) => { const value = localHttp(bytes, kind, map); buffers.push(value.body.bytes); return value; };
  try {
    const sent = http(transcripts.sent, 'request'), recv = http(transcripts.recv, 'response');
    const selected = identity ? selectedIdentity(recv, sent.startLine.target.text) : undefined;
    const privateSlots = { sent: [], recv: [] };
    const hide = (direction, map, start, end, kind, cap = 512) => {
      if (!Number.isInteger(start) || start < 0 || end <= start || end > map.length || end - start > cap) fail();
      for (let index = start + 1; index < end; index++) if (map[index] !== map[index - 1] + 1) fail();
      privateSlots[direction].push({ direction: direction.toUpperCase(), start: map[start], end: map[end - 1] + 1,
        hash: ZERO_HASH, ...(kind === undefined ? {} : { kind }) });
    };
    const header = (message, direction, value) => {
      // Medium values fit the existing small-header batches; large values stay cheaper individually.
      const capacity = batchHeaders && value.end - value.start <= 256 ? 64 : 2048;
      for (let start = value.start; start < value.end; start += capacity) {
        const end = Math.min(start + capacity, value.end);
        const raw = transcripts[direction];
        for (let index = start; index < end; index++) {
          const byte = raw[message.wireIndices[index]];
          if (!(byte === 9 || (byte >= 32 && byte <= 126))) fail();
        }
        hide(direction, message.wireIndices, start, end, undefined, 2048);
      }
    };
    const transport = (message, direction, outer) => {
      const publicHeaders = new Set(['content-length', 'transfer-encoding', 'content-encoding', 'content-type']);
      if (outer) {
        publicHeaders.add('connection');
        if (direction === 'sent') for (const name of ['host', 'x-16signals-nonce', 'accept', 'accept-encoding', 'origin']) publicHeaders.add(name);
      }
      for (const value of message.headers) {
        if (direction === 'sent' && !identity && value.name === 'x-goog-authuser') {
          hide(direction, message.wireIndices, value.value.start, value.value.end, undefined, 1);
        } else if (!publicHeaders.has(value.name)) header(message, direction, value.value);
      }
      const reason = message.startLine.reason;
      if (reason && reason.text !== (message.startLine.status === 200 ? 'OK' : message.startLine.status === 403 ? 'Forbidden' : undefined)) {
        header(message, direction, reason);
      }
    };
    const json = (body, mode, status) => {
      const root = parseJsonStructure(body.bytes).root, publicNodes = new Set(), timestamps = new Set();
      const keys = (node, names) => {
        for (const entry of node?.entries ?? []) if (names.includes(entry.key.value)) publicNodes.add(entry.key);
      };
      if (mode === 'identity') {
        publicNodes.add(root.items?.[0]);
        for (const row of root.items?.[1]?.items ?? []) for (const index of [0, 9, 14, 15]) publicNodes.add(row.items?.[index]);
      } else if (status === 200) {
        keys(root, ['entries']);
        for (const entry of child(root, 'entries')?.items ?? []) {
          keys(entry, ['timestamp']); timestamps.add(child(entry, 'timestamp'));
        }
      } else if (status === 403) {
        keys(root, ['error']);
        const error = child(root, 'error');
        keys(error, ['code', 'status', 'message', 'details', 'errors']);
        publicNodes.add(child(error, 'code')); publicNodes.add(child(error, 'status'));
      } else fail();
      const walk = node => {
        if (node.type === 'array') for (const item of node.items) walk(item);
        else if (node.type === 'object') for (const entry of node.entries) { walk(entry.key); walk(entry.value); }
        else if (!publicNodes.has(node) && ['string', 'number'].includes(node.type)) {
          hide('recv', body.wireIndices, node.start, node.end, node.kind, timestamps.has(node) ? 48 : 512);
        }
      };
      walk(root);
    };
    transport(sent, 'sent', true); transport(recv, 'recv', true);
    const target = sent.startLine.target;
    hide('sent', sent.wireIndices, target.end - (identity ? 1 : 39), target.end, undefined, identity ? 1 : 39);
    if (identity) {
      // This also validates the project and selected email against the existing query contract.
      localBatchBody('groups:0', policy, projectId, selected.email);
      json(recv.body, 'identity');
    } else {
      const expected = localBatchBody(meta.step, policy, projectId, email);
      if (!same(sent.body.bytes, encoder.encode(expected.text))) fail();
      for (const range of expected.privateRanges) hide('sent', sent.body.wireIndices, range.start, range.end, undefined, 254);
      const contentType = recv.headers.find(header => header.name === 'content-type')?.value.text;
      const boundary = /boundary=(?:"([A-Za-z0-9_-]{1,70})"|([A-Za-z0-9_-]{1,70}))$/i.exec(contentType ?? '');
      if (!boundary) fail();
      const shadow = asciiShadow(recv.body.bytes); buffers.push(shadow);
      for (const part of parseMultipartStructure({ ...recv.body, bytes: shadow }, boundary[1] ?? boundary[2])) {
        buffers.push(part.direction.bytes);
        const bytes = Uint8Array.from(part.wireIndices, index => transcripts.recv[index]);
        buffers.push(bytes);
        const inner = http(bytes, 'response', part.wireIndices);
        transport(inner, 'recv', false); json(inner.body, 'group', inner.startLine.status);
      }
    }
    const directions = {}, selections = {}, claims = [];
    for (const direction of ['sent', 'recv']) {
      const slots = privateSlots[direction].sort((a, b) => a.start - b.start);
      const bytes = new Uint8Array(transcripts[direction]), ranges = [];
      buffers.push(bytes);
      let cursor = 0;
      const add = (start, end, action) => ranges.push({ start, end,
        handler: { type: direction.toUpperCase(), part: 'BODY', action } });
      for (const slot of slots) {
        if (slot.start < cursor || slot.end > bytes.length) fail();
        if (slot.start > cursor) add(cursor, slot.start, { kind: 'REVEAL' });
        add(slot.start, slot.end, { kind: 'HASH', algorithm: 'SHA256' });
        bytes.fill(0, slot.start, slot.end); cursor = slot.end;
        if (slot.kind !== undefined) claims.push({ ...slot });
      }
      if (cursor < bytes.length) add(cursor, bytes.length, { kind: 'REVEAL' });
      // Preserve previously supported transcripts when extra commitments exhaust the native range budget.
      if (ranges.length > 256 && batchHeaders) return plan(meta, transcripts, { projectId, policy, email }, false);
      if (!ranges.length || ranges.length > 256) fail();
      selections[direction] = ranges;
      directions[direction] = { bytes, privateRanges: slots };
    }
    // All semantic roles are re-derived by the same verifier inspector.
    const inspection = inspectGcpSession(directions, meta, policy, claims);
    return { plan: { sentRangesWithHandlers: selections.sent, recvRangesWithHandlers: selections.recv },
      privateSlots, inspection, selected };
  } finally { for (const bytes of buffers) bytes.fill(0); }
}

async function authenticatedPlan(witness, options, crypto) {
  const planned = planGcpSession(witness, witness, options), directions = {}, claims = [], openings = new Map();
  const buffers = [];
  try {
    for (const direction of ['sent', 'recv']) {
      const expected = planned.plan[`${direction}RangesWithHandlers`];
      const actual = witness.selections?.[direction];
      if (!Array.isArray(actual) || actual.length !== expected.length || actual.some((range, index) => {
        const target = expected[index];
        return range.start !== target.start || range.end !== target.end || range.handler?.type !== target.handler.type ||
          range.handler.part !== target.handler.part || range.handler.action?.kind !== target.handler.action.kind ||
          range.handler.action?.algorithm !== target.handler.action.algorithm;
      })) fail();
      const slots = planned.privateSlots[direction], candidates = witness.openings?.[direction];
      if (!Array.isArray(candidates) || candidates.length !== slots.length) fail();
      const bytes = new Uint8Array(witness[direction]), authenticated = [];
      buffers.push(bytes);
      const used = new Set();
      for (const slot of slots) {
        const matches = candidates.filter(opening => opening.start === slot.start && opening.end === slot.end);
        if (matches.length !== 1 || used.has(matches[0])) fail();
        const opening = matches[0]; used.add(opening);
        if (!(opening.hash instanceof Uint8Array) || opening.hash.length !== 32 ||
            !(opening.blinder instanceof Uint8Array) || opening.blinder.length !== 16) fail();
        const preimage = new Uint8Array(slot.end - slot.start + 16);
        preimage.set(bytes.subarray(slot.start, slot.end)); preimage.set(opening.blinder, preimage.length - 16);
        let digest;
        try { digest = new Uint8Array(await crypto.subtle.digest('SHA-256', preimage)); }
        finally { preimage.fill(0); }
        if (!same(digest, opening.hash)) fail();
        const accepted = { ...slot, hash: hex(digest) };
        openings.set(slotKey(accepted), opening); authenticated.push(accepted);
        if (slot.kind !== undefined) claims.push(accepted);
        bytes.fill(0, slot.start, slot.end);
      }
      directions[direction] = { bytes, privateRanges: authenticated };
    }
    return { witness, openings, inspection: inspectGcpSession(directions, witness, options.policy, claims), selected: planned.selected };
  } finally { for (const bytes of buffers) bytes.fill(0); }
}

/** Counts only: safe to report for local cost planning, never private values. */
export function summarizeGcpPlan(inspections) {
  const circuits = { 'header-v1': 0, 'atom-v1': 0, 'identity-scope-v1': 0, 'query-scope-v1': 0, 'timestamps-v1': 0 };
  const lengths = { header: {}, atom: {} };
  for (const inspection of inspections) {
    if (inspection.identity) circuits['identity-scope-v1']++;
    if (inspection.query) { circuits['query-scope-v1']++; circuits['timestamps-v1']++; }
    for (const slot of inspection.obligations) {
      if (!['header-v1', 'atom-v1'].includes(slot.predicate)) continue;
      circuits[slot.predicate]++;
      const bucket = [64, 128, 256, 512, 1024, 2048].find(size => slot.length <= size);
      const histogram = lengths[slot.predicate === 'header-v1' ? 'header' : 'atom'];
      histogram[bucket] = (histogram[bucket] ?? 0) + 1;
    }
  }
  const smallHeaders = lengths.header[64] ?? 0, smallAtoms = lengths.atom[64] ?? 0;
  circuits['header-v1'] -= smallHeaders; circuits['atom-v1'] -= smallAtoms;
  circuits['headers-small-v1'] = Math.ceil(smallHeaders / 16);
  circuits['atoms-small-v1'] = Math.ceil(smallAtoms / 8);
  return { circuits, lengths, proofCount: Object.values(circuits).reduce((sum, count) => sum + count, 0) };
}

function erase(value) {
  if (Array.isArray(value)) { for (const item of value) erase(item); value.fill(0); }
  else if (value instanceof Uint8Array) value.fill(0);
  else if (value && typeof value === 'object') for (const item of Object.values(value)) erase(item);
}

/** Pinned offscreen module only. `proveCircuit` must terminate its worker on abort. */
export function createGcpPrivateClient({ projectId, policy, proveCircuit, crypto = globalThis.crypto }) {
  policy = Object.freeze(validatePolicy(policy));
  if (typeof proveCircuit !== 'function' || !crypto?.subtle || !crypto?.getRandomValues) fail();
  // Validate local project without retaining a fabricated identity.
  localBatchBody('groups:0', policy, projectId, 'validation@example.invalid');
  let email, consumed = false;
  const options = () => ({ projectId, policy, email });
  const clear = () => { consumed = true; email = undefined; projectId = undefined; };
  return {
    clear,
    getRevealPlan(meta, transcripts) { if (consumed) fail(); return planGcpSession(meta, transcripts, options()).plan; },
    identityEmail(witness) {
      if (consumed || email !== undefined || witness.step !== 'identity') fail();
      // Provisional local projection; final identity-scope proof authenticates it.
      email = planGcpSession(witness, witness, options()).selected.email;
      return email;
    },
    async prove(witnesses, signal) {
      if (consumed) fail(); consumed = true;
      const salt = new Uint8Array(32); crypto.getRandomValues(salt);
      let common;
      try {
        if (!signal || signal.aborted || !Array.isArray(witnesses) || witnesses.length !== 6) fail();
        const nonce = witnesses[0].nonceMac, proofId = witnesses[0].proofId;
        const ids = new Set(), prepared = [];
        for (let index = 0; index < STEPS.length; index++) {
          const witness = witnesses[index];
          if (signal.aborted || witness.step !== STEPS[index] || witness.nonceMac !== nonce || witness.proofId !== proofId ||
              !witness.sessionId || ids.has(witness.sessionId) || witness.serverName !== (index ? 'logging.clients6.google.com' : 'accounts.google.com')) fail();
          ids.add(witness.sessionId);
          const item = await authenticatedPlan(witness, options(), crypto);
          if (index === 0) { if (email !== item.selected.email) fail(); }
          else {
            const { authuserSlot, apiKeySlot } = item.inspection.query;
            if (witness.sent[authuserSlot.start] !== prepared[0].selected.account + 48 ||
                !/^AIza[A-Za-z0-9_-]{35}$/.test(decoder.decode(witness.sent.subarray(apiKeySlot.start, apiKeySlot.end)))) fail();
          }
          prepared.push(item);
        }
        const selected = prepared[0].selected;
        common = { nonce: Array.from(encoder.encode(nonce)), salt: Array.from(salt), account: selected.account,
          project: pad(encoder.encode(projectId), 30), project_len: projectId.length,
          email: pad(encoder.encode(selected.email), 254), email_len: selected.email.length,
          id: pad(encoder.encode(selected.id), 64), id_len: selected.id.length };
        const encoded = Uint8Array.from([...encoder.encode('gcp-private-scope-v1'), ...common.nonce, ...salt, selected.account,
          common.project_len, ...common.project, common.email_len, ...common.email, common.id_len, ...common.id]);
        try { common.scope_hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', encoded))); }
        finally { encoded.fill(0); }
        const inspections = prepared.map(item => item.inspection);
        const expectations = assembleBundleExpectations(inspections, common.scope_hash, policy, nonce);
        if (!expectations.length || expectations.length > 128) fail();
        const proofs = [];
        for (const expected of expectations) {
          if (signal.aborted) fail();
          const inputs = circuitInputs(expected, prepared, common, policy);
          try {
            const entry = await proveCircuit(expected.circuitId, inputs, signal);
            if (signal.aborted || entry?.circuitId !== expected.circuitId || !Array.isArray(entry.publicInputs) ||
                entry.publicInputs.length !== expected.publicInputs.length ||
                entry.publicInputs.some((field, index) => BigInt(field) !== BigInt(expected.publicInputs[index]))) fail();
            proofs.push(entry);
          } finally { erase(inputs); }
        }
        return { proofs };
      } catch { fail(); }
      finally { salt.fill(0); erase(common); clear(); }
    },
  };
}

function circuitInputs(expected, prepared, common, policy) {
  if (['headers-small-v1', 'atoms-small-v1'].includes(expected.circuitId)) {
    const count = expected.circuitId === 'headers-small-v1' ? 16 : 8;
    if (!expected.slots.length || expected.slots.length > count) fail();
    const inputs = { hashes: [], lengths: [], preimages: [], ...(count === 8 ? { kinds: [] } : {}) };
    for (let index = 0; index < count; index++) {
      const slot = expected.slots[index];
      if (!slot) {
        inputs.hashes.push(zeroes(32)); inputs.lengths.push(0); inputs.preimages.push(zeroes(80));
        inputs.kinds?.push(0); continue;
      }
      const item = prepared[STEPS.indexOf(slot.step)], opened = item?.openings.get(slotKey(slot));
      const obligation = item?.inspection.obligations.find(value => slotKey(value) === slotKey(slot));
      if (!opened || hex(opened.hash) !== slot.hash || slot.length > 64 || !obligation) fail();
      inputs.hashes.push(hashBytes(slot.hash)); inputs.lengths.push(slot.length);
      inputs.preimages.push(pad([...item.witness[slot.direction.toLowerCase()].subarray(slot.start, slot.end), ...opened.blinder], 80));
      if (inputs.kinds) inputs.kinds.push(obligation.kind);
    }
    return inputs;
  }
  const step = STEPS.find(step => expected.id.startsWith(`${step}:`));
  const item = prepared[STEPS.indexOf(step)];
  if (!item) fail();
  const { inspection, witness, openings } = item;
  const opening = slot => {
    const result = openings.get(slotKey(slot));
    if (!result || hex(result.hash) !== slot.hash) fail();
    return result;
  };
  const blinder = slot => Array.from(opening(slot).blinder);
  const preimage = (slot, size) => pad([...witness[slot.direction.toLowerCase()].subarray(slot.start, slot.end), ...blinder(slot)], size);
  const hashes = (slots, count) => Array.from({ length: count }, (_, index) => slots[index] ? hashBytes(slots[index].hash) : zeroes(32));
  const lengths = (slots, count) => Array.from({ length: count }, (_, index) => slots[index]?.length ?? 0);
  const blinders = (slots, count) => Array.from({ length: count }, (_, index) => slots[index] ? blinder(slots[index]) : zeroes(16));
  if (expected.circuitId === 'header-v1' || expected.circuitId === 'atom-v1') {
    const slot = inspection.obligations.find(slot => expected.id === `${inspection.step}:${expected.circuitId}:${slot.direction}:${slot.start}:${slot.end}`);
    if (!slot) fail();
    return { commitment: hashBytes(slot.hash), length: slot.length, preimage: preimage(slot, expected.circuitId === 'header-v1' ? 2064 : 528) };
  }
  if (expected.circuitId === 'timestamps-v1') {
    const slots = inspection.groups.map(group => group.timestampSlot);
    return { hashes: hashes(slots, 6), lengths: lengths(slots, 6), cutoff: policy.cutoff, window: policy.windowDays,
      preimages: Array.from({ length: 6 }, (_, index) => slots[index] ? preimage(slots[index], 64) : zeroes(64)) };
  }
  const scope = structuredClone(common);
  if (expected.circuitId === 'identity-scope-v1') {
    const { rows, authuserSlot } = inspection.identity, selected = rows[common.account];
    return { ...scope, authuser_hash: hashBytes(authuserSlot.hash), row_count: rows.length,
      row_email_hashes: hashes(rows.map(row => row.emailSlot), 10), row_id_hashes: hashes(rows.map(row => row.idSlot), 10),
      row_email_lengths: lengths(rows.map(row => row.emailSlot), 10), row_id_lengths: lengths(rows.map(row => row.idSlot), 10),
      row_valid: Array.from({ length: 10 }, (_, index) => rows[index]?.rowValid ?? false),
      authuser_blinder: blinder(authuserSlot), email_blinder: blinder(selected.emailSlot), id_blinder: blinder(selected.idSlot) };
  }
  if (expected.circuitId !== 'query-scope-v1') fail();
  const { project, email, authuserSlot, apiKeySlot } = inspection.query;
  return { ...scope, group_count: inspection.groups.length, project_hashes: hashes(project, 12), project_lengths: lengths(project, 12),
    email_hashes: hashes(email, 6), email_lengths: lengths(email, 6), authuser_hash: hashBytes(authuserSlot.hash), api_key_hash: hashBytes(apiKeySlot.hash),
    project_blinders: blinders(project, 12), email_blinders: blinders(email, 6), authuser_blinder: blinder(authuserSlot),
    api_key: Array.from(witness.sent.subarray(apiKeySlot.start, apiKeySlot.end)), api_key_blinder: blinder(apiKeySlot) };
}
