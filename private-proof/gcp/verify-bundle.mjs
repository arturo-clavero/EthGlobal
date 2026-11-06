import { authenticatedTranscript } from './authenticated-transcript.mjs';
import { inspectGcpSession } from './gcp-structure.mjs';
import { BATCHES, CATALOG_DIGEST, validatePolicy } from './policy.mjs';

const STEPS = Object.freeze(['identity', ...BATCHES.map(batch => batch.step)]);
const FIELD_COUNTS = Object.freeze({ 'header-v1': 33, 'atom-v1': 34, 'identity-scope-v1': 778,
  'query-scope-v1': 734, 'timestamps-v1': 200, 'headers-small-v1': 528, 'atoms-small-v1': 272 });
const HEX = /^[0-9a-f]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fail = () => { throw new Error('GCP_PRIVATE_BUNDLE_INVALID'); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) => record(value) && Reflect.ownKeys(value).length === keys.length &&
  keys.every(key => Object.hasOwn(value, key));
const slotKey = slot => `${slot.direction}:${slot.start}:${slot.end}:${slot.hash}`;

function bytes32(value) {
  if (typeof value === 'string') {
    if (!HEX.test(value)) fail();
    return Array.from({ length: 32 }, (_, index) => Number.parseInt(value.slice(index * 2, index * 2 + 2), 16));
  }
  if (!(Array.isArray(value) || value instanceof Uint8Array) || value.length !== 32) fail();
  const bytes = Array.from(value);
  if (bytes.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) fail();
  return bytes;
}

function fields(entry) {
  if (!exactKeys(entry, ['circuitId', 'proof', 'publicInputs']) || !Object.hasOwn(FIELD_COUNTS, entry.circuitId) ||
      typeof entry.proof !== 'string' || !entry.proof.length || entry.proof.length > 32768 || !BASE64.test(entry.proof) ||
      !Array.isArray(entry.publicInputs) || entry.publicInputs.length !== FIELD_COUNTS[entry.circuitId]) fail();
  return Array.from(entry.publicInputs, value => {
    if (typeof value !== 'string' || !/^(?:0x[0-9a-f]{1,64}|0|[1-9][0-9]{0,19})$/.test(value)) fail();
    const number = BigInt(value);
    if (number < 0n || number > 0xffffffffffffffffn) fail();
    return number;
  });
}

/** Bounded wire preflight for an endpoint before forwarding to the proof worker. */
export function validateBundleShape(bundle) {
  if (!exactKeys(bundle, ['kind', 'version', 'proofs', 'sessionIds']) || bundle.kind !== 'GCP_PRIVATE_RESULT' || bundle.version !== 1 ||
      !Array.isArray(bundle.sessionIds) || bundle.sessionIds.length !== STEPS.length ||
      bundle.sessionIds.some(id => typeof id !== 'string' || !UUID.test(id)) ||
      !Array.isArray(bundle.proofs) || !bundle.proofs.length || bundle.proofs.length > 128) fail();
  let length = JSON.stringify({ kind: bundle.kind, version: bundle.version, proofs: [], sessionIds: bundle.sessionIds }).length;
  for (let index = 0; index < bundle.proofs.length; index++) {
    fields(bundle.proofs[index]);
    // Each entry is already bounded; never stringify a potentially huge bundle.
    length += JSON.stringify(bundle.proofs[index]).length + Number(index > 0);
    if (length > 4 * 1024 * 1024) fail();
  }
}

function fieldHash(values) {
  if (values.length !== 32 || values.some(value => value < 0n || value > 255n)) fail();
  return values.map(value => value.toString(16).padStart(2, '0')).join('');
}

function slotFields(slot, limit) {
  if (!record(slot) || !['SENT', 'RECV'].includes(slot.direction) || !Number.isSafeInteger(slot.start) ||
      !Number.isSafeInteger(slot.end) || slot.start < 0 || slot.end <= slot.start || slot.end > 16384 ||
      slot.length !== slot.end - slot.start || slot.length > limit) fail();
  return bytes32(slot.hash);
}

function paddedSlots(slots, count, limit) {
  if (!Array.isArray(slots) || slots.length > count) fail();
  const hashes = [], lengths = [];
  for (let index = 0; index < count; index++) {
    const slot = slots[index];
    hashes.push(slot ? slotFields(slot, limit) : Array(32).fill(0));
    lengths.push(slot ? slot.length : 0);
  }
  return [hashes.flat(), lengths];
}

/**
 * Shared local/server ABI assembly. Inspections are provisional authenticated
 * structure results; this helper performs no cryptographic verification.
 * Wire proof ordering: identity scope; global small-header chunks, small-atom
 * chunks; then fixed session order of remaining large header/atom predicates
 * and each batch's query scope followed by timestamps. Chunks preserve fixed
 * session order and each session's native SENT/RECV offset order.
 * Diagnostic IDs and slots are local only and never added to completion wire.
 */
export function assembleBundleExpectations(inspections, scopeHash, policy, nonceMac) {
  const checkedPolicy = validatePolicy(policy), scope = bytes32(scopeHash);
  if (!/^[A-Za-z0-9_-]{43}$/.test(nonceMac ?? '') || !Array.isArray(inspections) || inspections.length !== STEPS.length) fail();
  const nonce = Array.from(nonceMac, character => character.charCodeAt(0));
  const expected = [], coverage = [];
  for (let index = 0; index < STEPS.length; index++) {
    const inspection = inspections[index];
    if (!record(inspection) || inspection.step !== STEPS[index] || inspection.catalogDigest !== CATALOG_DIGEST ||
        !Array.isArray(inspection.obligations) || inspection.obligations.length > 512) fail();
    const obligations = new Map();
    for (const slot of inspection.obligations) {
      slotFields(slot, 16384);
      if (obligations.has(slotKey(slot)) || !Object.hasOwn(FIELD_COUNTS, slot.predicate)) fail();
      obligations.set(slotKey(slot), slot);
    }
    coverage.push({ obligations, used: new Set() });
  }
  const reference = (index, slot, predicate, consume = true) => {
    const { obligations, used } = coverage[index], key = slotKey(slot), original = obligations.get(key);
    if (!original || original.predicate !== predicate || original.length !== slot.length || original.kind !== slot.kind ||
        (consume && used.has(key))) fail();
    if (consume) used.add(key);
  };
  const add = (index, circuitId, publicInputs, slots, suffix = '') => {
    if (publicInputs.length !== FIELD_COUNTS[circuitId]) fail();
    expected.push({ id: `${STEPS[index]}:${circuitId}${suffix}`, circuitId, publicInputs,
      slots: slots.map(slot => ({ step: STEPS[index], direction: slot.direction, start: slot.start,
        end: slot.end, hash: slot.hash, length: slot.length })) });
  };

  const identity = inspections[0].identity;
  if (!record(identity) || !Array.isArray(identity.rows) || !identity.rows.length || identity.rows.length > 10 ||
      inspections[0].query !== undefined || inspections[0].groups !== undefined) fail();
  reference(0, identity.authuserSlot, 'identity-scope-v1');
  if (identity.authuserSlot.length !== 1) fail();
  const emailSlots = [], idSlots = [], validRows = [];
  for (const row of identity.rows) {
    if (!record(row) || typeof row.rowValid !== 'boolean' || row.emailSlot?.kind !== 1 || row.idSlot?.kind !== 1) fail();
    reference(0, row.emailSlot, 'atom-v1', false);
    reference(0, row.idSlot, 'atom-v1', false);
    emailSlots.push(row.emailSlot); idSlots.push(row.idSlot); validRows.push(Number(row.rowValid));
  }
  const [rowEmailHashes, rowEmailLengths] = paddedSlots(emailSlots, 10, 256);
  const [rowIdHashes, rowIdLengths] = paddedSlots(idSlots, 10, 66);
  while (validRows.length < 10) validRows.push(0);
  add(0, 'identity-scope-v1', [...nonce, ...scope, ...slotFields(identity.authuserSlot, 1), identity.rows.length,
    ...rowEmailHashes, ...rowIdHashes, ...rowEmailLengths, ...rowIdLengths, ...validRows],
  [identity.authuserSlot, ...identity.rows.flatMap(row => [row.emailSlot, row.idSlot])]);

  for (const [predicate, circuitId, capacity] of [['header-v1', 'headers-small-v1', 16], ['atom-v1', 'atoms-small-v1', 8]]) {
    const small = inspections.flatMap((inspection, index) => inspection.obligations
      .filter(slot => slot.predicate === predicate && slot.length <= 64).map(slot => ({ index, slot })));
    for (let start = 0; start < small.length; start += capacity) {
      const chunk = small.slice(start, start + capacity), slots = chunk.map(item => item.slot);
      for (const item of chunk) reference(item.index, item.slot, predicate);
      const [hashes, lengths] = paddedSlots(slots, capacity, 64), publicInputs = [...hashes, ...lengths];
      if (predicate === 'atom-v1') {
        const kinds = slots.map(slot => {
          if (!Number.isInteger(slot.kind) || slot.kind < 1 || slot.kind > 5) fail();
          return slot.kind;
        });
        while (kinds.length < capacity) kinds.push(0);
        publicInputs.push(...kinds);
      }
      if (publicInputs.length !== FIELD_COUNTS[circuitId]) fail();
      expected.push({ id: `bundle:${circuitId}:${start / capacity}`, circuitId, publicInputs,
        slots: chunk.map(({ index, slot }) => ({ step: STEPS[index], direction: slot.direction,
          start: slot.start, end: slot.end, hash: slot.hash, length: slot.length })) });
    }
  }

  for (let index = 0; index < inspections.length; index++) {
    const inspection = inspections[index];
    for (const slot of inspection.obligations) {
      if (slot.predicate !== 'header-v1' && slot.predicate !== 'atom-v1') continue;
      if (slot.length <= 64) continue;
      reference(index, slot, slot.predicate);
      const values = [...slotFields(slot, slot.predicate === 'header-v1' ? 2048 : 512), slot.length];
      if (slot.predicate === 'atom-v1') {
        if (!Number.isInteger(slot.kind) || slot.kind < 1 || slot.kind > 5) fail();
        values.push(slot.kind);
      }
      add(index, slot.predicate, values, [slot], `:${slot.direction}:${slot.start}:${slot.end}`);
    }
    if (index === 0) continue;
    const query = inspection.query, batch = BATCHES[index - 1], groups = inspection.groups;
    if (!record(query) || inspection.identity !== undefined || !Array.isArray(groups) || groups.length !== batch.groupIds.length ||
        !Array.isArray(query.project) || query.project.length !== groups.length * 2 ||
        !Array.isArray(query.email) || query.email.length !== groups.length ||
        query.authuserSlot?.length !== 1 || query.apiKeySlot?.length !== 39) fail();
    const querySlots = [query.authuserSlot, query.apiKeySlot, ...query.project, ...query.email];
    for (const slot of querySlots) reference(index, slot, 'query-scope-v1');
    const [projectHashes, projectLengths] = paddedSlots(query.project, 12, 30);
    const [emailHashes, emailLengths] = paddedSlots(query.email, 6, 254);
    add(index, 'query-scope-v1', [...nonce, ...scope, groups.length, ...projectHashes, ...projectLengths,
      ...emailHashes, ...emailLengths, ...slotFields(query.authuserSlot, 1), ...slotFields(query.apiKeySlot, 39)], querySlots);
    const timestamps = [];
    for (let group = 0; group < groups.length; group++) {
      const value = groups[group];
      if (!record(value) || value.id !== batch.groupIds[group] || !['observed', 'empty', 'denied'].includes(value.status)) fail();
      if (value.status === 'observed') {
        if (value.timestampSlot?.kind !== 1) fail();
        reference(index, value.timestampSlot, 'timestamps-v1');
        timestamps.push(value.timestampSlot);
      } else {
        if (value.timestampSlot !== undefined) fail();
        timestamps.push(null);
      }
    }
    const [timestampHashes, timestampLengths] = paddedSlots(timestamps, 6, 48);
    add(index, 'timestamps-v1', [...timestampHashes, ...timestampLengths, checkedPolicy.cutoff, checkedPolicy.windowDays], timestamps.filter(Boolean));
  }
  for (const { obligations, used } of coverage) if (used.size !== obligations.size) fail();
  return expected;
}

/**
 * `sessions`, `policy` and `runtime` come from trusted application state. The
 * caller authenticates native receipts and enforces attempt expiry/replay before
 * entry. Runtime must use application-pinned artifacts, never request artifacts
 * or verification keys. Only the completion bundle is untrusted request data.
 */
export async function verifyBundle({ sessions, policy, bundle, runtime }) {
  try {
    const checkedPolicy = validatePolicy(policy);
    if (!Array.isArray(sessions) || sessions.length !== STEPS.length || !runtime || typeof runtime.verify !== 'function') fail();
    validateBundleShape(bundle);
    const seenSessions = new Set(), native = new Map(), directions = [], first = sessions[0]?.expected;
    for (let index = 0; index < sessions.length; index++) {
      const session = sessions[index], expected = session?.expected;
      if (!record(expected) || expected.step !== STEPS[index] || expected.nonceMac !== first.nonceMac ||
          expected.proofId !== first.proofId || expected.pluginSha256 !== first.pluginSha256 ||
          bundle.sessionIds[index] !== expected.sessionId || seenSessions.has(expected.sessionId)) fail();
      seenSessions.add(expected.sessionId);
      const transcript = authenticatedTranscript(session.receipt, expected);
      directions.push(transcript);
      for (const [name, value] of Object.entries(transcript)) {
        for (const slot of value.privateRanges) {
          if (native.has(slot.hash)) fail();
          native.set(slot.hash, { ...slot, direction: name.toUpperCase(), step: expected.step,
            length: slot.end - slot.start, sessionIndex: index });
        }
      }
    }
    const parsed = bundle.proofs.map(fields);
    if (bundle.proofs[0].circuitId !== 'identity-scope-v1') fail();
    const scopeHash = fieldHash(parsed[0].slice(43, 75));
    const claims = sessions.map(() => []), claimed = new Set();
    const claim = (hashFields, length, kind) => {
      const hash = fieldHash(hashFields), slot = native.get(hash);
      if (!slot || BigInt(slot.length) !== length || claimed.has(hash) || kind < 1n || kind > 5n) fail();
      claimed.add(hash);
      claims[slot.sessionIndex].push({ direction: slot.direction, start: slot.start, end: slot.end, hash, kind: Number(kind) });
    };
    for (let index = 0; index < bundle.proofs.length; index++) {
      const entry = bundle.proofs[index], values = parsed[index];
      if (entry.circuitId === 'atom-v1') claim(values.slice(0, 32), values[32], values[33]);
      else if (entry.circuitId === 'atoms-small-v1') {
        for (let slot = 0; slot < 8; slot++) {
          const hash = values.slice(slot * 32, slot * 32 + 32), length = values[256 + slot], kind = values[264 + slot];
          if (length === 0n) { if (kind !== 0n || hash.some(byte => byte !== 0n)) fail(); }
          else claim(hash, length, kind);
        }
      }
      else if (entry.circuitId === 'timestamps-v1') {
        for (let slot = 0; slot < 6; slot++) {
          const hash = values.slice(slot * 32, slot * 32 + 32), length = values[192 + slot];
          if (length === 0n) { if (hash.some(byte => byte !== 0n)) fail(); }
          else claim(hash, length, 1n);
        }
      }
    }
    const inspections = directions.map((value, index) => inspectGcpSession(value, sessions[index].expected, checkedPolicy, claims[index]));
    const expectations = assembleBundleExpectations(inspections, scopeHash, checkedPolicy, first.nonceMac);
    if (expectations.length !== bundle.proofs.length) fail();
    for (let index = 0; index < expectations.length; index++) {
      const entry = bundle.proofs[index], expectation = expectations[index];
      if (entry.circuitId !== expectation.circuitId || !await runtime.verify(entry, expectation.publicInputs)) fail();
    }
    return { catalogDigest: CATALOG_DIGEST, policy: checkedPolicy,
      groups: inspections.slice(1).flatMap(inspection => inspection.groups.map(group => ({ id: group.id, status: group.status }))) };
  } catch { throw new Error('GCP_PRIVATE_BUNDLE_INVALID'); }
}
