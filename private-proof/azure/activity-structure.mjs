import { parseJsonStructure } from '../gcp/json-structure.mjs';

const fields = ['claims', 'eventDataId', 'eventName', 'eventTimestamp', 'operationId',
  'operationName', 'status', 'correlationId', 'resourceId', 'subscriptionId'];
const fail = () => { throw new Error('AZURE_PRIVATE_ACTIVITY_STRUCTURE_INVALID'); };

function object(node, keys, optional = []) {
  if (node?.type !== 'object' || node.privateSlot !== undefined || node.hasPrivateKeys ||
      node.entries.length < keys.length || node.entries.length > keys.length + optional.length) fail();
  const entries = new Map(node.entries.map(entry => [entry.key.value, entry.value]));
  if (!keys.every(key => entries.has(key)) || [...entries.keys()].some(key => !keys.includes(key) && !optional.includes(key))) fail();
  return entries;
}

// Shape inspection is provisional: the caller must authenticate every range and
// verify claims proofs plus an Activity relation proof for EVERY returned row.
export function inspectActivityBody(bytes, privateSlots) {
  let parsed;
  const logical = [], objects = new Map();
  try {
    if (!(bytes instanceof Uint8Array) || !Array.isArray(privateSlots) || privateSlots.length > 256) fail();
    let previousEnd = 0;
    for (const input of privateSlots) {
      const { start, end, kind, hash } = input ?? {};
      if (!Number.isInteger(start) || !Number.isInteger(end) || start < previousEnd || start >= end ||
          end > bytes.length || ![1, 6].includes(kind) || typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)) fail();
      const slot = { start, end, kind, hash };
      const previous = logical.at(-1);
      if (kind === 6) {
        if (end - start > 512) fail();
        if (previous?.kind === 6 && previous.end === start) {
          const chunks = objects.get(previous.start);
          if (chunks.at(-1).end - chunks.at(-1).start !== 512) fail();
          chunks.push(slot); previous.end = end;
        } else {
          // This hash is a syntax placeholder, never a native commitment to the merged object.
          logical.push({ start, end, kind, hash: '0'.repeat(64) }); objects.set(start, [slot]);
        }
      } else logical.push(slot);
      previousEnd = end;
    }
    parsed = parseJsonStructure(bytes, logical, true);
  }
  catch { return fail(); }
  const values = object(parsed.root, ['value']).get('value');
  if (values.type !== 'array' || !values.items.length || values.items.length > 8) fail();
  const used = new Set();
  const slot = (node, kind, maximum, exact) => {
    if (!Number.isInteger(node?.privateSlot) || node.kind !== kind) fail();
    const index = node.privateSlot, value = parsed.slots[index];
    const length = value.end - value.start;
    if (used.has(index) || length > maximum || (exact !== undefined && length !== exact)) fail();
    used.add(index);
    return { ...value, length };
  };
  const atomObligations = [];
  const atom = node => atomObligations.push(slot(node, 1, 512));
  const rows = values.items.map(row => {
    const entry = object(row, fields, ['id', 'submissionTimestamp', 'category']);
    const nested = name => {
      const values = object(entry.get(name), ['value'], ['localizedValue']);
      if (values.has('localizedValue')) atom(values.get('localizedValue'));
      return values.get('value');
    };
    const claims = slot(entry.get('claims'), 6, 2304);
    const result = {
      claims: { start: claims.start, end: claims.end, length: claims.length, chunks: objects.get(claims.start) },
      subscription: slot(entry.get('subscriptionId'), 1, 38, 38),
      eventId: slot(entry.get('eventDataId'), 1, 38, 38),
      operationId: slot(entry.get('operationId'), 1, 38, 38),
      correlationId: slot(entry.get('correlationId'), 1, 38, 38),
      event: slot(nested('eventName'), 1, 32),
      operation: slot(nested('operationName'), 1, 96),
      status: slot(nested('status'), 1, 32),
      timestamp: slot(entry.get('eventTimestamp'), 1, 32),
      resource: slot(entry.get('resourceId'), 1, 514),
    };
    for (const name of ['id', 'submissionTimestamp']) if (entry.has(name)) atom(entry.get(name));
    if (entry.has('category')) for (const node of object(entry.get('category'), ['value', 'localizedValue']).values()) atom(node);
    return result;
  });
  if (used.size !== parsed.slots.length) fail();
  return { rows, atomObligations, requiresClaimsProofs: true, requiresCompleteCoverageProofs: true };
}
