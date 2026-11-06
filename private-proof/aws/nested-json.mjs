import { JSON_STRUCTURE_LIMITS, parseJsonStructure } from '../gcp/json-structure.mjs';

const decoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const fail = () => { throw new Error('AWS_PRIVATE_STRUCTURE_INVALID'); };
const child = (node, name) => node?.entries?.find(entry => entry.key.value === name)?.value;

function publicKeys(node) {
  if (node.type === 'object') {
    if (node.hasPrivateKeys) fail();
    for (const { value } of node.entries) publicKeys(value);
  } else if (node.type === 'array') {
    for (const item of node.items) publicKeys(item);
  }
}

/**
 * Parse one exact-event lookup BODY with zero-filled private intervals. HTTP framing,
 * native authentication, every atom proof and AWS claim predicates remain REQUIRED.
 * Outer slots: {layer:'outer',start,end,kind,hash}; event slots add decodedHash and
 * decodedLength, which are provisional public outputs of the escaped-atom circuit.
 * Offsets are bytes, never JS string indices. No private key or container is allowed.
 */
export function parseCloudTrailStructure(bytes, slots = []) {
  try {
    if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > JSON_STRUCTURE_LIMITS.bytes ||
        !Array.isArray(slots) || slots.length > JSON_STRUCTURE_LIMITS.slots) fail();
    const source = new Uint8Array(bytes), shadow = new Uint8Array(bytes);
    const outerSlots = [], eventSlots = [];
    let previousEnd = 0;
    for (const slot of slots) {
      if (!slot || typeof slot !== 'object' || !['outer', 'event'].includes(slot.layer)) fail();
      const keys = ['layer', 'start', 'end', 'kind', 'hash', ...(slot.layer === 'event' ? ['decodedHash', 'decodedLength'] : [])];
      if (Reflect.ownKeys(slot).length !== keys.length || keys.some(key => !Object.hasOwn(slot, key))) fail();
      const { start, end, kind, hash } = slot;
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < previousEnd || start >= end ||
          end > source.length || end - start > 512 || !Number.isInteger(kind) || kind < 1 || kind > 5 || !digest(hash)) fail();
      for (let i = start; i < end; i++) if (source[i] !== 0) fail();
      previousEnd = end;
      if (slot.layer === 'outer') outerSlots.push({ start, end, kind, hash });
      else {
        if (!digest(slot.decodedHash) || !Number.isSafeInteger(slot.decodedLength) ||
            slot.decodedLength < 1 || slot.decodedLength > 512) fail();
        eventSlots.push({ start, end, kind, hash, decodedHash: slot.decodedHash, decodedLength: slot.decodedLength });
        // Only the escaped-atom proof justifies treating a hole as non-closing string content.
        shadow.fill(32, start, end);
      }
    }
    const outer = parseJsonStructure(shadow, outerSlots);
    publicKeys(outer.root);
    if (outer.root.type !== 'object' || outer.root.entries.length !== 1 || outer.root.entries[0].key.value !== 'Events') fail();
    const events = child(outer.root, 'Events');
    if (events?.type !== 'array' || events.items.length !== 1 || events.items[0].type !== 'object') fail();
    const embedded = child(events.items[0], 'CloudTrailEvent');
    if (embedded?.type !== 'string' || embedded.privateSlot !== undefined) fail();
    const start = embedded.start + 1, end = embedded.end - 1;
    if (eventSlots.some(slot => slot.start < start || slot.end > end)) fail();

    const pieces = [], decodedSlots = [], eventAtoms = [];
    let at = start, length = 0;
    const append = piece => {
      length += piece.length;
      if (length > JSON_STRUCTURE_LIMITS.bytes) fail();
      pieces.push(piece);
    };
    const publicFragment = until => {
      const fragment = decoder.decode(source.subarray(at, until));
      const value = JSON.parse(`"${fragment}"`);
      const decoded = encoder.encode(value);
      // Reject alternate outer escapes and lossy lone-surrogate UTF-8 conversion.
      if (JSON.stringify(value).slice(1, -1) !== fragment || decoder.decode(decoded) !== value) fail();
      append(decoded);
    };
    for (const slot of eventSlots) {
      publicFragment(slot.start);
      const decoded = { start: length, end: length + slot.decodedLength, kind: slot.kind, hash: slot.decodedHash };
      decodedSlots.push(decoded);
      eventAtoms.push({ encoded: { start: slot.start, end: slot.end, hash: slot.hash }, decoded });
      append(new Uint8Array(slot.decodedLength));
      at = slot.end;
    }
    publicFragment(end);
    const body = new Uint8Array(length);
    let offset = 0;
    for (const piece of pieces) { body.set(piece, offset); offset += piece.length; }
    const inner = parseJsonStructure(body, decodedSlots);
    publicKeys(inner.root);
    if (inner.root.type !== 'object') fail();
    // Never expose the shadow placeholder text as if it were an authenticated value.
    delete embedded.value;
    embedded.type = 'embedded-json';
    return { outer: outer.root, event: inner.root, outerAtoms: outer.slots, eventAtoms,
      requiresAtomicProofs: slots.length > 0 };
  } catch {
    throw new Error('AWS_PRIVATE_STRUCTURE_INVALID');
  }
}
