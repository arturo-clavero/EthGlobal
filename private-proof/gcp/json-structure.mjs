/** Bounded JSON structure parsing over authenticated public bytes and opaque atoms.
 *
 * This module verifies neither TLS authentication nor ZK proofs. EVERY returned
 * privateSlot remains provisional until the caller verifies its exact authenticated
 * range/hash and a ZK proof of its COMPLETE bytes and selected internal semantics.
 * A private string includes both quotes. Opaque objects require explicit opt-in
 * and a complete object proof; an atomic proof is insufficient. A private object key is
 * unknown: callers cannot assume it differs from any public key without a proof.
 * Objects retain entry lists; this module never constructs objects from JSON keys.
 */

export const JSON_STRUCTURE_LIMITS = Object.freeze({ bytes: 16384, depth: 32, nodes: 512, slots: 256 });
const TYPES = [undefined, 'string', 'number', 'boolean', 'boolean', 'null', 'object'];
const decoder = new TextDecoder('utf-8', { fatal: true });
const whitespace = byte => byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d;
const delimiter = byte => whitespace(byte) || byte === 0x2c || byte === 0x5d || byte === 0x7d;

export class JsonStructureError extends Error {
  constructor(code, offset) {
    super(`JSON structure ${code} at byte ${offset}`);
    this.name = 'JsonStructureError';
    this.code = code;
    this.offset = offset;
  }
}

/**
 * @param {Uint8Array} bytes Full JSON body; every private position must be zero.
 * @param {{start:number,end:number,kind:number,hash:string}[]} privateSlots
 *   Sorted, nonoverlapping byte spans; kinds: 1 string, 2 number, 3 true,
 *   4 false, 5 null, 6 opaque object (only with explicit trusted opt-in).
 *   Hashes are lowercase SHA256 hex. Arrays cannot be opaque.
 * @param {boolean} allowPrivateObjects Trusted caller policy, never a client flag.
 * @returns {{root:object,slots:object[],requiresAtomicProofs:boolean}}
 *   Nodes have type/start/end. Public atoms additionally have kind/value;
 *   numbers retain raw text because JSON.parse may round them. Private atoms
 *   have kind/privateSlot and NEVER a value. Arrays have items; objects have
 *   entries:[{key,value}] and hasPrivateKeys. All offsets are body byte offsets.
 */
export function parseJsonStructure(bytes, privateSlots = [], allowPrivateObjects = false) {
  const fail = (code, offset = 0) => { throw new JsonStructureError(code, offset); };
  if (!(bytes instanceof Uint8Array)) fail('INPUT_TYPE');
  if (typeof allowPrivateObjects !== 'boolean') fail('OBJECT_POLICY');
  if (!bytes.length || bytes.length > JSON_STRUCTURE_LIMITS.bytes) fail('INPUT_LIMIT');
  if (!Array.isArray(privateSlots)) fail('SLOTS_TYPE');
  if (privateSlots.length > JSON_STRUCTURE_LIMITS.slots) fail('SLOT_LIMIT');
  // Copy even Buffer input; Buffer.slice() would leave a mutable shared view.
  const source = new Uint8Array(bytes);
  const slots = [];
  let previousEnd = 0;
  for (const slot of privateSlots) {
    if (!slot || typeof slot !== 'object') fail('SLOT_METADATA');
    const { start, end, kind, hash } = slot;
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || start >= end || end > source.length) {
      fail('SLOT_RANGE');
    }
    if (start < previousEnd) fail('SLOT_ORDER', start);
    if (!Number.isInteger(kind) || kind < 1 || kind > (allowPrivateObjects ? 6 : 5)) fail('SLOT_KIND', start);
    const length = end - start;
    if (((kind === 1 || kind === 6) && length < 2) || ((kind === 3 || kind === 5) && length !== 4) ||
        (kind === 4 && length !== 5)) fail('SLOT_LENGTH', start);
    if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)) fail('SLOT_HASH', start);
    for (let at = start; at < end; at++) if (source[at] !== 0) fail('PRIVATE_NOT_ZERO', at);
    slots.push({ start, end, kind, hash });
    previousEnd = end;
  }

  let position = 0;
  let slotIndex = 0;
  let nodeCount = 0;
  const skipWhitespace = () => { while (whitespace(source[position])) position++; };
  const assertPublic = () => {
    if (slotIndex < slots.length && position >= slots[slotIndex].start) fail('SLOT_BOUNDARY', position);
  };
  const decodeAtom = (start, end) => {
    let raw;
    try { raw = decoder.decode(source.subarray(start, end)); }
    catch { fail('INVALID_UTF8', start); }
    try { return { raw, value: JSON.parse(raw) }; }
    catch { fail('INVALID_JSON', start); }
  };

  function parseValue(depth) {
    skipWhitespace();
    if (position >= source.length) fail('TRUNCATED', position);
    if (++nodeCount > JSON_STRUCTURE_LIMITS.nodes) fail('NODE_LIMIT', position);
    const start = position;
    const slot = slots[slotIndex];
    if (slot && slot.start === position) {
      position = slot.end;
      return { type: TYPES[slot.kind], kind: slot.kind, start, end: position, privateSlot: slotIndex++ };
    }
    assertPublic();
    const first = source[position];
    if (first === 0x5b || first === 0x7b) {
      if (depth >= JSON_STRUCTURE_LIMITS.depth) fail('DEPTH_LIMIT', start);
      const object = first === 0x7b;
      const closing = object ? 0x7d : 0x5d;
      const node = object
        ? { type: 'object', start, end: 0, entries: [], hasPrivateKeys: false }
        : { type: 'array', start, end: 0, items: [] };
      const publicKeys = new Set();
      position++;
      skipWhitespace();
      if (source[position] === closing) {
        node.end = ++position;
        return node;
      }
      while (true) {
        if (object) {
          skipWhitespace();
          const keySlot = slots[slotIndex];
          if (source[position] !== 0x22 && !(keySlot?.start === position && keySlot.kind === 1)) {
            fail('EXPECTED_STRING_KEY', position);
          }
          const key = parseValue(depth + 1);
          if (key.privateSlot !== undefined) node.hasPrivateKeys = true;
          else {
            if (publicKeys.has(key.value)) fail('DUPLICATE_KEY', key.start);
            publicKeys.add(key.value);
          }
          skipWhitespace();
          assertPublic();
          if (source[position] !== 0x3a) fail('EXPECTED_COLON', position);
          position++;
          node.entries.push({ key, value: parseValue(depth + 1) });
        } else node.items.push(parseValue(depth + 1));
        skipWhitespace();
        assertPublic();
        if (source[position] === closing) {
          node.end = ++position;
          return node;
        }
        if (source[position] !== 0x2c) fail('EXPECTED_COMMA_OR_END', position);
        position++;
      }
    }

    if (first === 0x22) {
      position++;
      let escaped = false;
      while (position < source.length) {
        assertPublic();
        const byte = source[position++];
        if (escaped) escaped = false;
        else if (byte === 0x5c) escaped = true;
        else if (byte === 0x22) {
          const { value } = decodeAtom(start, position);
          return { type: 'string', kind: 1, start, end: position, value };
        }
      }
      fail('TRUNCATED', position);
    }

    if (!(first === 0x2d || (first >= 0x30 && first <= 0x39) || first === 0x74 || first === 0x66 || first === 0x6e)) {
      fail('EXPECTED_VALUE', position);
    }
    while (position < source.length && !delimiter(source[position])) {
      assertPublic();
      position++;
    }
    const { raw, value } = decodeAtom(start, position);
    const kind = value === null ? 5 : value === true ? 3 : value === false ? 4 : 2;
    const node = { type: TYPES[kind], kind, start, end: position, value };
    if (kind === 2) node.raw = raw;
    return node;
  }

  const root = parseValue(0);
  skipWhitespace();
  if (position !== source.length) fail('TRAILING_BYTES', position);
  if (slotIndex !== slots.length) fail('UNUSED_SLOT', position);
  return { root, slots, requiresAtomicProofs: slots.length > 0,
    ...(slots.some(slot => slot.kind === 6) ? { requiresObjectProofs: true } : {}) };
}
