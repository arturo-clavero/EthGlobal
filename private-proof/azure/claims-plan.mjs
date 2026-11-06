const encoder = new TextEncoder();
const actorKey = 'http://schemas.microsoft.com/identity/claims/objectidentifier';
const tenantKey = 'http://schemas.microsoft.com/identity/claims/tenantid';
const fail = () => { throw new Error('AZURE_PRIVATE_CLAIMS_PLAN_INVALID'); };
const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const lower = c => c >= 65 && c <= 90 ? c + 32 : c;
const limbs = bytes => {
  const parts = [0n, 0n];
  for (let i = 0; i < Math.min(bytes.length, 62); i++) parts[Math.floor(i / 31)] = parts[Math.floor(i / 31)] * 256n + BigInt(bytes[i]);
  return parts;
};
const keyParts = [limbs(encoder.encode(actorKey)), limbs(encoder.encode(tenantKey))];
const stringStart = () => [0, 0, 0, 128, 191];

// This witness builder mirrors the circuit's private carry; only a verified proof authenticates it.
function stringByte(s, c) {
  if (s[2]) {
    if (c < s[3] || c > s[4]) fail();
    s[2]--; s[3] = 128; s[4] = 191;
  } else if (s[1]) {
    if (!(c >= 48 && c <= 57 || lower(c) >= 97 && lower(c) <= 102)) fail();
    s[1]--;
  } else if (s[0]) {
    if (![34, 92, 47, 98, 102, 110, 114, 116, 117].includes(c)) fail();
    if (c === 117) s[1] = 4;
    s[0] = 0;
  } else if (c === 34) return true;
  else if (c === 92) s[0] = 1;
  else {
    if (c < 32) fail();
    if (c >= 128) {
      if (c < 194 || c > 244) fail();
      s[2] = c <= 223 ? 1 : c <= 239 ? 2 : 3;
      s[3] = c === 224 ? 160 : c === 240 ? 144 : 128;
      s[4] = c === 237 ? 159 : c === 244 ? 143 : 191;
    }
  }
  return false;
}

function scan(s, bytes, identities) {
  for (const c of bytes) {
    if (s.grammar === 2) {
      if (c < 32 || c >= 127 || c === 92) fail();
      if (c === 34) {
        s.selected = s.keyLength === 61 && same(s.parts, keyParts[0]) ? 1 : s.keyLength === 53 && same(s.parts, keyParts[1]) ? 2 : 0;
        if (s.selected) {
          if (s.seen[s.selected - 1]) fail();
          s.seen[s.selected - 1] = 1;
        }
        s.grammar = 3;
      } else {
        if (s.keyLength < 62) {
          const at = Math.floor(s.keyLength / 31); s.parts[at] = s.parts[at] * 256n + BigInt(c);
        }
        s.keyLength++;
      }
    } else if (s.grammar === 5) {
      if (stringByte(s.string, c)) {
        if (s.selected && (s.position !== 36 || !same(s.parts, identities[s.selected - 1]))) fail();
        s.grammar = 6;
      } else {
        if (s.selected) {
          if (s.position >= 36) fail();
          const at = Math.floor(s.position / 31); s.parts[at] = s.parts[at] * 256n + BigInt(lower(c));
        }
        s.position++;
      }
    } else if (![32, 9, 10, 13].includes(c)) {
      if (s.grammar === 0) { if (c !== 123) fail(); s.grammar = 1; }
      else if (s.grammar === 1 || s.grammar === 7) {
        if (s.grammar === 1 && c === 125) s.grammar = 8;
        else { if (c !== 34) fail(); s.parts = [0n, 0n]; s.keyLength = 0; s.grammar = 2; }
      } else if (s.grammar === 3) { if (c !== 58) fail(); s.grammar = 4; }
      else if (s.grammar === 4) {
        if (c !== 34) fail(); s.string = stringStart(); s.parts = [0n, 0n]; s.position = 0; s.grammar = 5;
      } else if (s.grammar === 6) { if (c !== 44 && c !== 125) fail(); s.grammar = c === 44 ? 7 : 8; }
      else fail();
    }
    s.consumed++;
  }
}

function encode(s) {
  const bytes = new Uint8Array(83), view = new DataView(bytes.buffer);
  bytes[0] = s.grammar;
  for (let part = 0; part < 2; part++) {
    let value = s.parts[part];
    for (let i = 30; i >= 0; i--) { bytes[1 + part * 31 + i] = Number(value & 255n); value >>= 8n; }
  }
  view.setUint32(63, s.keyLength); bytes[67] = s.selected; bytes.set(s.seen, 68);
  view.setUint32(70, s.position); bytes.set(s.string, 74); view.setUint32(79, s.consumed);
  return bytes;
}

// Native opening coordinates refer to the exact object bytes in the authenticated response.
export async function prepareClaimsChunks(bytes, openings, { start = 0, crypto = globalThis.crypto } = {}) {
  const privateArrays = [];
  const clear = () => { for (const value of privateArrays) value.fill(0); };
  const keep = value => { privateArrays.push(value); return value; };
  const seal = async (value, capacity, blinder = keep(crypto.getRandomValues(new Uint8Array(16)))) => {
    const preimage = keep(new Array(capacity + 16).fill(0));
    preimage.splice(0, value.length, ...value); preimage.splice(value.length, 16, ...blinder);
    const encoded = keep(Uint8Array.from(preimage.slice(0, value.length + 16)));
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', encoded)));
    encoded.fill(0);
    return { preimage, hash };
  };
  try {
    if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 2304 ||
        !Number.isSafeInteger(start) || start < 0 || start + bytes.length > 16384 ||
        !Array.isArray(openings) || openings.length !== Math.ceil(bytes.length / 512) ||
        !crypto?.subtle || !crypto?.getRandomValues) fail();
    const document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    const ids = [document?.[actorKey], document?.[tenantKey]].map(value => {
      if (typeof value !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value)) fail();
      return value.toLowerCase();
    });
    const identities = [];
    for (const id of ids) identities.push(await seal(keep(encoder.encode(JSON.stringify(id))), 38));
    const references = ids.map(id => limbs(encoder.encode(id)));
    const state = { grammar: 0, parts: [0n, 0n], keyLength: 0, selected: 0, seen: [0, 0], position: 0, string: stringStart(), consumed: 0 };
    let before = await seal(keep(encode(state)), 83);
    const chunks = [];
    for (let offset = 0; offset < bytes.length; offset += 512) {
      const length = Math.min(512, bytes.length - offset);
      const opening = openings[offset / 512];
      if (!opening || opening.start !== start + offset || opening.end !== start + offset + length ||
          !(opening.hash instanceof Uint8Array) || opening.hash.length !== 32 ||
          !(opening.blinder instanceof Uint8Array) || opening.blinder.length !== 16) fail();
      const chunk = bytes.subarray(offset, offset + length);
      const authenticated = await seal(chunk, 512, opening.blinder);
      if (!same(authenticated.hash, opening.hash)) fail();
      scan(state, chunk, references);
      const after = await seal(keep(encode(state)), 83);
      const hashes = [authenticated.hash, before.hash, after.hash, ...identities.map(value => value.hash)];
      chunks.push({ inputs: { hashes, length, offset, total: bytes.length, chunk_preimage: authenticated.preimage,
        state_preimages: [before.preimage, after.preimage], identity_preimages: identities.map(value => value.preimage) },
        publicInputs: [...hashes.flat(), length, offset, bytes.length].map(value => `0x${BigInt(value).toString(16).padStart(64, '0')}`) });
      before = after;
    }
    if (state.grammar !== 8 || !state.seen.every(Boolean)) fail();
    return { chunks, identities, clear };
  } catch { clear(); return fail(); }
}
