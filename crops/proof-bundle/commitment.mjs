// Canonical JSON and the bundle commitment. Pure ESM on WebCrypto: runs in Node 22+ and browsers.

export const DOMAIN = 'tlsn-fork/proof-bundle';
const HEX64 = /^[0-9a-f]{64}$/;
const NAME = /^[a-z0-9-]{1,48}$/;
// Coarse claims only: lowercase words, digits and separators, never free text; fits an Arkiv str (128 bytes).
const CLAIM = /^[a-z0-9:,._-]{1,128}$/;
const REQUIRED = ['provider', 'claim', 'proofHash'];
const OPTIONAL = ['window', 'vkHashes', 'coreDigest', 'pluginSha256'];

const fail = reason => { throw new Error(`PROOF_BUNDLE_INVALID: ${reason}`); };

/** Sorted keys, no whitespace. Only plain objects, arrays, strings, booleans, null and safe integers. */
export function canonicalize(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail('only safe integers are canonical');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    const keys = Object.keys(value).sort();
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return fail(`unsupported value of type ${typeof value}`);
}

export function toHex(bytes) {
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function sha256Hex(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  return toHex(await globalThis.crypto.subtle.digest('SHA-256', bytes));
}

/**
 * Validates and copies the public commitment fields of any evidence type.
 * Required: provider, claim (prefixed "<provider>:"), proofHash. Optional: window (days), vkHashes, coreDigest,
 * pluginSha256. Throws on anything outside this closed shape, so no free text or identifiers can ride along.
 */
export function commitmentFields(fields) {
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) fail('fields must be an object');
  const extra = Object.keys(fields).filter(key => !REQUIRED.includes(key) && !OPTIONAL.includes(key));
  if (extra.length) fail(`unexpected field ${extra[0]}`);
  const { provider, claim, window, vkHashes, proofHash, coreDigest, pluginSha256 } = fields;
  if (typeof provider !== 'string' || !NAME.test(provider)) fail('provider');
  if (typeof claim !== 'string' || !CLAIM.test(claim) || !claim.startsWith(`${provider}:`)) fail('claim');
  const clean = { provider, claim, proofHash };
  if (window !== undefined) {
    if (!Number.isSafeInteger(window) || window < 1 || window > 3660) fail('window');
    clean.window = window;
  }
  if (vkHashes !== undefined) {
    if (!vkHashes || typeof vkHashes !== 'object' || Array.isArray(vkHashes)) fail('vkHashes');
    const circuits = Object.keys(vkHashes);
    if (!circuits.length || circuits.length > 32 ||
        circuits.some(id => !NAME.test(id) || typeof vkHashes[id] !== 'string' || !HEX64.test(vkHashes[id]))) fail('vkHashes');
    clean.vkHashes = Object.fromEntries(circuits.sort().map(id => [id, vkHashes[id]]));
  }
  for (const [name, value] of [['proofHash', proofHash], ['coreDigest', coreDigest], ['pluginSha256', pluginSha256]]) {
    if (value === undefined && name !== 'proofHash') continue;
    if (typeof value !== 'string' || !HEX64.test(value)) fail(name);
    clean[name] = value;
  }
  return clean;
}

/** Hex sha256 over the canonical JSON of the versioned, domain-separated commitment fields. */
export async function bundleCommitment(fields) {
  return sha256Hex(canonicalize({ v: 1, domain: DOMAIN, ...commitmentFields(fields) }));
}
