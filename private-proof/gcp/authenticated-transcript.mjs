const HEX = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PARTS = new Set(['START_LINE', 'PROTOCOL', 'METHOD', 'REQUEST_TARGET', 'STATUS_CODE', 'HEADERS', 'BODY', 'ALL']);
const fail = () => { throw new Error('GCP_PRIVATE_TRANSCRIPT_INVALID'); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) => record(value) && Object.keys(value).length === keys.length &&
  keys.every(key => Object.hasOwn(value, key));

function action(value) {
  if (exactKeys(value, ['kind']) && value.kind === 'REVEAL') return 'REVEAL';
  if (exactKeys(value, ['kind', 'algorithm']) && value.kind === 'HASH' && value.algorithm === 'SHA256') return 'HASH';
  return fail();
}

/**
 * Call only after authenticating the native verifier's receipt and checking the
 * current attempt, expiry and replay ledger. `expected` comes from server state.
 * This binds ranges; HTTP/JSON semantics and all private predicates remain to verify.
 */
export function authenticatedTranscript(receipt, expected) {
  if (!record(receipt) || !record(expected) || receipt.failure !== undefined ||
      !UUID.test(expected.sessionId ?? '') || !UUID.test(expected.proofId ?? '') ||
      !HEX.test(expected.pluginSha256 ?? '') || !/^[A-Za-z0-9_-]{43}$/.test(expected.nonceMac ?? '') ||
      !/^(?:identity|groups:[0-4])$/.test(expected.step ?? '') || !record(receipt.session) ||
      receipt.session.id !== expected.sessionId || receipt.session.proofId !== expected.proofId ||
      receipt.session.pluginSha256 !== expected.pluginSha256 || receipt.session.nonceMac !== expected.nonceMac ||
      receipt.session.step !== expected.step || receipt.session.method !== 'GCP_WORK' || receipt.session.mode !== 'Proxy' ||
      receipt.server_name !== (expected.step === 'identity' ? 'accounts.google.com' : 'logging.clients6.google.com')) fail();
  return authenticatedTranscriptRanges(receipt);
}

/** Same session binding as authenticatedTranscript for another source. `source` is a fixed
 * application policy ({host, method, step}), never a field in a client proof bundle. */
export function authenticatedSourceTranscript(receipt, expected, source) {
  if (!record(receipt) || !record(expected) || receipt.failure !== undefined ||
      !exactKeys(source, ['host', 'method', 'step']) || typeof source.host !== 'string' ||
      !source.host || typeof source.method !== 'string' || !source.method ||
      !UUID.test(expected.sessionId ?? '') || !UUID.test(expected.proofId ?? '') ||
      !HEX.test(expected.pluginSha256 ?? '') || !/^[A-Za-z0-9_-]{43}$/.test(expected.nonceMac ?? '') ||
      typeof source.step !== 'string' || !source.step || expected.step !== source.step || !record(receipt.session) ||
      receipt.session.id !== expected.sessionId || receipt.session.proofId !== expected.proofId ||
      receipt.session.pluginSha256 !== expected.pluginSha256 || receipt.session.nonceMac !== expected.nonceMac ||
      receipt.session.step !== expected.step || receipt.session.method !== source.method || receipt.session.mode !== 'Proxy' ||
      receipt.server_name !== source.host) fail();
  return authenticatedTranscriptRanges(receipt);
}

/** Provider-neutral range checks only. The caller MUST authenticate the native
 * receipt and bind its host/session/attempt before calling; this authenticates no source. */
export function authenticatedTranscriptRanges(receipt) {
  if (!record(receipt) || receipt.failure !== undefined || !exactKeys(receipt.config, ['sent', 'recv']) ||
      !Array.isArray(receipt.results) || !record(receipt.transcript)) fail();

  const resultCount = ['sent', 'recv'].reduce((count, direction) => {
    const ranges = receipt.config[direction];
    if (!Array.isArray(ranges) || !ranges.length || ranges.length > 256) fail();
    return count + ranges.length;
  }, 0);
  if (receipt.results.length !== resultCount || receipt.results.some(result =>
    !exactKeys(result, ['type', 'part', 'action', 'value']) || !['SENT', 'RECV'].includes(result.type))) fail();

  const output = {};
  const digests = new Set();
  for (const direction of ['sent', 'recv']) {
    const type = direction.toUpperCase();
    const length = receipt.transcript[`${direction}_length`];
    if (!Number.isSafeInteger(length) || length < 1 || length > 16384) fail();
    const bytes = new Uint8Array(length);
    const privateRanges = [];
    const results = receipt.results.filter(result => result.type === type);
    const ranges = receipt.config[direction];
    if (results.length !== ranges.length) fail();
    const ordered = [];
    for (let index = 0; index < ranges.length; index++) {
      const range = ranges[index], result = results[index];
      if (!exactKeys(range, ['start', 'end', 'handler']) || !Number.isSafeInteger(range.start) ||
          !Number.isSafeInteger(range.end) || range.start < 0 || range.end <= range.start || range.end > length ||
          !exactKeys(range.handler, ['type', 'part', 'action']) || range.handler.type !== type ||
          !PARTS.has(range.handler.part) || range.handler.part !== result.part ||
          (range.handler.part === 'ALL' && (range.start !== 0 || range.end !== length)) ||
          typeof result.value !== 'string') fail();
      const kind = action(range.handler.action);
      if (action(result.action) !== kind) fail();
      if (kind === 'HASH') {
        if (!HEX.test(result.value) || digests.has(result.value)) fail();
        digests.add(result.value);
        privateRanges.push({ start: range.start, end: range.end, hash: result.value });
      } else {
        // Only public ASCII is supported; reject lossy native UTF-8 conversions.
        if (result.value.length !== range.end - range.start || /[^\x09\x0a\x0d\x20-\x7e]/.test(result.value)) fail();
        for (let offset = 0; offset < result.value.length; offset++) bytes[range.start + offset] = result.value.charCodeAt(offset);
      }
      ordered.push({ start: range.start, end: range.end });
    }
    ordered.sort((left, right) => left.start - right.start);
    let cursor = 0;
    for (const range of ordered) {
      if (range.start !== cursor) fail();
      cursor = range.end;
    }
    if (cursor !== length) fail();
    // Extra authenticated disclosures must not enter storage outside this plan.
    const native = receipt.transcript[direction];
    if (typeof native !== 'string' || native.length !== length) fail();
    for (let offset = 0; offset < length; offset++) if (native.charCodeAt(offset) !== bytes[offset]) fail();
    privateRanges.sort((left, right) => left.start - right.start);
    output[direction] = { bytes, privateRanges };
  }
  return output;
}
