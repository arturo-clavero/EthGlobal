// Synthetic-only test fixtures. These hashes are deterministic stand-ins, NOT
// native TLS commitments or accepted cryptographic proofs. Never use at runtime.
import { BATCHES, localBatchBody } from './policy.mjs';

export const fixturePolicy = Object.freeze({ cutoff: Date.parse('2026-10-13T00:00:00.000Z'), windowDays: 30 });
export const fixtureNonce = 'N'.repeat(43);
export const literal = text => ({ text, hidden: [] });
export const secret = (text, kind) => ({ text, hidden: [{ start: 0, end: text.length, ...(kind === undefined ? {} : { kind }) }] });
export function fragments(...items) {
  let text = ''; const hidden = [];
  for (const item of items) {
    const part = typeof item === 'string' ? literal(item) : item;
    for (const range of part.hidden) hidden.push({ ...range, start: range.start + text.length, end: range.end + text.length });
    text += part.text;
  }
  return { text, hidden };
}
export function redactFixture(sent, recv, step = 'identity', policy = fixturePolicy) {
  let next = 1;
  const atomicClaims = [], directions = {};
  for (const [name, fragment] of [['sent', sent], ['recv', recv]]) {
    const bytes = new TextEncoder().encode(fragment.text), direction = name.toUpperCase();
    const privateRanges = fragment.hidden.map(range => {
      const start = new TextEncoder().encode(fragment.text.slice(0, range.start)).length;
      const end = new TextEncoder().encode(fragment.text.slice(0, range.end)).length;
      const slot = { start, end, hash: (next++).toString(16).padStart(64, '0') };
      bytes.fill(0, start, end);
      if (range.kind !== undefined) atomicClaims.push({ direction, ...slot, kind: range.kind });
      return slot;
    });
    directions[name] = { bytes, privateRanges };
  }
  return { directions, meta: { step, nonceMac: fixtureNonce }, policy, atomicClaims };
}
export function identityRow(index = 0, flag = '1', metadata = literal('null')) {
  return fragments('["gaia.l.a",', metadata, ',null,', secret(`"member${index}@example.test"`, 1),
    ',null,null,null,null,null,', flag, ',', secret(`"123450${index}"`, 1), ',null,null,null,0,1]');
}
export function identityFragments({ rows = [identityRow()], requestHeaders = '', responseHeaders = '', root } = {}) {
  const body = root ?? fragments('["gaia.l.a.r",[', ...rows.flatMap((row, index) => index ? [',', row] : [row]), ']]');
  return {
    sent: fragments('POST /ListAccounts?json=standard&authuser=', secret('0'),
      ' HTTP/1.1\r\nHost: accounts.google.com\r\nConnection: close\r\nX-16Signals-Nonce: ', fixtureNonce,
      '\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: ', secret('synthetic-cookie'),
      '\r\n', requestHeaders, 'Content-Length: 1\r\n\r\n '),
    recv: fragments('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n', responseHeaders,
      'Content-Length: ', String(body.text.length), '\r\n\r\n', body),
  };
}
export function groupPart(id, status = 'observed', bodyOverride) {
  const body = bodyOverride ?? (status === 'observed' ? fragments('{"entries":[{"timestamp":', secret('"2026-10-12T12:34:56Z"', 1), '}]}')
    : status === 'denied' ? fragments('{"error":{"code":403,"status":"PERMISSION_DENIED","message":', secret('"synthetic denied"', 1), '}}')
      : literal('{"entries":[]}'));
  const code = status === 'denied' ? '403 Forbidden' : '200 OK';
  return fragments('--fixture_boundary\r\nContent-Type: application/http\r\nContent-ID: <response-', id,
    '>\r\n\r\nHTTP/1.1 ', code, '\r\nContent-Type: application/json\r\nContent-Length: ',
    String(body.text.length), '\r\n\r\n', body, '\r\n');
}
export function groupFragments(step = 'groups:0', { parts, requestHeaders = '', responseHeaders = '', chunked = false } = {}) {
  const batch = BATCHES.find(batch => batch.step === step);
  const built = localBatchBody(step, fixturePolicy, 'sample-project', 'member0@example.test');
  const requestBody = { text: built.text, hidden: built.privateRanges };
  const body = fragments(...(parts ?? batch.groupIds.map((id, index) => groupPart(id, ['observed', 'empty', 'denied'][index % 3]))),
    '--fixture_boundary--\r\n');
  return {
    sent: fragments('POST /batch?key=', secret('AIza' + 'X'.repeat(35)),
      ' HTTP/1.1\r\nHost: logging.clients6.google.com\r\nConnection: close\r\nX-16Signals-Nonce: ', fixtureNonce,
      '\r\nContent-Type: multipart/mixed; boundary=gcp_groups_v1\r\nX-Goog-AuthUser: ', secret('0'),
      '\r\nAuthorization: ', secret('synthetic-auth'), '\r\n', requestHeaders,
      'Content-Length: ', String(requestBody.text.length), '\r\n\r\n', requestBody),
    recv: fragments('HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=fixture_boundary\r\n', responseHeaders,
      chunked ? fragments('Transfer-Encoding: chunked\r\n\r\n', body.text.length.toString(16), '\r\n', body, '\r\n0\r\n\r\n')
        : fragments('Content-Length: ', String(body.text.length), '\r\n\r\n', body)),
  };
}
export function gcpFixture(step = 'identity', options = {}) {
  const raw = step === 'identity' ? identityFragments(options) : groupFragments(step, options);
  return redactFixture(raw.sent, raw.recv, step);
}
