// Synthetic-only transcripts and SHA openings; these are NOT authenticated TLS receipts.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { BATCHES, localBatchBody } from './policy.mjs';
import { planGcpSession } from './client-plan.mjs';

const encoder = new TextEncoder(), decoder = new TextDecoder();
export const policy = { cutoff: 1704067200000, windowDays: 7 };
export const projectId = 'sample-project', email = 'user@example.invalid', nonceMac = 'A'.repeat(43);
const sha = bytes => createHash('sha256').update(bytes).digest();
export const options = { projectId, email, policy };
function http(start, headers, body, chunkAt) {
  const bytes = typeof body === 'string' ? encoder.encode(body) : body;
  if (chunkAt !== undefined) {
    const chunks = [bytes.slice(0, chunkAt), bytes.slice(chunkAt)].filter(part => part.length);
    return Buffer.concat([Buffer.from(`${start}\r\n${headers.join('\r\n')}\r\nTransfer-Encoding: chunked\r\n\r\n`),
      ...chunks.flatMap(part => [Buffer.from(`${part.length.toString(16)}\r\n`), part, Buffer.from('\r\n')]), Buffer.from('0\r\n\r\n')]);
  }
  return encoder.encode(`${start}\r\n${headers.join('\r\n')}\r\nContent-Length: ${bytes.length}\r\n\r\n${decoder.decode(bytes)}`);
}
export function fixture({ identityBody, chunkAt, denied = false, cookieLength = 2049, capacity = false } = {}) {
  const row = ['gaia.l.a', 'Private employer 👩‍💻', 'https://private.invalid/avatar', email,
    null, null, null, null, null, 1, '12345', null, null, null, 0, 1];
  // Realistic public workload counts, with invented values and upper-bucket header lengths.
  if (capacity) {
    cookieLength = 2048;
    row[2] = 'a'.repeat(128);
    for (const index of [4, 5, 6, 7, 8]) row[index] = 'synthetic';
  }
  const capacityHeaders = index => !capacity ? [] : [
    ...Array.from({ length: index < 3 ? 25 : 24 }, () => `X-Synthetic-Small: ${'s'.repeat(64)}`),
    ...Array.from({ length: index < 4 ? 3 : 2 }, (_, item) =>
      `X-Synthetic-Medium: ${'m'.repeat(index === 0 && item === 0 ? 128 : 256)}`),
    ...(index === 0 ? [`X-Synthetic-Large: ${'l'.repeat(1024)}`] : []),
  ];
  identityBody ??= JSON.stringify(['gaia.l.a.r', [row]]);
  const requestHeaders = identity => [`Host: ${identity ? 'accounts.google.com' : 'logging.clients6.google.com'}`,
    'Connection: close', `X-16signals-Nonce: ${nonceMac}`,
    `Content-Type: ${identity ? 'application/x-www-form-urlencoded' : 'multipart/mixed; boundary=gcp_groups_v1'}`,
    `Origin: ${identity ? 'https://www.google.com' : 'https://console.cloud.google.com'}`,
    `Accept: ${identity ? 'application/json' : 'multipart/mixed'}`, 'Accept-Encoding: identity',
    `Cookie: ${'s'.repeat(cookieLength)}`, ...(!identity ? ['X-Goog-Authuser: 0', 'Authorization: SAPISIDHASH synthetic'] : [])];
  const identity = {
    sent: http('POST /ListAccounts?json=standard&authuser=0 HTTP/1.1', requestHeaders(true), ' '),
    recv: http('HTTP/1.1 200 OK', ['Content-Type: application/json; charset=UTF-8', 'X-Private-Transport: synthetic', ...capacityHeaders(0)], identityBody, chunkAt),
  };
  let groupIndex = 0;
  const transcripts = [identity, ...BATCHES.map((batch, index) => {
    let body = '';
    for (const id of batch.groupIds) {
      const json = denied ? '{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Private project", "details":[{"privateEmployer":"hidden"}]}}'
        : capacity && groupIndex++ >= 8 ? '{"entries":[]}' : '{"entries":[{"timestamp":"2023-12-31T12:00:00Z"}]}';
      const inner = decoder.decode(http(`HTTP/1.1 ${denied ? '403 Forbidden' : '200 OK'}`, ['Content-Type: application/json'], json));
      body += `--response_v1\r\nContent-Type: application/http\r\nContent-ID: <response-${id}>\r\n\r\n${inner}\r\n`;
    }
    body += '--response_v1--\r\n';
    return { sent: http(`POST /batch?key=AIza${'K'.repeat(35)} HTTP/1.1`, requestHeaders(false), localBatchBody(batch.step, policy, projectId, email).text),
      recv: http('HTTP/1.1 200 OK', ['Content-Type: multipart/mixed; boundary=response_v1', 'X-Private-Transport: synthetic', ...capacityHeaders(index + 1)], body) };
  })];
  return transcripts.map((transcript, index) => ({ ...transcript, step: index ? BATCHES[index - 1].step : 'identity',
    sessionId: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`, proofId: 'private-run', nonceMac,
    serverName: index ? 'logging.clients6.google.com' : 'accounts.google.com' }));
}
export function committed(raw) {
  const planned = planGcpSession(raw, raw, options), selections = {
    sent: planned.plan.sentRangesWithHandlers, recv: planned.plan.recvRangesWithHandlers,
  };
  const openings = {};
  for (const direction of ['sent', 'recv']) {
    openings[direction] = selections[direction].filter(range => range.handler.action.kind === 'HASH').map((range, index) => {
      const blinder = new Uint8Array(sha(encoder.encode(`${raw.sessionId}:${direction}:${index}`)).subarray(0, 16));
      return { start: range.start, end: range.end, blinder,
        hash: new Uint8Array(sha(Buffer.concat([raw[direction].subarray(range.start, range.end), blinder]))) };
    }).reverse(); // Native openings are deliberately not returned in range order.
  }
  return { ...raw, selections, openings };
}
export function mockPublicInputs(id, input) {
  let values;
  if (id === 'headers-small-v1' || id === 'atoms-small-v1') {
    values = [...input.hashes.flat(), ...input.lengths, ...(input.kinds ?? [])];
    for (let index = 0; index < input.lengths.length; index++) {
      const length = input.lengths[index];
      if (length) assert.deepEqual(Array.from(sha(Uint8Array.from(input.preimages[index].slice(0, length + 16)))), input.hashes[index]);
      else assert(input.hashes[index].every(byte => byte === 0));
      assert(input.preimages[index].slice(length ? length + 16 : 0).every(byte => byte === 0));
      if (length && input.kinds) {
        const atom = JSON.parse(decoder.decode(Uint8Array.from(input.preimages[index].slice(0, length))));
        assert.equal(input.kinds[index], typeof atom === 'string' ? 1 : typeof atom === 'number' ? 2 : atom === true ? 3 : atom === false ? 4 : 5);
      }
    }
  } else if (id === 'header-v1' || id === 'atom-v1') {
    values = [...input.commitment, input.length];
    const raw = input.preimage.slice(0, input.length);
    assert.deepEqual(Array.from(sha(Uint8Array.from(input.preimage.slice(0, input.length + 16)))), input.commitment);
    assert(input.preimage.slice(input.length + 16).every(byte => byte === 0));
    if (id === 'atom-v1') {
      const value = JSON.parse(decoder.decode(Uint8Array.from(raw)));
      values.push(typeof value === 'string' ? 1 : typeof value === 'number' ? 2 : value === true ? 3 : value === false ? 4 : 5);
    }
  } else if (id === 'identity-scope-v1') values = [...input.nonce, ...input.scope_hash, ...input.authuser_hash, input.row_count,
    ...input.row_email_hashes.flat(), ...input.row_id_hashes.flat(), ...input.row_email_lengths, ...input.row_id_lengths, ...input.row_valid.map(Number)];
  else if (id === 'query-scope-v1') values = [...input.nonce, ...input.scope_hash, input.group_count, ...input.project_hashes.flat(),
    ...input.project_lengths, ...input.email_hashes.flat(), ...input.email_lengths, ...input.authuser_hash, ...input.api_key_hash];
  else values = [...input.hashes.flat(), ...input.lengths, input.cutoff, input.window];
  return values.map(value => String(value));
}
