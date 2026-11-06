import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { inspectIdentityReceipt } from './identity-receipt.mjs';

const expected = { sessionId: '11111111-1111-4111-8111-111111111111', proofId: '22222222-2222-4222-8222-222222222222',
  pluginSha256: 'a'.repeat(64), nonceMac: 'b'.repeat(43), step: 'identity' };
const secret = 'Bearer PRIVATE_CREDENTIAL_SENTINEL';
const digest = bytes => createHash('sha256').update(bytes).update(Buffer.alloc(16, 7)).digest('hex');

function fixture({ target = '/v1.0/me?$select=id', host = 'graph.microsoft.com', extra = '', revealCredential = false } = {}) {
  const prefix = `GET ${target} HTTP/1.1\r\nHost: ${host}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nx-azure-proof-nonce: ${expected.nonceMac}\r\nx-azure-proof-step: identity\r\nAuthorization: `;
  const suffix = `\r\n${extra}\r\n`;
  const sent = prefix + secret + suffix;
  const response = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}';
  const config = { sent: [], recv: [] }, results = [];
  function add(type, start, end, bytes, hidden) {
    const action = hidden ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' };
    const handler = { type, part: type === 'RECV' ? 'ALL' : 'HEADERS', action };
    config[type.toLowerCase()].push({ start, end, handler });
    results.push({ ...handler, value: hidden ? digest(Buffer.from(bytes)) : bytes });
  }
  add('SENT', 0, prefix.length, prefix, false);
  add('SENT', prefix.length, prefix.length + secret.length, secret, !revealCredential);
  add('SENT', prefix.length + secret.length, sent.length, suffix, false);
  add('RECV', 0, response.length, response, true);
  return { server_name: 'graph.microsoft.com', session: { id: expected.sessionId, proofId: expected.proofId,
    pluginSha256: expected.pluginSha256, nonceMac: expected.nonceMac, step: 'identity', method: 'AZURE_WORK_PRIVATE', mode: 'Proxy' },
    config, results, transcript: { sent: prefix + (revealCredential ? secret : '\0'.repeat(secret.length)) + suffix,
      sent_length: sent.length, recv: '\0'.repeat(response.length), recv_length: response.length } };
}

test('derives identity commitment and mandatory header proofs without releasing private bytes', () => {
  const result = inspectIdentityReceipt(fixture(), expected);
  assert.equal(result.headerObligations.length, 1);
  assert.equal(result.headerObligations[0].circuitId, 'header-v1');
  assert.equal(result.headerObligations[0].length, secret.length);
  assert.match(result.responseHash, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.ok(!JSON.stringify(result).includes('HTTP/1.1'));
});

test('rejects source, method, session, nonce, step and packaged-build substitutions', () => {
  for (const mutate of [
    r => { r.server_name = 'accounts.google.com'; },
    r => { r.session.method = 'GCP_WORK'; },
    r => { r.session.id = expected.proofId; },
    r => { r.session.proofId = expected.sessionId; },
    r => { r.session.nonceMac = 'c'.repeat(43); },
    r => { r.session.step = 'tenant'; },
    r => { r.session.pluginSha256 = 'c'.repeat(64); },
    r => { r.session.mode = 'Mpc'; },
  ]) {
    const receipt = fixture(); mutate(receipt);
    assert.throws(() => inspectIdentityReceipt(receipt, expected), /AZURE_PRIVATE_IDENTITY_RECEIPT_INVALID/);
  }
});

test('rejects private disclosure, extra headers, changed request semantics and malformed coverage', () => {
  for (const receipt of [fixture({ revealCredential: true }), fixture({ target: '/v1.0/users/attacker?$select=id' }),
    fixture({ host: 'other.invalid' }), fixture({ extra: 'Cookie: PRIVATE_COOKIE\r\n' }),
    fixture({ extra: 'Authorization: Bearer attacker\r\n' }), fixture({ extra: 'Content-Length: 1\r\n' })]) {
    assert.throws(() => inspectIdentityReceipt(receipt, expected), /AZURE_PRIVATE_IDENTITY_RECEIPT_INVALID/);
  }
  for (const mutate of [
    r => { r.transcript.recv = 'X' + r.transcript.recv.slice(1); },
    r => { r.config.recv[0].end--; },
    r => { r.config.sent[1].start++; },
    r => { r.results.at(-1).action.algorithm = 'BLAKE3'; },
    r => { r.results.at(-1).value = 'not-a-commitment'; },
    r => { r.results[0].unexpected = 'PRIVATE'; },
  ]) {
    const receipt = fixture(); mutate(receipt);
    assert.throws(() => inspectIdentityReceipt(receipt, expected), /AZURE_PRIVATE_IDENTITY_RECEIPT_INVALID/);
  }
});
