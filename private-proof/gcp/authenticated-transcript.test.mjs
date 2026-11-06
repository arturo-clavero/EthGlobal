import assert from 'node:assert/strict';
import { authenticatedTranscript } from './authenticated-transcript.mjs';

const expected = {
  sessionId: '11111111-1111-4111-8111-111111111111', proofId: '22222222-2222-4222-8222-222222222222',
  pluginSha256: 'ab'.repeat(32), nonceMac: 'N'.repeat(43), step: 'identity',
};
function fixture() {
  const handler = (type, kind) => ({ type, part: 'BODY', action: kind === 'HASH' ? { kind, algorithm: 'SHA256' } : { kind } });
  const sent = [{ start: 0, end: 2, handler: handler('SENT', 'REVEAL') },
    { start: 2, end: 8, handler: handler('SENT', 'HASH') },
    { start: 8, end: 10, handler: handler('SENT', 'REVEAL') }];
  const recv = [{ start: 0, end: 2, handler: handler('RECV', 'REVEAL') }];
  return {
    server_name: 'accounts.google.com',
    session: { id: expected.sessionId, proofId: expected.proofId, pluginSha256: expected.pluginSha256,
      nonceMac: expected.nonceMac, step: expected.step, method: 'GCP_WORK', mode: 'Proxy' },
    config: { sent, recv },
    results: [...sent.map((range, index) => ({ ...structuredClone(range.handler), value: ['[ ', 'cd'.repeat(32), ' ]'][index] })),
      { ...structuredClone(recv[0].handler), value: '{}' }],
    transcript: { sent: '[ ' + '\0'.repeat(6) + ' ]', recv: '{}', sent_length: 10, recv_length: 2 },
  };
}

const good = fixture(), result = authenticatedTranscript(good, expected);
assert.deepEqual(result.sent.privateRanges, [{ start: 2, end: 8, hash: 'cd'.repeat(32) }]);
assert.deepEqual([...result.sent.bytes], [91, 32, 0, 0, 0, 0, 0, 0, 32, 93]);
assert.equal(new TextDecoder().decode(result.recv.bytes), '{}');
good.config.sent[1].start = 1;
assert.equal(result.sent.privateRanges[0].start, 2);

// Native handlers preserve configuration order, which may differ from byte order.
const shuffled = fixture();
[shuffled.config.sent[0], shuffled.config.sent[2]] = [shuffled.config.sent[2], shuffled.config.sent[0]];
[shuffled.results[0], shuffled.results[2]] = [shuffled.results[2], shuffled.results[0]];
assert.deepEqual(authenticatedTranscript(shuffled, expected).sent, result.sent);

const bad = [
  receipt => { receipt.session.id = expected.proofId; },
  receipt => { receipt.session.proofId = expected.sessionId; },
  receipt => { receipt.session.nonceMac = 'X'.repeat(43); },
  receipt => { receipt.session.pluginSha256 = 'ee'.repeat(32); },
  receipt => { receipt.session.step = 'groups:0'; },
  receipt => { receipt.session.method = 'AWS_WORK'; },
  receipt => { receipt.session.mode = 'MPC'; },
  receipt => { receipt.server_name = 'attacker.invalid'; },
  receipt => { receipt.failure = { reason: 'REQUEST_TOO_LARGE' }; },
  receipt => { receipt.config.sent[1].start++; },
  receipt => { receipt.config.sent[1].start--; },
  receipt => { receipt.config.sent[1].end = 16385; },
  receipt => { receipt.config.sent[1].start = 2.5; },
  receipt => { receipt.config.sent[1].end = 2; },
  receipt => { receipt.config.sent[1].handler.part = 'ALL'; receipt.results[1].part = 'ALL'; },
  receipt => { receipt.config.sent[1].handler.type = 'RECV'; },
  receipt => { receipt.config.sent[1].handler.action.algorithm = 'BLAKE3'; },
  receipt => { receipt.results[1].action.algorithm = 'KECCAK256'; },
  receipt => { receipt.results[1].action = { kind: 'REVEAL' }; },
  receipt => { receipt.results[1].type = 'RECV'; },
  receipt => { receipt.results[1].part = 'HEADERS'; },
  receipt => { receipt.results[1].value = 'private-token'; },
  receipt => { receipt.results[0].value = '\ufffd '; },
  receipt => { receipt.results[0].value = 'too long'; },
  receipt => { receipt.results[0].value = '[\0'; },
  receipt => { receipt.results[0].action.secret = 'must not persist'; },
  receipt => { receipt.transcript.sent = '[ secret ]'; },
  receipt => { receipt.transcript.sent_length++; },
  receipt => { receipt.transcript.recv_length = 16385; },
  receipt => { receipt.results.push(receipt.results[0]); },
  receipt => { receipt.results.pop(); },
  receipt => { receipt.config.sent = Array(257).fill(receipt.config.sent[0]); },
];
for (const mutate of bad) {
  const receipt = fixture(); mutate(receipt);
  assert.throws(() => authenticatedTranscript(receipt, expected), { message: 'GCP_PRIVATE_TRANSCRIPT_INVALID' });
}
assert.throws(() => authenticatedTranscript(null, expected), /GCP_PRIVATE_TRANSCRIPT_INVALID/);
assert.throws(() => authenticatedTranscript(fixture(), { ...expected, step: 'groups:5' }), /GCP_PRIVATE_TRANSCRIPT_INVALID/);
console.log(JSON.stringify({ suite: 'authenticated transcript range binding', accepted: 2, rejected: bad.length + 2 }));
