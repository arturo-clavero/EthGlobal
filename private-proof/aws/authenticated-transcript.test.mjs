import assert from 'node:assert/strict';
import test from 'node:test';
import { authenticatedAwsTranscript } from './authenticated-transcript.mjs';

const now = 1_800_000_000_000;
const expected = { sessionId: '11111111-1111-4111-8111-111111111111', proofId: '22222222-2222-4222-8222-222222222222',
  pluginSha256: 'ab'.repeat(32), nonceMac: 'N'.repeat(43), step: 'E0', identityService: 'iam', region: 'us-east-1',
  issuedAt: now - 1000, expiresAt: now + 1000 };
function receipt(state = expected) {
  const reveal = type => ({ type, part: 'BODY', action: { kind: 'REVEAL' } });
  const hidden = { type: 'SENT', part: 'BODY', action: { kind: 'HASH', algorithm: 'SHA256' } };
  return { server_name: state.step === 'identity' ? 'iam.amazonaws.com' : 'cloudtrail.us-east-1.amazonaws.com',
    session: { id: state.sessionId, proofId: state.proofId, pluginSha256: state.pluginSha256,
      nonceMac: state.nonceMac, step: state.step, method: 'AWS_ACCOUNT', mode: 'Proxy' },
    config: { sent: [{ start: 0, end: 1, handler: reveal('SENT') }, { start: 1, end: 4, handler: hidden },
      { start: 4, end: 5, handler: reveal('SENT') }], recv: [{ start: 0, end: 2, handler: reveal('RECV') }] },
    results: [{ ...reveal('SENT'), value: '[' }, { ...hidden, value: 'cd'.repeat(32) },
      { ...reveal('SENT'), value: ']' }, { ...reveal('RECV'), value: '{}' }],
    transcript: { sent: '[\0\0\0]', recv: '{}', sent_length: 5, recv_length: 2 } };
}
const rejects = (value, state = expected, clock = now) => assert.throws(() => authenticatedAwsTranscript(value, state, clock),
  { message: 'AWS_PRIVATE_TRANSCRIPT_INVALID' });

test('binds separate IAM-self and exact-event receipts with fully covered private ranges', () => {
  for (const step of ['identity', 'E0']) {
    const state = { ...expected, step }, value = receipt(state);
    const parsed = authenticatedAwsTranscript(value, state, now);
    assert.deepEqual(parsed.sent.privateRanges, [{ start: 1, end: 4, hash: 'cd'.repeat(32) }]);
    assert.equal(new TextDecoder().decode(parsed.sent.bytes), '[\0\0\0]');
    value.config.sent[1].start = 0;
    assert.equal(parsed.sent.privateRanges[0].start, 1);
  }
});

test('rejects another attempt, step, session, nonce, plugin, host or protocol', () => {
  for (const [key, value] of Object.entries({ id: expected.proofId, proofId: expected.sessionId,
    nonceMac: 'X'.repeat(43), pluginSha256: 'ee'.repeat(32), step: 'identity', method: 'GCP_WORK', mode: 'MPC' })) {
    const candidate = receipt(); candidate.session[key] = value; rejects(candidate);
  }
  for (const host of ['iam.amazonaws.com', 'cloudtrail.us-west-2.amazonaws.com', 'attacker.invalid']) {
    const candidate = receipt(); candidate.server_name = host; rejects(candidate);
  }
});

test('does not promote a plaintext method to private assurance', () => {
  const value = receipt(); value.session.method = 'AWS_PLAINTEXT'; rejects(value);
});

test('rejects expired, future-issued and overlong attempt state at exact boundaries', () => {
  for (const patch of [{ expiresAt: now }, { issuedAt: now + 1 }, { expiresAt: expected.issuedAt + 900001 },
    { issuedAt: -1 }, { expiresAt: NaN }, { issuedAt: 1.5 }]) rejects(receipt(), { ...expected, ...patch });
  rejects(receipt(), expected, NaN);
  rejects(receipt(), { ...expected, step: 'E1' });
  rejects(receipt(), { ...expected, identityService: 'sts' });
  rejects(receipt(), { ...expected, region: 'us-west-2' });
});

test('retains the shared range guards for gaps, overlaps, extra disclosure and unsupported hashes', () => {
  const mutations = [
    value => { value.config.sent[1].start++; },
    value => { value.config.sent[1].start--; },
    value => { value.results[1].action.algorithm = 'BLAKE3'; },
    value => { value.transcript.sent = '[key]'; },
    value => { value.transcript.recv_length = 16385; },
    value => { value.results[1].value = 'private-credential'; },
    value => { value.results[0].value = '\ufffd'; },
    value => { value.failure = { reason: 'REQUEST_TOO_LARGE' }; },
    value => { value.results.pop(); },
  ];
  for (const mutate of mutations) { const value = receipt(); mutate(value); rejects(value); }
});

test('rejects malformed metadata without returning receipt contents', () => {
  rejects(null); rejects(receipt(), null);
  for (const patch of [{ sessionId: 'not-a-uuid' }, { proofId: null }, { pluginSha256: 'x' }, { nonceMac: 'x' }]) {
    rejects(receipt(), { ...expected, ...patch });
  }
});
