import assert from 'node:assert/strict';
import test from 'node:test';
import { hashSignal } from '@worldcoin/idkit-core/hashing';
import { worldIdRequest, worldIdRequestConfig } from './client.mjs';
import { signRpContext, verifyWorldIdResult } from './server.mjs';

const commitment = 'a'.repeat(64);
const rpContext = signRpContext({ rpId: 'rp_test', action: 'apply:job-1', signingKeyHex: '11'.repeat(32) });
const options = { appId: 'app_test', action: 'apply:job-1', signal: commitment, rpContext };

test('rp_context is signed with the real IDKit signer for the job action', () => {
  assert.equal(rpContext.rp_id, 'rp_test');
  assert.match(rpContext.signature, /^0x[0-9a-f]{130}$/);
  assert.ok(rpContext.expires_at > rpContext.created_at);
  assert.throws(() => signRpContext({ rpId: 'rp_test', action: 'login', signingKeyHex: '11'.repeat(32) }), /action/);
});

test('request asks for proof of human or passport uniqueness, bound to the commitment, never attributes', async () => {
  const { config, constraints } = worldIdRequestConfig(options);
  assert.deepEqual(JSON.parse(JSON.stringify(constraints)), { any: [{ type: 'proof_of_human', signal: commitment }, { type: 'passport', signal: commitment }] });
  assert.equal(config.allow_legacy_proofs, false);
  assert.equal(JSON.stringify({ config, constraints }).match(/nationality|age|country|attributes/), null);
  assert.deepEqual(JSON.parse(JSON.stringify(worldIdRequestConfig({ ...options, preset: 'proof_of_human' }).constraints)), { type: 'proof_of_human', signal: commitment });
  for (const bad of [{ action: 'apply:../x' }, { signal: 'user-123' }, { preset: 'identityCheck' }, { appId: 'x' }, { rpContext: {} }])
    assert.throws(() => worldIdRequestConfig({ ...options, ...bad }), /PERSONHOOD_INVALID/);
  const calls = [];
  const idkit = { request: config => ({ constraints: async value => { calls.push([config, value]); return 'request'; } }) };
  assert.equal(await worldIdRequest(options, { idkit }), 'request');
  assert.equal(calls[0][0].app_id, 'app_test');
});

const result = (extra = {}) => ({ protocol_version: '4.0', nonce: rpContext.nonce, action: 'apply:job-1', environment: 'production',
  responses: [{ identifier: 'passport', signal_hash: hashSignal(commitment), proof: ['0x1', '0x2', '0x3', '0x4', '0x5'],
    nullifier: '0xABC', issuer_schema_id: 9, expires_at_min: 1 }], ...extra });
const portal = (body, status = 200) => {
  const calls = [];
  return { calls, fetch: async (url, init) => { calls.push({ url, init }); return { ok: status === 200, json: async () => body }; } };
};
const verifyOptions = { rpId: 'rp_test', action: 'apply:job-1', signal: commitment };

test('a verified result is forwarded unchanged and yields the nullifier and credential', async () => {
  const api = portal({ success: true, environment: 'production', nullifier: '0xabc',
    results: [{ identifier: 'passport', success: true, nullifier: '0xABC' }] });
  assert.deepEqual(await verifyWorldIdResult(result(), { ...verifyOptions, fetch: api.fetch }),
    { ok: true, nullifier: '0xabc', credential: 'passport' });
  assert.equal(api.calls[0].url, 'https://developer.world.org/api/v4/verify/rp_test');
  assert.deepEqual(JSON.parse(api.calls[0].init.body), result());
});

test('mismatched, rejected or unavailable verifications fail closed without calling out when local checks fail', async () => {
  const reason = async (value, api = portal({ success: true, environment: 'production', nullifier: '0x1' })) =>
    (await verifyWorldIdResult(value, { ...verifyOptions, fetch: api.fetch })).reason;
  assert.equal(await reason(result({ action: 'apply:job-2' })), 'action-mismatch');
  assert.equal(await reason(result({ environment: 'staging' })), 'environment-mismatch');
  assert.equal(await reason(result({ protocol_version: '3.0' })), 'malformed');
  assert.equal(await reason(result({ responses: [{ ...result().responses[0], signal_hash: hashSignal('b'.repeat(64)) }] })), 'signal-mismatch');
  assert.equal(await reason(result({ responses: [{ ...result().responses[0], identifier: 'selfie' }] })), 'credential-not-allowed');
  assert.equal(await reason(result(), portal({ success: false, code: 'all_verifications_failed' }, 400)), 'all_verifications_failed');
  assert.equal(await reason(result(), { fetch: async () => { throw new Error('down'); } }), 'unavailable');
  assert.equal(await reason(result(), portal({ success: true, environment: 'staging', nullifier: '0x1' })), 'rejected');
});
