import assert from 'node:assert/strict';
import test from 'node:test';
import { groupedFixture } from './grouped-fixture.mjs';
import { fixtureNow } from './event-fixture.mjs';
import { inspectAwsIdentitySession } from './identity-structure.mjs';
import { inspectAwsEventSession } from './event-structure.mjs';
import { assembleAwsBundleExpectations, verifyAwsBundle } from './verify-bundle.mjs';

function fixture(families) {
  const fixtures = groupedFixture(families), [identity, ...events] = fixtures;
  const targets = assembleAwsBundleExpectations(inspectAwsIdentitySession(identity.receipt, identity.expected, fixtureNow),
    events.map(event => inspectAwsEventSession(event.receipt, event.expected, event.claims, fixtureNow)), identity.expected.issuedAt);
  return { sessions: fixtures.map(({ receipt, expected }) => ({ receipt, expected })), now: fixtureNow,
    bundle: { kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: fixtures.map(f => f.expected.sessionId),
      proofs: targets.map(({ circuitId, publicInputs }) => ({ circuitId, publicInputs: publicInputs.map(String), proof: 'AA==' })) },
    runtime: { verify: async () => true } };
}

test('groups only individually bound positive events; sparse collections make no absence claim', async () => {
  assert.deepEqual(await verifyAwsBundle(fixture()), { activities: ['iam-role-trust-update', 'lambda-configuration-update', 'security-group-ingress'],
    attribution: 'iam-user', windowDays: 90 });
  assert.deepEqual(await verifyAwsBundle(fixture(['network'])), { activities: ['security-group-ingress'], attribution: 'iam-user', windowDays: 90 });
});

test('does not count repeated-family events as additional breadth', async () => {
  await assert.rejects(verifyAwsBundle(fixture(['iam', 'iam'])), /AWS_PRIVATE_BUNDLE_INVALID/);
});

test('each group requires its own native receipt, actor relation, cutoff and proof', async () => {
  for (const mutate of [
    value => { value.sessions.pop(); },
    value => { value.sessions[2].receipt = value.sessions[1].receipt; },
    value => { value.sessions[2].expected.step = 'E0'; },
    value => { value.sessions[3].expected.nonceMac = 'X'.repeat(43); },
    value => { value.bundle.proofs.splice(2, 1); },
    value => { value.bundle.proofs[2].publicInputs[128] = String(BigInt(value.bundle.proofs[2].publicInputs[128]) ^ 1n); },
    value => { value.bundle.proofs[5].publicInputs[198] = String(fixtureNow); },
    value => { value.runtime.verify = async proof => proof !== value.bundle.proofs[3]; },
  ]) {
    const value = fixture(); mutate(value);
    await assert.rejects(verifyAwsBundle(value), /AWS_PRIVATE_BUNDLE_INVALID/);
  }
});
