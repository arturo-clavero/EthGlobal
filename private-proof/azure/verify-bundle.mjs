import { sanitizeAzurePrivateResult, validateAzureAttempt, azureProofFields } from './browser-result.mjs';
import { inspectIdentityReceipt } from './identity-receipt.mjs';
import { inspectTenantReceipt, inspectActivityReceipt } from './source-receipt.mjs';
import { activityProofExpectations, headerProofExpectations } from './activity-bindings.mjs';

const fail = () => { throw new Error('AZURE_PRIVATE_BUNDLE_INVALID'); };
const digest = value => {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail();
  return Array.from({ length: 32 }, (_, i) => parseInt(value.slice(i * 2, i * 2 + 2), 16));
};
const field = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
const attemptKeys = ['proofId', 'pluginSha256', 'nonceMac', 'challenge', 'cutoffMs', 'issuedAt', 'expiresAt'];

/** Only trusted native receipts and their server-owned attempt contexts may enter here.
 * The bundle contains provisional commitments; none can replace a source-derived expectation.
 */
export function azureBundleExpectations(sessions, bundle, now = Date.now()) {
  if (!Array.isArray(sessions) || sessions.length !== 3) fail();
  const first = sessions[0]?.expected;
  if (!first) fail();
  validateAzureAttempt(Object.fromEntries(attemptKeys.map(key => [key, first[key]])), now);
  for (const [index, step] of ['identity', 'tenant', 'activity'].entries()) {
    const expected = sessions[index]?.expected;
    if (!expected || expected.step !== step || expected.sessionId !== bundle.sessionIds[index] ||
        attemptKeys.some(key => expected[key] !== first[key])) fail();
  }
  const identity = inspectIdentityReceipt(sessions[0].receipt, sessions[0].expected);
  const tenant = inspectTenantReceipt(sessions[1].receipt, sessions[1].expected);
  const activity = inspectActivityReceipt(sessions[2].receipt, sessions[2].expected);
  const requirements = [{ circuitId: 'identity-v1', publicInputs: [
    ...digest(identity.responseHash), identity.responseLength, ...digest(first.challenge),
    ...digest(bundle.bindings.identityBinding),
  ].map(field) }];
  requirements.push(...headerProofExpectations(identity.headerObligations));
  requirements.push(...activityProofExpectations(tenant, activity, first, bundle.bindings, bundle.claim).proofs);
  if (requirements.length > 128) fail();
  return requirements;
}

/** The caller owns native delivery, attempt ownership, cancellation and atomic replay consumption.
 * runtime must verify with application-pinned keys. No partial or configuration-change claim exists.
 */
export async function verifyAzureBundle({ sessions, bundle, runtime, now = Date.now() }) {
  try {
    const owned = sanitizeAzurePrivateResult(bundle);
    if (typeof runtime?.verify !== 'function') fail();
    const expectations = azureBundleExpectations(sessions, owned, now);
    if (owned.proofs.length !== expectations.length) fail();
    for (let i = 0; i < expectations.length; i++) {
      const entry = owned.proofs[i], expected = expectations[i], values = azureProofFields(entry);
      if (entry.circuitId !== expected.circuitId || values.length !== expected.publicInputs.length ||
          values.some((value, index) => value !== BigInt(expected.publicInputs[index]))) fail();
    }
    for (let i = 0; i < expectations.length; i++) {
      if (await runtime.verify(owned.proofs[i], expectations[i].publicInputs) !== true) fail();
    }
    return { claim: owned.claim, attribution: 'signed-in-user', windowDays: 14 };
  } catch { fail(); }
}
