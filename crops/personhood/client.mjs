// Browser side: builds the World ID request for one job application, bound to the evidence commitment.
import { any, CredentialRequest, IDKit } from '@worldcoin/idkit-core';

export const CREDENTIALS = Object.freeze(['proof_of_human', 'passport']);
const PRESETS = { any: CREDENTIALS, proof_of_human: ['proof_of_human'], passport: ['passport'] };
const fail = reason => { throw new Error(`PERSONHOOD_INVALID: ${reason}`); };

export const jobAction = jobId => {
  if (typeof jobId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(jobId)) fail('jobId');
  return `apply:${jobId}`;
};

/**
 * Pure request description. Uniqueness only: the passport credential is requested as a proof of one human, never its
 * attributes (nationality, age, country) — no identityCheck, no attribute constraints.
 */
export function worldIdRequestConfig({ appId, action, signal, rpContext, preset = 'any', environment = 'production' } = {}) {
  if (typeof appId !== 'string' || !/^app_[A-Za-z0-9_]+$/.test(appId)) fail('appId');
  if (typeof action !== 'string' || !/^apply:[A-Za-z0-9_-]{1,64}$/.test(action)) fail('action');
  if (typeof signal !== 'string' || !/^[0-9a-f]{64}$/.test(signal)) fail('signal must be 64 hex characters');
  const { rp_id, nonce, created_at, expires_at, signature } = rpContext ?? {};
  if (typeof rp_id !== 'string' || !rp_id.startsWith('rp_') || typeof nonce !== 'string' || typeof signature !== 'string' ||
      !Number.isSafeInteger(created_at) || !Number.isSafeInteger(expires_at) || expires_at <= created_at) fail('rpContext');
  if (!Object.hasOwn(PRESETS, preset)) fail('preset');
  if (!['production', 'staging'].includes(environment)) fail('environment');
  const requests = PRESETS[preset].map(type => CredentialRequest(type, { signal }));
  return {
    config: { app_id: appId, action, rp_context: { rp_id, nonce, created_at, expires_at, signature },
      allow_legacy_proofs: false, environment },
    constraints: requests.length === 1 ? requests[0] : any(...requests),
  };
}

/** Starts the IDKit request; show `request.connectorURI` and await `request.pollUntilCompletion()`. */
export async function worldIdRequest(options, { idkit = IDKit } = {}) {
  const { config, constraints } = worldIdRequestConfig(options);
  return idkit.request(config).constraints(constraints);
}
