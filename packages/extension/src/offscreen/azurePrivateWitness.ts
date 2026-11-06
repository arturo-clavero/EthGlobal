import { PrivateWitnessRun, type PrivateProofModule } from './gcpPrivateWitness';
import { sanitizeAzurePrivateResult, validateAzureAttempt } from '../azure-private/browser-result.mjs';

/** Compiled capability only; neither this policy nor its proof module comes from page data. */
export function createAzurePrivateRun(run: Record<string, string>, requestId: string | null,
  module: PrivateProofModule, rawAttempt: unknown) {
  const attempt = validateAzureAttempt(rawAttempt);
  if (attempt.proofId !== requestId || attempt.proofId !== run.proofId || attempt.pluginSha256 !== run.pluginSha256) {
    module.clear?.(); throw new Error('AZURE_PRIVATE_RUN_INVALID');
  }
  return new PrivateWitnessRun(run, requestId, module, {
    method: 'AZURE_WORK_PRIVATE', nonceMac: attempt.nonceMac,
    steps: [{ step: 'identity', host: 'graph.microsoft.com' },
      { step: 'tenant', host: 'management.azure.com' }, { step: 'activity', host: 'management.azure.com' }],
    proveTimeoutMs: Math.min(3_600_000, attempt.expiresAt - Date.now()),
    finish(raw, sessionIds) {
      validateAzureAttempt(attempt);
      const result = sanitizeAzurePrivateResult(raw);
      if (JSON.stringify(result.sessionIds) !== JSON.stringify(sessionIds)) throw new Error('AZURE_PRIVATE_RUN_INVALID');
      return result;
    },
  });
}
