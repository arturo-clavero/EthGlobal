import { proofRuntimeFactory } from './proof-runtime-core.mjs';
import { pinnedVerificationKey } from './verification-key-registry.mjs';

export const createProofRuntime = proofRuntimeFactory({
  ids: ['header-v1', 'atom-v1', 'headers-small-v1', 'atoms-small-v1', 'timestamps-v1', 'identity-scope-v1', 'query-scope-v1'],
  invalidCode: 'GCP_PRIVATE_PROOF_INVALID', provingCode: 'GCP_PRIVATE_PROVING_FAILED',
  keyForCircuit: pinnedVerificationKey, threads: 4,
});
