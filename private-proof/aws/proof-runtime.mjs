import { proofRuntimeFactory } from '../gcp/proof-runtime-core.mjs';
import { pinnedAwsKey } from './artifact-registry.mjs';

const create = proofRuntimeFactory({
  ids: ['header-v1', 'atom-v1', 'headers-small-v1', 'atoms-small-v1', 'aws-xml-text-v1',
    'aws-escaped-atom-v1', 'aws-escaped-atoms-small-v1', 'aws-escaped-atom-small-v1', 'aws-identity-link-v1', 'aws-event-link-v1'],
  invalidCode: 'AWS_PRIVATE_PROOF_INVALID', provingCode: 'AWS_PRIVATE_PROVING_FAILED',
  keyForCircuit: pinnedAwsKey, threads: 1,
});

export async function createAwsProofRuntime(artifacts, pinnedKeys) {
  // AWS verification always requires packaged keys, including in component callers.
  pinnedAwsKey(pinnedKeys, 'aws-event-link-v1');
  return create(artifacts, pinnedKeys);
}
