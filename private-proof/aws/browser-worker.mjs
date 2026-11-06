import { loadAwsArtifacts, loadAwsVerificationKeys } from './artifact-registry.mjs';
import { createAwsProofRuntime } from './proof-runtime.mjs';
import { eraseAwsInputs } from './circuit-inputs.mjs';

let runtime, busy = false;
async function packaged(file) {
  const response = await fetch(new URL(`./artifacts/${file}`, self.location.href));
  if (!response.ok) throw new Error('AWS_PRIVATE_ARTIFACT_INVALID');
  return new Uint8Array(await response.arrayBuffer());
}
self.onmessage = async ({ data }) => {
  const id = typeof data?.id === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(data.id) ? data.id : null;
  if (!id || busy || !data || Object.keys(data).length !== 3 ||
      !['id', 'circuitId', 'inputs'].every(key => Object.hasOwn(data, key))) {
    eraseAwsInputs(data?.inputs);
    self.postMessage({ id, ok: false, error: 'AWS_PRIVATE_PROVING_FAILED' });
    return;
  }
  busy = true;
  try {
    runtime ??= await createAwsProofRuntime(await loadAwsArtifacts(packaged), await loadAwsVerificationKeys(packaged));
    const entry = await runtime.prove(data.circuitId, data.inputs);
    self.postMessage({ id, ok: true, entry });
  } catch {
    self.postMessage({ id, ok: false, error: 'AWS_PRIVATE_PROVING_FAILED' });
  } finally { eraseAwsInputs(data.inputs); busy = false; }
};
