import { loadPinnedArtifacts } from './artifact-registry.mjs';
import { createProofRuntime } from './proof-runtime.mjs';

let runtime, busy = false;
function erase(value) {
  if (ArrayBuffer.isView(value)) { value.fill(0); return; }
  if (!value || typeof value !== 'object') return;
  for (const key of Object.keys(value)) {
    erase(value[key]);
    if (Array.isArray(value)) value[key] = 0;
    else delete value[key];
  }
}
self.onmessage = async ({ data }) => {
  const id = typeof data?.id === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(data.id) ? data.id : null;
  if (!id || busy || Object.keys(data).length !== 3 ||
      !['id', 'circuitId', 'inputs'].every(key => Object.hasOwn(data, key))) {
    erase(data?.inputs);
    self.postMessage({ id, ok: false, error: 'GCP_PRIVATE_PROVING_FAILED' });
    return;
  }
  busy = true;
  try {
    runtime ??= await createProofRuntime(await loadPinnedArtifacts(async file => {
      const response = await fetch(new URL(`./artifacts/${file}`, self.location.href));
      if (!response.ok) throw new Error('GCP_PRIVATE_ARTIFACT_INVALID');
      return new Uint8Array(await response.arrayBuffer());
    }));
    const entry = await runtime.prove(data.circuitId, data.inputs);
    self.postMessage({ id, ok: true, entry });
  } catch {
    self.postMessage({ id, ok: false, error: 'GCP_PRIVATE_PROVING_FAILED' });
  } finally { erase(data.inputs); busy = false; }
};
