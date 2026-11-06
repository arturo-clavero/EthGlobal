import { Noir } from '@noir-lang/noir_js';
import { Barretenberg, BackendType, UltraHonkBackend, UltraHonkVerifierBackend } from '@aztec/bb.js';
import { loadAzureCircuit, azureProofOptions } from './browser-artifacts.mjs';
import { azureProofFields, eraseAzureInputs } from './browser-result.mjs';

let busy = false, api;
async function packaged(file) {
  const response = await fetch(new URL(`./artifacts/${file}`, self.location.href));
  if (!response.ok) throw new Error('AZURE_PRIVATE_ARTIFACT_INVALID');
  return new Uint8Array(await response.arrayBuffer());
}
// Request child-worker shutdown before returning the final proof; the parent still terminates this worker.
self.onmessage = async ({ data }) => {
  const id = typeof data?.id === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(data.id) ? data.id : null;
  if (!id || busy || !data || Reflect.ownKeys(data).length !== 4 || typeof data.final !== 'boolean' ||
      !['id', 'circuitId', 'inputs', 'final'].every(key => Object.hasOwn(data, key))) {
    eraseAzureInputs(data?.inputs);
    self.postMessage({ id, ok: false, error: 'AZURE_PRIVATE_PROVING_FAILED' }); return;
  }
  busy = true;
  let witness;
  try {
    const { circuit, verificationKey } = await loadAzureCircuit(data.circuitId, packaged);
    ({ witness } = await new Noir(circuit).execute(data.inputs));
    api ??= await Barretenberg.new({ backend: BackendType.Wasm, threads: 2, memory: { maximum: 32768 } });
    const proof = await new UltraHonkBackend(circuit.bytecode, api).generateProof(witness, azureProofOptions);
    if (!await new UltraHonkVerifierBackend(api).verifyProof({ ...proof, verificationKey }, azureProofOptions)) throw new Error();
    const entry = { circuitId: data.circuitId,
      proof: btoa(String.fromCharCode(...proof.proof)), publicInputs: [...proof.publicInputs] };
    azureProofFields(entry);
    witness.fill(0); witness = undefined; eraseAzureInputs(data.inputs);
    if (data.final) { const finishedApi = api; api = undefined; await finishedApi.destroy(); }
    self.postMessage({ id, ok: true, entry });
  } catch {
    // The parent terminates this worker even if runtime cleanup fails.
    if (api) await api.destroy().catch(() => {});
    api = undefined;
    self.postMessage({ id, ok: false, error: 'AZURE_PRIVATE_PROVING_FAILED' });
  } finally {
    witness?.fill(0); eraseAzureInputs(data.inputs);
    busy = false;
  }
};
