import { parentPort, workerData } from 'node:worker_threads';
import { Barretenberg, BackendType, UltraHonkVerifierBackend } from '@aztec/bb.js';
import { verificationKey, proofOptions } from './artifacts.mjs';
import { azureProofFields } from './browser-result.mjs';

let api, accepted = false;
try {
  const { entry, expectedPublicInputs } = workerData;
  const values = azureProofFields(entry);
  if (!Array.isArray(expectedPublicInputs) || values.length !== expectedPublicInputs.length ||
      values.some((value, index) => value !== BigInt(expectedPublicInputs[index]))) throw new Error('INVALID_PROOF');
  const key = verificationKey(entry.circuitId);
  api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1, memory: { maximum: 32768 } });
  accepted = await new UltraHonkVerifierBackend(api).verifyProof({
    proof: new Uint8Array(Buffer.from(entry.proof, 'base64')), publicInputs: expectedPublicInputs,
    verificationKey: key,
  }, proofOptions);
} catch { accepted = false; }
finally { if (api) await api.destroy(); }
parentPort.postMessage(accepted === true);

