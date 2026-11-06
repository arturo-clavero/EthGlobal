import { Worker } from 'node:worker_threads';
import { azureProofFields } from './browser-result.mjs';

/** One pinned-key check at a time; terminating each worker releases retained WASM memory. */
export function createAzureVerifier() {
  let active, closed = false;
  return {
    async verify(entry, expectedPublicInputs) {
      if (closed || active) return false;
      try {
        const values = azureProofFields(entry);
        if (!Array.isArray(expectedPublicInputs) || values.length !== expectedPublicInputs.length ||
            values.some((value, index) => value !== BigInt(expectedPublicInputs[index]))) return false;
        const worker = new Worker(new URL('./verifier-worker.mjs', import.meta.url), {
          workerData: { entry, expectedPublicInputs },
        });
        active = worker;
        try {
          return await new Promise(resolve => {
            let settled = false;
            const finish = value => {
              if (settled) return;
              settled = true; clearTimeout(timer); resolve(value === true);
            };
            const timer = setTimeout(() => finish(false), 180000);
            worker.once('message', finish);
            worker.once('error', () => finish(false));
            worker.once('exit', () => finish(false));
          });
        } finally { await worker.terminate(); if (active === worker) active = undefined; }
      } catch { return false; }
    },
    async close() { closed = true; if (active) await active.terminate(); },
  };
}
