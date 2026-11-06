import { createAzurePrivatePlan } from './browser-plan.mjs';
import { validateAzureAttempt, azureProofFields, sanitizeAzurePrivateResult } from './browser-result.mjs';
export { validateAzureAttempt, sanitizeAzurePrivateResult } from './browser-result.mjs';

const error = () => new Error('AZURE_PRIVATE_PROVING_FAILED');
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

/** Constructed only by compiled offscreen code; never accept a page-supplied worker URL. */
export function createAzurePrivateModule({ attempt, workerUrl, onProgress }) {
  validateAzureAttempt(attempt);
  let url;
  try {
    const location = new URL(globalThis.location.href);
    url = new URL(workerUrl, location);
    if (!['chrome-extension:', 'moz-extension:'].includes(location.protocol) || url.protocol !== location.protocol ||
        url.hostname !== location.hostname || url.port !== location.port || url.origin !== location.origin ||
        url.pathname !== '/azure-private/browser-worker.js' || url.username || url.password || url.search || url.hash) throw error();
  } catch { throw error(); }
  if (onProgress !== undefined && typeof onProgress !== 'function') throw error();
  let worker, pending, closed = false, proving = false, completedProofs = 0, totalProofs, controller, deadline;
  const terminate = () => {
    worker?.terminate(); worker = undefined;
    if (pending) { const current = pending; pending = undefined; current.cleanup(); current.reject(error()); }
  };
  const progress = () => { if (totalProofs === undefined) return; try { onProgress?.({ completedProofs, totalProofs }); } catch { /* Observers cannot change proof validity. */ } };
  const proveCircuit = (circuitId, inputs, signal, plannedTotal) => {
    if (closed || pending || !signal || signal.aborted || !Number.isInteger(plannedTotal) || plannedTotal < 1 || plannedTotal > 128 ||
        completedProofs >= plannedTotal || totalProofs !== undefined && totalProofs !== plannedTotal) return Promise.reject(error());
    if (totalProofs === undefined) { totalProofs = plannedTotal; progress(); }
    return new Promise((resolve, reject) => {
      let timer;
      const abort = () => terminate();
      try {
        const id = crypto.randomUUID();
        pending = { id, circuitId, resolve, reject, cleanup: () => {
          clearTimeout(timer); signal.removeEventListener('abort', abort);
        } };
        if (!worker) {
          worker = new Worker(url, { type: 'module' });
          worker.addEventListener('error', terminate);
          worker.addEventListener('messageerror', terminate);
          worker.addEventListener('message', event => {
            const message = event.data, current = pending;
            try {
              if (!current || !exact(message, ['id', 'ok', 'entry']) || message.id !== current.id ||
                  message.ok !== true || message.entry?.circuitId !== current.circuitId) throw error();
              azureProofFields(message.entry);
            } catch { terminate(); return; }
            pending = undefined; current.cleanup();
            completedProofs++; progress();
            current.resolve({ circuitId: message.entry.circuitId, proof: message.entry.proof,
              publicInputs: [...message.entry.publicInputs] });
          });
        }
        signal.addEventListener('abort', abort, { once: true });
        timer = setTimeout(terminate, 180000);
        worker.postMessage({ id, circuitId, inputs, final: completedProofs + 1 === plannedTotal });
      } catch { terminate(); reject(error()); }
    });
  };
  const local = createAzurePrivatePlan({ attempt: { ...attempt }, proveCircuit });
  const expiresAt = attempt.expiresAt;
  const clear = () => { closed = true; clearTimeout(deadline); controller?.abort(); terminate(); local.clear(); };
  deadline = setTimeout(clear, Math.max(0, expiresAt - Date.now()));
  return {
    getRevealPlan: (...args) => { if (closed || proving) throw error(); return local.getRevealPlan(...args); },
    clear,
    async prove(witnesses, signal) {
      if (closed || proving || !signal || signal.aborted) { clear(); throw error(); }
      proving = true; controller = new AbortController();
      const abort = () => controller.abort();
      signal.addEventListener('abort', abort, { once: true });
      progress();
      try {
        const result = sanitizeAzurePrivateResult(await local.prove(witnesses, controller.signal));
        terminate();
        // shortcut: measured Chromium teardown needs a grace period; replace with an exit acknowledgement when available.
        await new Promise((resolve, reject) => {
          const cancelled = () => { clearTimeout(timer); controller.signal.removeEventListener('abort', cancelled); reject(error()); };
          const timer = setTimeout(() => { controller.signal.removeEventListener('abort', cancelled); resolve(); }, 5000);
          controller.signal.addEventListener('abort', cancelled, { once: true });
          if (controller.signal.aborted) cancelled();
        });
        return result;
      }
      catch { throw error(); }
      finally { signal.removeEventListener('abort', abort); clear(); }
    },
  };
}
