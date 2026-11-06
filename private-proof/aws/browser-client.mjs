import { createAwsPrivateClient } from './client.mjs';
import { awsProofFields, sanitizeAwsPrivateResult } from './verify-bundle.mjs';
export { sanitizeAwsPrivateResult } from './verify-bundle.mjs';
export { validateAwsAttempt } from './authenticated-transcript.mjs';
export { createAwsLocalSession, awsPrivateCredentials, readAwsPrivateResponse } from './browser-session.mjs';
export { awsConsoleSession } from './console-session.mjs';

const error = () => new Error('AWS_PRIVATE_PROVING_FAILED');
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

/** Constructed by the pinned offscreen runner, never by page messages. */
export function createAwsPrivateModule({ attempt, workerUrl, onProgress }) {
  let url;
  try {
    const location = new URL(globalThis.location.href);
    url = new URL(workerUrl, location);
    if (!['chrome-extension:', 'moz-extension:'].includes(location.protocol) || url.protocol !== location.protocol ||
        url.hostname !== location.hostname || url.port !== location.port || url.origin !== location.origin ||
        url.pathname !== '/aws-private/browser-worker.js' || url.username || url.password || url.search || url.hash) throw error();
  } catch { throw error(); }
  if (onProgress !== undefined && typeof onProgress !== 'function') throw error();
  let worker, pending, closed = false, completedProofs = 0, controller, deadline;
  const terminate = () => {
    worker?.terminate(); worker = undefined;
    if (pending) { const current = pending; pending = undefined; current.cleanup(); current.reject(error()); }
  };
  const progress = () => { try { onProgress?.({ completedProofs }); } catch { /* UI observers cannot affect proof validity. */ } };
  const proveCircuit = (circuitId, inputs, signal) => {
    if (closed || pending || signal.aborted) return Promise.reject(error());
    if (!worker) {
      try {
        worker = new Worker(url, { type: 'module' });
        worker.addEventListener('error', terminate);
        worker.addEventListener('messageerror', terminate);
        worker.addEventListener('message', event => {
          const message = event.data, current = pending;
          try {
            if (!current || !message || message.id !== current.id || !exact(message, ['id', 'ok', 'entry']) || message.ok !== true ||
                message.entry?.circuitId !== current.circuitId) throw error();
            awsProofFields(message.entry);
          } catch { terminate(); return; }
          pending = undefined; current.cleanup(); completedProofs++; progress();
          current.resolve({ circuitId: message.entry.circuitId, proof: message.entry.proof, publicInputs: [...message.entry.publicInputs] });
        });
      } catch { terminate(); return Promise.reject(error()); }
    }
    return new Promise((resolve, reject) => {
      const abort = () => terminate();
      try {
        pending = { id: crypto.randomUUID(), circuitId, resolve, reject, cleanup: () => signal.removeEventListener('abort', abort) };
        signal.addEventListener('abort', abort, { once: true });
        worker.postMessage({ id: pending.id, circuitId, inputs });
      } catch { terminate(); reject(error()); }
    });
  };
  const local = createAwsPrivateClient({ attempt, proveCircuit });
  const expiresAt = attempt.expiresAt;
  attempt = undefined;
  const clear = () => { closed = true; clearTimeout(deadline); controller?.abort(); terminate(); local.clear(); };
  // Expiry must stop a hung CPU worker, not merely reject its eventual result.
  deadline = setTimeout(clear, Math.max(0, expiresAt - Date.now()));
  return {
    getRevealPlan: (...args) => { if (closed) throw error(); return local.getRevealPlan(...args); },
    clear,
    async prove(witnesses, signal) {
      if (closed || controller || !signal || signal.aborted) { clear(); throw error(); }
      controller = new AbortController();
      const abort = () => controller.abort();
      signal.addEventListener('abort', abort, { once: true });
      progress();
      try { return sanitizeAwsPrivateResult(await local.prove(witnesses, controller.signal)); }
      catch { throw error(); }
      finally { signal.removeEventListener('abort', abort); clear(); }
    },
  };
}
