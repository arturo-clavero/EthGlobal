import { createGcpPrivateClient } from './client-plan.mjs';

const error = () => new Error('GCP_PRIVATE_PROVING_FAILED');
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

/** Only the pinned offscreen runner constructs this module, never page messages. */
export function createGcpPrivateModule({ projectId, policy, workerUrl, onProgress }) {
  let url;
  try {
    const location = new URL(globalThis.location.href);
    url = new URL(workerUrl, location);
    if (!['chrome-extension:', 'moz-extension:'].includes(location.protocol) || url.protocol !== location.protocol ||
        url.hostname !== location.hostname || url.port !== location.port || url.origin !== location.origin ||
        url.pathname !== '/gcp-private/browser-worker.js' || url.username || url.password || url.search || url.hash) throw error();
  } catch { throw error(); }
  if (onProgress !== undefined && typeof onProgress !== 'function') throw error();
  let worker, pending, closed = false, completedProofs = 0, controller;
  const terminate = () => {
    worker?.terminate(); worker = undefined;
    if (pending) { const current = pending; pending = undefined; current.cleanup(); current.reject(error()); }
  };
  const progress = () => { try { onProgress?.({ completedProofs }); } catch { /* Local UI observers cannot affect proof validity. */ } };
  const proveCircuit = (circuitId, inputs, signal) => {
    if (closed || pending || signal.aborted) return Promise.reject(error());
    if (!worker) {
      try {
        worker = new Worker(url, { type: 'module' });
        worker.addEventListener('error', terminate);
        worker.addEventListener('messageerror', terminate);
        worker.addEventListener('message', event => {
          const message = event.data, current = pending;
          if (!current || !message || message.id !== current.id ||
              !(message.ok === true ? exact(message, ['id', 'ok', 'entry']) :
                message.ok === false && exact(message, ['id', 'ok', 'error']) && message.error === 'GCP_PRIVATE_PROVING_FAILED')) {
            terminate(); return;
          }
          if (!message.ok || !exact(message.entry, ['circuitId', 'proof', 'publicInputs']) ||
              message.entry.circuitId !== current.circuitId || typeof message.entry.proof !== 'string' ||
              !message.entry.proof.length || message.entry.proof.length > 32768 ||
              !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(message.entry.proof) ||
              !Array.isArray(message.entry.publicInputs) || !message.entry.publicInputs.length || message.entry.publicInputs.length > 1024 ||
              message.entry.publicInputs.some(value => typeof value !== 'string' || !/^(?:0x[0-9a-f]{1,64}|0|[1-9][0-9]{0,19})$/.test(value))) {
            terminate(); return;
          }
          pending = undefined; current.cleanup(); completedProofs++; progress();
          current.resolve({ circuitId: message.entry.circuitId, proof: message.entry.proof, publicInputs: [...message.entry.publicInputs] });
        });
      } catch { terminate(); return Promise.reject(error()); }
    }
    return new Promise((resolve, reject) => {
      const abort = () => terminate();
      signal.addEventListener('abort', abort, { once: true });
      pending = { id: crypto.randomUUID(), circuitId, resolve, reject, cleanup: () => signal.removeEventListener('abort', abort) };
      try { worker.postMessage({ id: pending.id, circuitId, inputs }); }
      catch { terminate(); }
    });
  };
  const local = createGcpPrivateClient({ projectId, policy, proveCircuit });
  // The factory argument must not remain captured after local module construction.
  projectId = undefined;
  const clear = () => { closed = true; controller?.abort(); terminate(); local.clear(); };
  return {
    getRevealPlan: (...args) => { if (closed) throw error(); return local.getRevealPlan(...args); },
    identityEmail: (...args) => { if (closed) throw error(); return local.identityEmail(...args); },
    clear,
    async prove(witnesses, signal) {
      if (closed || controller || !signal || signal.aborted) { clear(); throw error(); }
      controller = new AbortController();
      const abort = () => controller.abort();
      signal.addEventListener('abort', abort, { once: true });
      progress();
      try { return await local.prove(witnesses, controller.signal); }
      catch { throw error(); }
      finally { signal.removeEventListener('abort', abort); clear(); }
    },
  };
}
