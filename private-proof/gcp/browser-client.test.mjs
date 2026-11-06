import test, { beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createGcpPrivateModule } from './browser-client.mjs';
import { fixture, committed, projectId, policy, email, mockPublicInputs } from './client-fixture.mjs';

const workerUrl = 'chrome-extension://private-extension/gcp-private/browser-worker.js';
const previous = new Map(['location', 'Worker', 'crypto'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
let instances, behavior;
class SyntheticWorker extends EventTarget {
  constructor(url, options) {
    super(); this.url = String(url); this.options = options; this.messages = []; this.terminated = false;
    instances.push(this);
  }
  postMessage(message) {
    const copy = structuredClone(message); this.messages.push(copy);
    queueMicrotask(() => behavior(this, copy));
  }
  respond(data) { this.dispatchEvent(new MessageEvent('message', { data })); }
  terminate() { this.terminated = true; }
}
beforeEach(() => {
  instances = [];
  behavior = (worker, message) => worker.respond({ id: message.id, ok: true, entry: {
    circuitId: message.circuitId, proof: 'YQ==', publicInputs: mockPublicInputs(message.circuitId, message.inputs),
  } });
  for (const [key, value] of Object.entries({ location: { href: 'chrome-extension://private-extension/offscreen.html' },
    Worker: SyntheticWorker, crypto: webcrypto })) Object.defineProperty(globalThis, key, { configurable: true, value });
});
afterEach(() => {
  for (const [key, descriptor] of previous) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else delete globalThis[key];
  }
});
function ready(onProgress) {
  const witnesses = fixture().map(committed);
  const module = createGcpPrivateModule({ projectId, policy, workerUrl, onProgress });
  assert.equal(module.identityEmail(witnesses[0]), email);
  return { module, witnesses };
}

test('packaged module worker starts lazily, uses serial exact RPC, and terminates after completion', async () => {
  const progress = [], { module, witnesses } = ready(value => progress.push(value));
  assert.equal(instances.length, 0);
  const result = await module.prove(witnesses, new AbortController().signal);
  assert.equal(result.proofs.length, 20);
  assert.equal(instances.length, 1);
  assert.equal(instances[0].url, workerUrl);
  assert.deepEqual(instances[0].options, { type: 'module' });
  assert.equal(instances[0].terminated, true);
  assert.equal(instances[0].messages.length, 20);
  assert.equal(new Set(instances[0].messages.map(message => message.id)).size, 20);
  assert(instances[0].messages.every(message => Object.keys(message).sort().join(',') === 'circuitId,id,inputs'));
  assert.deepEqual(progress, Array.from({ length: 21 }, (_, completedProofs) => ({ completedProofs })));
  assert.throws(() => module.identityEmail(witnesses[0]), /GCP_PRIVATE_PROVING_FAILED/);
});

test('cross-extension, remote, blob and unexpected packaged worker locations are rejected', () => {
  for (const url of ['chrome-extension://other/gcp-private/browser-worker.js', 'https://example.invalid/worker.js',
    'blob:chrome-extension://private-extension/fake', 'chrome-extension://private-extension/other.js', `${workerUrl}?private=value`, `${workerUrl}#x`]) {
    assert.throws(() => createGcpPrivateModule({ projectId, policy, workerUrl: url }), /GCP_PRIVATE_PROVING_FAILED/);
  }
  assert.equal(instances.length, 0);
});

test('abort terminates a busy worker and prevents a late reply completing the proof', async () => {
  const controller = new AbortController();
  behavior = (worker, message) => {
    controller.abort();
    worker.respond({ id: message.id, ok: true, entry: { circuitId: message.circuitId, proof: 'YQ==',
      publicInputs: mockPublicInputs(message.circuitId, message.inputs) } });
  };
  const { module, witnesses } = ready();
  await assert.rejects(module.prove(witnesses, controller.signal), /GCP_PRIVATE_PROVING_FAILED/);
  assert.equal(instances[0].terminated, true);
  assert.equal(instances[0].messages.length, 1);
});

test('clear drops local input access and terminates any pending worker', async () => {
  const { module, witnesses } = ready();
  behavior = () => module.clear();
  await assert.rejects(module.prove(witnesses, new AbortController().signal), /GCP_PRIVATE_PROVING_FAILED/);
  assert.equal(instances[0].terminated, true);
  assert.throws(() => module.getRevealPlan(witnesses[0], witnesses[0]), /GCP_PRIVATE_PROVING_FAILED/);
});

test('wrong request IDs, extra witness fields, malformed result and worker errors fail closed', async () => {
  for (const response of [
    (message, entry) => ({ id: 'wrong', ok: true, entry }),
    (message, entry) => ({ id: message.id, ok: true, entry, witness: 'private' }),
    (message, entry) => ({ id: message.id, ok: true, entry: { ...entry, private: 'private' } }),
    (message, entry) => ({ id: message.id, ok: true, entry: { ...entry, proof: 'invalid!' } }),
    (message, entry) => ({ id: message.id, ok: true, entry: { ...entry, publicInputs: ['private'] } }),
    message => ({ id: message.id, ok: false, error: 'private exception text' }),
    message => ({ id: message.id, ok: false, error: 'GCP_PRIVATE_PROVING_FAILED' }),
  ]) {
    behavior = (worker, message) => worker.respond(response(message, { circuitId: message.circuitId,
      proof: 'YQ==', publicInputs: mockPublicInputs(message.circuitId, message.inputs) }));
    const { module, witnesses } = ready();
    await assert.rejects(module.prove(witnesses, new AbortController().signal), /GCP_PRIVATE_PROVING_FAILED/);
    assert.equal(instances.at(-1).terminated, true);
  }
  for (const event of ['error', 'messageerror']) {
    behavior = worker => worker.dispatchEvent(new Event(event));
    const { module, witnesses } = ready();
    await assert.rejects(module.prove(witnesses, new AbortController().signal), /GCP_PRIVATE_PROVING_FAILED/);
    assert.equal(instances.at(-1).terminated, true);
  }
});
