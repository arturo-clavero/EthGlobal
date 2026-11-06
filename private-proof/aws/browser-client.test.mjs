import test, { beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createAwsPrivateModule } from './browser-client.mjs';
import { identityFixture } from './identity-fixture.mjs';
import { eventFixture, fixtureNow, syntheticWitness } from './event-fixture.mjs';
import { loadAwsArtifacts } from './artifact-registry.mjs';

const artifacts = await loadAwsArtifacts(file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url)));
const workerUrl = 'chrome-extension://private-extension/aws-private/browser-worker.js';
const previous = new Map(['location', 'Worker', 'crypto'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
const failure = { message: 'AWS_PRIVATE_PROVING_FAILED' };
let instances, behavior;
function entry({ circuitId, inputs }) {
  const abi = artifacts[circuitId].abi;
  const fields = abi.parameters.filter(p => p.visibility === 'public').flatMap(p => [inputs[p.name]].flat(Infinity));
  if (abi.return_type) {
    const bytes = inputs.decoded_preimage ?? inputs.preimage, length = inputs.decoded_length ?? inputs.length;
    const value = JSON.parse(Buffer.from(bytes.slice(0, length)).toString());
    fields.push(value === null ? 5 : value === false ? 4 : value === true ? 3 : typeof value === 'number' ? 2 : 1);
  }
  return { circuitId, proof: 'AA==', publicInputs: fields.map(String) };
}
class SyntheticWorker extends EventTarget {
  constructor(url, options) {
    super(); this.url = String(url); this.options = options; this.messages = []; this.terminated = false;
    instances.push(this);
  }
  postMessage(message) { const copy = structuredClone(message); this.messages.push(copy); queueMicrotask(() => behavior(this, copy)); }
  respond(data) { this.dispatchEvent(new MessageEvent('message', { data })); }
  terminate() { this.terminated = true; }
}
beforeEach(context => {
  context.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: fixtureNow });
  instances = [];
  behavior = (worker, message) => worker.respond({ id: message.id, ok: true, entry: entry(message) });
  for (const [key, value] of Object.entries({ location: { href: 'chrome-extension://private-extension/offscreen.html' },
    Worker: SyntheticWorker, crypto: webcrypto })) Object.defineProperty(globalThis, key, { configurable: true, value });
});
afterEach(() => {
  for (const [key, descriptor] of previous) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else delete globalThis[key];
  }
});
function ready(options = {}) {
  const identity = identityFixture(), event = eventFixture({ mutateEvent: value => {
    value.userIdentity.arn = 'arn:aws:iam::111122223333:user/engineering/AWS_PRIVATE_USER_SENTINEL';
  } });
  event.receipt.session.id = '33333333-3333-4333-8333-333333333333';
  const witnesses = [identity, event].map(syntheticWitness);
  return { witnesses, module: createAwsPrivateModule({ attempt: identity.expected, workerUrl, ...options }) };
}

test('starts one packaged worker lazily, proves serially, and terminates on completion', async () => {
  const progress = [], { module, witnesses } = ready({ onProgress: value => progress.push(value) });
  for (const witness of witnesses) assert.deepEqual(module.getRevealPlan(witness, witness), {
    sentRangesWithHandlers: witness.selections.sent, recvRangesWithHandlers: witness.selections.recv });
  assert.equal(instances.length, 0);
  const bundle = await module.prove(witnesses, new AbortController().signal);
  assert.equal(bundle.proofs.length, 10);
  assert.equal(instances.length, 1);
  assert.equal(instances[0].url, workerUrl);
  assert.deepEqual(instances[0].options, { type: 'module' });
  assert.equal(instances[0].terminated, true);
  assert.equal(instances[0].messages.length, 10);
  assert.equal(new Set(instances[0].messages.map(message => message.id)).size, 10);
  assert(instances[0].messages.every(message => Object.keys(message).sort().join(',') === 'circuitId,id,inputs'));
  assert.deepEqual(progress, Array.from({ length: 11 }, (_, completedProofs) => ({ completedProofs })));
  assert.throws(() => module.getRevealPlan(witnesses[0], witnesses[0]), failure);
});

test('rejects remote, cross-extension, blob and unexpected packaged worker URLs', () => {
  for (const url of ['chrome-extension://other/aws-private/browser-worker.js', 'https://example.invalid/worker.js',
    'blob:chrome-extension://private-extension/fake', 'chrome-extension://private-extension/gcp-private/browser-worker.js',
    `${workerUrl}?private=value`, `${workerUrl}#x`]) assert.throws(() => ready({ workerUrl: url }), failure);
  assert.throws(() => ready({ onProgress: 'not-a-function' }), failure);
  assert.equal(instances.length, 0);
});

test('abort and clear terminate busy work, settle promises, and ignore late replies', async () => {
  for (const action of ['abort', 'clear']) {
    const controller = new AbortController(), { module, witnesses } = ready();
    behavior = (worker, message) => {
      if (action === 'abort') controller.abort(); else module.clear();
      worker.respond({ id: message.id, ok: true, entry: entry(message) });
    };
    await assert.rejects(module.prove(witnesses, controller.signal), failure);
    assert.equal(instances.at(-1).terminated, true);
    assert.equal(instances.at(-1).messages.length, 1);
  }
});

test('attempt expiry terminates a hung worker without waiting for its response', async context => {
  const { module, witnesses } = ready();
  behavior = () => context.mock.timers.tick(1001);
  await assert.rejects(module.prove(witnesses, new AbortController().signal), failure);
  assert.equal(instances[0].terminated, true);
  assert.throws(() => module.getRevealPlan(witnesses[0], witnesses[0]), failure);
});

test('pre-aborted and concurrent calls close the module', async () => {
  const controller = new AbortController(); controller.abort();
  const first = ready();
  await assert.rejects(first.module.prove(first.witnesses, controller.signal), failure);
  assert.equal(instances.length, 0);
  const second = ready(), signal = new AbortController().signal;
  const running = assert.rejects(second.module.prove(second.witnesses, signal), failure);
  await assert.rejects(second.module.prove(second.witnesses, signal), failure);
  await running;
  assert.equal(instances.length, 0);
});

test('rejects wrong IDs, extra private fields, malformed outputs, altered public inputs and worker errors', async () => {
  for (const response of [
    (message, proof) => ({ id: 'wrong', ok: true, entry: proof }),
    (message, proof) => ({ id: message.id, ok: true, entry: proof, witness: 'private' }),
    (message, proof) => ({ id: message.id, ok: true, entry: { ...proof, witness: 'private' } }),
    (message, proof) => ({ id: message.id, ok: true, entry: { ...proof, circuitId: 'timestamp-v1' } }),
    (message, proof) => ({ id: message.id, ok: true, entry: { ...proof, proof: 'invalid!' } }),
    (message, proof) => ({ id: message.id, ok: true, entry: { ...proof, publicInputs: ['private'] } }),
    (message, proof) => ({ id: message.id, ok: true, entry: { ...proof, publicInputs: proof.publicInputs.map(() => '0') } }),
    message => ({ id: message.id, ok: false, error: 'private exception text' }),
    message => ({ id: message.id, ok: false, error: 'AWS_PRIVATE_PROVING_FAILED' }),
  ]) {
    behavior = (worker, message) => worker.respond(response(message, entry(message)));
    const { module, witnesses } = ready();
    await assert.rejects(module.prove(witnesses, new AbortController().signal), failure);
    assert.equal(instances.at(-1).terminated, true);
  }
  for (const event of ['error', 'messageerror']) {
    behavior = worker => worker.dispatchEvent(new Event(event));
    const { module, witnesses } = ready();
    await assert.rejects(module.prove(witnesses, new AbortController().signal), failure);
    assert.equal(instances.at(-1).terminated, true);
  }
});
