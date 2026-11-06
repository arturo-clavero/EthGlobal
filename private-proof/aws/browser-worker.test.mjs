import test from 'node:test';
import assert from 'node:assert/strict';

test('worker rejects malformed and overlapping RPC, masks package failures, and erases owned inputs', async () => {
  const previous = new Map(['self', 'fetch'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  const messages = [], scope = { location: { href: 'chrome-extension://test/aws-private/browser-worker.js' }, postMessage: value => messages.push(value) };
  let release, requested;
  try {
    Object.defineProperty(globalThis, 'self', { configurable: true, value: scope });
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: url => {
      requested = String(url); return new Promise(resolve => { release = resolve; });
    } });
    await import('./browser-worker.mjs');
    const malformed = { id: 'bad id', inputs: { preimage: [1, 2, 3], epoch_ms: 123 } };
    await scope.onmessage({ data: malformed });
    assert.deepEqual(malformed.inputs, { preimage: [0, 0, 0], epoch_ms: 0 });
    assert.equal(requested, undefined);
    const first = { id: 'first', circuitId: 'aws-event-link-v1', inputs: { preimage: new Uint8Array([1, 2]) } };
    const running = scope.onmessage({ data: first });
    assert(requested.startsWith('chrome-extension://test/aws-private/artifacts/'));
    const second = { id: 'second', circuitId: first.circuitId, inputs: { preimage: [3, 4] } };
    await scope.onmessage({ data: second });
    assert.deepEqual(second.inputs.preimage, [0, 0]);
    release({ ok: false, private: 'PRIVATE_FAILURE_SENTINEL' });
    await running;
    assert.deepEqual([...first.inputs.preimage], [0, 0]);
    assert.deepEqual(messages, [null, 'second', 'first'].map(id => ({ id, ok: false, error: 'AWS_PRIVATE_PROVING_FAILED' })));
  } finally {
    for (const [key, descriptor] of previous) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key];
    }
  }
});
