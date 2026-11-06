import { describe, it, expect } from 'vitest';
import { GCP_PRIVATE_ROUTE_TTL_MS, liveGcpPrivateRoute, takeGcpPrivateCompletion, type GcpPrivateRoute } from '../../src/background/gcpPrivateCompletion';
import { sanitizeGcpPrivateResult } from '../../src/offscreen/gcpPrivateResult';

const extensionId = 'private-extension', offscreenUrl = `chrome-extension://${extensionId}/offscreen.html`;
const sender = { id: extensionId, url: offscreenUrl };
const deps = { extensionId, offscreenUrl, now: 1000 };
const route = (): GcpPrivateRoute => ({ tabId: 8, createdAt: 100, pageProgress: true, gcpPrivate: true });
const routes = () => new Map([['run-1', route()]]);
const result = () => ({ kind: 'GCP_PRIVATE_RESULT', version: 1,
  proofs: ['header-v1', 'atom-v1', 'headers-small-v1', 'atoms-small-v1', 'timestamps-v1', 'identity-scope-v1', 'query-scope-v1']
    .map(circuitId => ({ circuitId, proof: 'AQID', publicInputs: ['0x01', '2'] })),
  sessionIds: Array.from({ length: 6 }, (_, index) => `11111111-1111-4111-8111-11111111111${index}`) });
const message = () => ({ type: 'GCP_PRIVATE_COMPLETE', requestId: 'run-1', success: true, result: result() });

describe('GCP asynchronous completion route', () => {
  it('accepts only the approved tab route, copies seven registered proof types and consumes once', () => {
    const map = routes(), raw = message();
    const completion = takeGcpPrivateCompletion(raw, sender, map, deps);
    expect(completion).toEqual({ requestId: 'run-1', tabId: 8, response: { success: true, result: raw.result } });
    raw.result.proofs[0].publicInputs[0] = 'changed';
    expect(completion?.response.success && completion.response.result.proofs[0].publicInputs[0]).toBe('0x01');
    expect(map.size).toBe(0);
    expect(takeGcpPrivateCompletion(message(), sender, map, deps)).toBeNull();
  });

  it('rejects content scripts, other extensions and other extension pages without deleting an active route', () => {
    for (const bad of [{ ...sender, id: 'other' }, { ...sender, tab: { id: 8 } }, { id: extensionId },
      { ...sender, url: `chrome-extension://${extensionId}/popup.html` }, {}]) {
      const map = routes();
      expect(takeGcpPrivateCompletion(message(), bad, map, deps)).toBeNull();
      expect(liveGcpPrivateRoute('run-1', bad, map, deps)).toBeNull();
      expect(map.size).toBe(1);
    }
  });

  it('does not route missing, cancelled, non-GCP or non-approved runs', () => {
    for (const map of [new Map<string, GcpPrivateRoute>(), new Map([['run-1', { ...route(), gcpPrivate: false }]]),
      new Map([['run-1', { ...route(), pageProgress: false }]]), new Map([['run-1', { ...route(), tabId: -1 }]])]) {
      expect(takeGcpPrivateCompletion(message(), sender, map, deps)).toBeNull();
    }
    expect(takeGcpPrivateCompletion({ ...message(), requestId: 'other' }, sender, routes(), deps)).toBeNull();
  });

  it('heartbeats do not extend the absolute12min deadline and expired completions cannot revive routes', () => {
    const map = routes(), expiry = route().createdAt + GCP_PRIVATE_ROUTE_TTL_MS;
    expect(liveGcpPrivateRoute('run-1', sender, map, { ...deps, now: expiry - 1 })).toEqual(route());
    expect(map.get('run-1')?.createdAt).toBe(100);
    expect(takeGcpPrivateCompletion(message(), sender, map, { ...deps, now: expiry })).toBeNull();
    expect(map.size).toBe(0);
    expect(takeGcpPrivateCompletion(message(), sender, map, deps)).toBeNull();
  });

  it('failure and malformed trusted responses become fixed errors and consume the route', () => {
    for (const raw of [{ type: 'GCP_PRIVATE_COMPLETE', requestId: 'run-1', success: false, error: 'private error' },
      { ...message(), secret: 'private' }, { ...message(), result: { ...result(), transcript: 'private' } },
      { ...message(), result: { ...result(), proofs: [{ ...result().proofs[0], witness: [1] }] } },
      { ...message(), result: { ...result(), sessionIds: Array(6).fill(result().sessionIds[0]) } }]) {
      const map = routes();
      expect(takeGcpPrivateCompletion(raw, sender, map, deps)?.response).toEqual({ success: false, error: 'GCP_PRIVATE_PROVING_FAILED' });
      expect(map.size).toBe(0);
    }
  });

  it('result bounds reject missing sessions, unsupported circuits and private extra fields', () => {
    for (const raw of [{ ...result(), sessionIds: result().sessionIds.slice(0, 5) },
      { ...result(), proofs: Array(129).fill(result().proofs[0]) },
      { ...result(), proofs: [{ ...result().proofs[0], circuitId: 'caller-circuit' }] },
      { ...result(), proofs: [{ ...result().proofs[0], verificationKey: 'caller-key' }] },
      { ...result(), proofs: [{ ...result().proofs[0], publicInputs: Array(1025).fill('1') }] }]) {
      expect(() => sanitizeGcpPrivateResult(raw)).toThrow('GCP_PRIVATE_PROOF_INVALID');
    }
  });
});
