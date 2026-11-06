import { expect, it } from 'vitest';
import { AWS_PRIVATE_ROUTE_TTL_MS, livePrivateRoute, takePrivateCompletion, type GcpPrivateRoute } from '../../src/background/gcpPrivateCompletion';

const extensionId = 'private-extension', offscreenUrl = `chrome-extension://${extensionId}/offscreen.html`;
const sender = { id: extensionId, url: offscreenUrl }, deps = { extensionId, offscreenUrl, now: 1000 };
const routes = () => new Map<string, GcpPrivateRoute>([['run-1', { tabId: 8, createdAt: 100, pageProgress: true, awsPrivate: true }]]);
const result = () => ({ kind: 'AWS_PRIVATE_RESULT', version: 1,
  sessionIds: ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'],
  proofs: ['aws-identity-link-v1', 'aws-event-link-v1'].map((circuitId, i) => ({ circuitId, proof: 'AQID', publicInputs: Array(i ? 199 : 264).fill('0') })) });
const message = () => ({ type: 'AWS_PRIVATE_COMPLETE', requestId: 'run-1', success: true, result: result() });

it('consumes only the originating AWS route and copies its closed public result', () => {
  const map = routes(), raw = message(), expected = structuredClone(raw.result);
  const complete = takePrivateCompletion(raw, sender, map, deps, 'aws');
  raw.result.proofs[0].publicInputs[0] = '1';
  expect(complete).toEqual({ requestId: 'run-1', tabId: 8, response: { success: true, result: expected } });
  expect(map.size).toBe(0); expect(takePrivateCompletion(raw, sender, map, deps, 'aws')).toBeNull();
});

it('rejects another extension, content tab, wrong URL and GCP route without consuming the AWS route', () => {
  for (const source of [{ ...sender, id: 'other' }, { ...sender, tab: { id: 8 } }, { ...sender, url: offscreenUrl + '?x' }]) {
    const map = routes(); expect(takePrivateCompletion(message(), source, map, deps, 'aws')).toBeNull(); expect(map.size).toBe(1);
  }
  const map = routes();
  expect(takePrivateCompletion({ ...message(), type: 'GCP_PRIVATE_COMPLETE' }, sender, map, deps)).toBeNull();
  expect(livePrivateRoute('run-1', sender, map, deps)).toBeNull(); expect(map.size).toBe(1);
  map.get('run-1')!.gcpPrivate = true;
  expect(takePrivateCompletion(message(), sender, map, deps, 'aws')).toBeNull();
});

it('heartbeats cannot extend the thirteen-minute absolute route deadline', () => {
  const map = routes();
  expect(AWS_PRIVATE_ROUTE_TTL_MS).toBe(13 * 60 * 1000);
  expect(livePrivateRoute('run-1', sender, map, { ...deps, now: 100 + 300_000 }, 'aws')).not.toBeNull();
  expect(livePrivateRoute('run-1', sender, map, { ...deps, now: 100 + AWS_PRIVATE_ROUTE_TTL_MS - 1 }, 'aws')).not.toBeNull();
  expect(takePrivateCompletion(message(), sender, map, { ...deps, now: 100 + AWS_PRIVATE_ROUTE_TTL_MS }, 'aws')).toBeNull();
  expect(map.size).toBe(0);
  expect(livePrivateRoute('run-1', sender, routes(), { ...deps, now: 99 }, 'aws')).toBeNull();
});

it('consumes malformed completions and emits only a fixed failure code', () => {
  const value = message();
  for (const raw of [{ ...value, success: false, error: 'PRIVATE_SENTINEL' }, { ...value, rawWitness: 'PRIVATE_SENTINEL' },
    { ...value, result: { ...value.result, privateData: 'PRIVATE_SENTINEL' } },
    { ...value, result: { ...value.result, kind: 'GCP_PRIVATE_RESULT' } },
    { ...value, result: { ...value.result, proofs: [{ ...value.result.proofs[0], verificationKey: 'PRIVATE_SENTINEL' }] } },
    { ...value, result: { ...value.result, sessionIds: [value.result.sessionIds[0], ,] } }]) {
    const map = routes();
    expect(takePrivateCompletion(raw, sender, map, deps, 'aws')).toEqual({ requestId: 'run-1', tabId: 8,
      response: { success: false, error: 'AWS_PRIVATE_PROVING_FAILED' } });
    expect(map.size).toBe(0);
  }
});
