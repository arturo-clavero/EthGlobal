import { azureCatalogClaims, azureCatalogResult } from '../fixtures/azureCatalogResult';
import { describe, it, expect } from 'vitest';
import { liveAzurePrivateRoute, takeAzurePrivateCompletion, takeAzurePrivateCancellation } from '../../src/background/azurePrivateCompletion';
const id = '11111111-1111-4111-8111-111111111111';
const extensionId = 'extension', offscreenUrl = 'chrome-extension://extension/offscreen.html';
const attempt = { proofId: id, pluginSha256: 'a'.repeat(64), nonceMac: 'b'.repeat(43) };
const route = () => ({ tabId: 7, createdAt: 1000, pageProgress: true, azurePrivate: true,
  azureOrigin: 'https://app.example.test', azureAttempt: { ...attempt } });
const page = { id: extensionId, frameId: 0, origin: 'https://app.example.test', tab: { id: 7 } };
const cancel = () => ({ type: 'CANCEL_AZURE_PRIVATE', requestId: id, pluginSha256: attempt.pluginSha256, nonceMac: attempt.nonceMac });
describe('Azure private completion and cancellation routes', () => {
  it('accepts only exact originating page/attempt and consumes cancellation once', () => {
    const routes = new Map([[id, route()]]);
    expect(takeAzurePrivateCancellation(cancel(), page, routes, extensionId)).toBe(id);
    expect(takeAzurePrivateCancellation(cancel(), page, routes, extensionId)).toBeNull();
  });
  it('rejects other tabs, origins, frames, providers, hashes, nonces and extra values without consuming', () => {
    for (const sender of [{ ...page, tab: { id: 8 } }, { ...page, origin: 'http://localhost:5173' },
      { ...page, frameId: 1 }, { ...page, id: 'other' }]) {
      const routes = new Map([[id, route()]]);
      expect(takeAzurePrivateCancellation(cancel(), sender, routes, extensionId)).toBeNull(); expect(routes.size).toBe(1);
    }
    for (const raw of [{ ...cancel(), pluginSha256: 'c'.repeat(64) }, { ...cancel(), nonceMac: 'd'.repeat(43) },
      { ...cancel(), requestId: 'other' }, { ...cancel(), secret: 'extra' }]) {
      const routes = new Map([[id, route()]]);
      expect(takeAzurePrivateCancellation(raw, page, routes, extensionId)).toBeNull(); expect(routes.size).toBe(1);
    }
    const routes = new Map([[id, { ...route(), azurePrivate: false, gcpPrivate: true }]]);
    expect(takeAzurePrivateCancellation(cancel(), page, routes, extensionId)).toBeNull(); expect(routes.size).toBe(1);
  });
  it('restricts completion and heartbeat to offscreen and absolute 60 minute lifetime', () => {
    const routes = new Map([[id, route()]]), deps = { extensionId, offscreenUrl, now: 1001 };
    expect(liveAzurePrivateRoute(id, { id: extensionId, url: offscreenUrl }, routes, deps)).toEqual(route());
    expect(liveAzurePrivateRoute(id, page, routes, deps)).toBeNull();
    expect(liveAzurePrivateRoute(id, { id: extensionId, url: offscreenUrl }, routes, { ...deps, now: 3601000 })).toBeNull();
    expect(routes.size).toBe(0);
  });
  it('never routes source data from malformed completion', () => {
    const routes = new Map([[id, route()]]);
    const result = takeAzurePrivateCompletion({ type: 'AZURE_PRIVATE_COMPLETE', requestId: id, success: true,
      result: { transcript: 'PRIVATE' } }, { id: extensionId, url: offscreenUrl }, routes, { extensionId, offscreenUrl, now: 1001 });
    expect(result?.response).toEqual({ success: false, error: 'AZURE_PRIVATE_PROVING_FAILED' }); expect(routes.size).toBe(0);
  });
});


describe('Azure catalog completion schema', () => {
  it.each(azureCatalogClaims)('routes %s once through the real sanitizer', claim => {
    const result = azureCatalogResult(claim), routes = new Map([[id, route()]]);
    const message = { type: 'AZURE_PRIVATE_COMPLETE', requestId: id, success: true, result };
    const sender = { id: extensionId, url: offscreenUrl }, deps = { extensionId, offscreenUrl, now: 1001 };
    expect(takeAzurePrivateCompletion(message, sender, routes, deps)?.response).toEqual({ success: true, result });
    expect(takeAzurePrivateCompletion(message, sender, routes, deps)).toBeNull();
  });
  it.each(['AZURE_UNKNOWN_OPERATION', 'AZURE_WEB_APP_SLOT_SWAP'])('rejects unsupported claim %s and consumes the route', claim => {
    const routes = new Map([[id, route()]]);
    const message = { type: 'AZURE_PRIVATE_COMPLETE', requestId: id, success: true, result: { ...azureCatalogResult(), claim } };
    const sender = { id: extensionId, url: offscreenUrl }, deps = { extensionId, offscreenUrl, now: 1001 };
    expect(takeAzurePrivateCompletion(message, sender, routes, deps)?.response).toEqual({ success: false, error: 'AZURE_PRIVATE_PROVING_FAILED' });
    expect(takeAzurePrivateCompletion(message, sender, routes, deps)).toBeNull();
  });
});
