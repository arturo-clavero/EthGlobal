import { describe, expect, it, vi } from 'vitest';
import { liveAzurePrivatePageRoute, dropAzurePrivatePageRoutes, type AzurePrivateRoute } from '../../src/background/azurePrivateCompletion';
import { closeAzurePrivateWindow } from '../../src/background/azurePrivateWindow';

const id = '11111111-1111-4111-8111-111111111111';
const extensionId = 'extension', offscreenUrl = 'chrome-extension://extension/offscreen.html';
const page = { id: extensionId, frameId: 0, origin: 'https://app.example.test', tab: { id: 7 } };
const attempt = { proofId: id, pluginSha256: 'a'.repeat(64), nonceMac: 'b'.repeat(43) };
const heartbeat = { type: 'AZURE_PRIVATE_PAGE_HEARTBEAT', requestId: id, pluginSha256: attempt.pluginSha256, nonceMac: attempt.nonceMac };
const route = (): AzurePrivateRoute => ({ tabId: 7, createdAt: 1000, pageProgress: true, azurePrivate: true,
  azureOrigin: page.origin, azureAttempt: { ...attempt } });

describe('Azure page routes fail closed across restart', () => {
  it('checks live routes without consumption and never reconstructs a lost route', () => {
    const routes = new Map([[id, route()]]);
    expect(liveAzurePrivatePageRoute(heartbeat, page, routes, extensionId, 1001)).toBe(true);
    expect(routes.size).toBe(1);
    routes.clear();
    expect(liveAzurePrivatePageRoute(heartbeat, page, routes, extensionId, 1001)).toBe(false);
    expect(routes.size).toBe(0);
  });
  it('rejects forged page identity, route tuple, extra fields, stale clocks and other providers', () => {
    const routes = new Map([[id, route()]]);
    for (const sender of [{ ...page, id: 'foreign' }, { ...page, frameId: 1 }, { ...page, tab: { id: 8 } },
      { ...page, origin: 'https://foreign.invalid' }, { id: extensionId, url: offscreenUrl }]) {
      expect(liveAzurePrivatePageRoute(heartbeat, sender, routes, extensionId, 1001)).toBe(false);
    }
    for (const message of [{ ...heartbeat, nonceMac: 'c'.repeat(43) }, { ...heartbeat, pluginSha256: 'c'.repeat(64) },
      { ...heartbeat, requestId: 'other' }, { ...heartbeat, extra: true }, { ...heartbeat, type: 'CANCEL_AZURE_PRIVATE' }]) {
      expect(liveAzurePrivatePageRoute(message, page, routes, extensionId, 1001)).toBe(false);
    }
    for (const now of [999, 3601000, NaN]) expect(liveAzurePrivatePageRoute(heartbeat, page, routes, extensionId, now)).toBe(false);
    routes.set(id, { ...route(), azurePrivate: false });
    expect(liveAzurePrivatePageRoute(heartbeat, page, routes, extensionId, 1001)).toBe(false);
  });
  it('drops only this tab Azure routes on navigation/close and cannot cancel a replacement tuple', () => {
    const routes = new Map([[id, route()], ['other-tab', { ...route(), tabId: 8 }], ['gcp', { ...route(), azurePrivate: false }]]);
    dropAzurePrivatePageRoutes(7, routes);
    expect([...routes.keys()]).toEqual(['other-tab', 'gcp']);
    routes.set(id, { ...route(), azureAttempt: { ...attempt, nonceMac: 'd'.repeat(43) } });
    expect(liveAzurePrivatePageRoute(heartbeat, page, routes, extensionId, 1001)).toBe(false);
    expect(routes.get(id)?.azureAttempt?.nonceMac).toBe('d'.repeat(43));
  });
});

describe('Azure orphan popup removal', () => {
  const message = { type: 'CLOSE_AZURE_PRIVATE_WINDOW', requestId: id, windowId: 10, tabId: 11 };
  const sender = { id: extensionId, url: offscreenUrl };
  const deps = () => ({ extensionId, offscreenUrl,
    getTab: vi.fn(async () => ({ id: 11, windowId: 10 })),
    getWindow: vi.fn(async () => ({ id: 10, type: 'popup', tabs: [{ id: 11, windowId: 10 }] })),
    removeTab: vi.fn(async () => undefined),
  });
  it('removes the exact saved single-tab popup without resurrecting routing state', async () => {
    const api = deps(); expect(await closeAzurePrivateWindow(message, sender, api)).toBe(true);
    expect(api.removeTab).toHaveBeenCalledExactlyOnceWith(11);
  });
  it('rejects content/page/foreign senders and malformed or extra capabilities before tab access', async () => {
    for (const source of [{ ...sender, id: 'foreign' }, { ...sender, url: 'chrome-extension://extension/other.html' },
      { ...sender, tab: { id: 11 } }, { id: extensionId }]) {
      const api = deps(); expect(await closeAzurePrivateWindow(message, source, api)).toBe(false);
      expect(api.getTab).not.toHaveBeenCalled(); expect(api.removeTab).not.toHaveBeenCalled();
    }
    for (const bad of [{ ...message, tabId: -1 }, { ...message, windowId: 1.5 }, { ...message, requestId: 'bad' },
      { ...message, extra: true }, { ...message, type: 'CLOSE_WINDOW' }]) {
      const api = deps(); expect(await closeAzurePrivateWindow(bad, sender, api)).toBe(false);
      expect(api.removeTab).not.toHaveBeenCalled();
    }
  });
  it('never removes an absent/moved tab, normal window, mismatched popup or popup with other tabs', async () => {
    const cases = [
      (api: ReturnType<typeof deps>) => { api.getTab.mockRejectedValue(new Error('NO_TAB')); },
      (api: ReturnType<typeof deps>) => { api.getTab.mockResolvedValue({ id: 11, windowId: 12 }); },
      (api: ReturnType<typeof deps>) => { api.getTab.mockResolvedValue({ id: 12, windowId: 10 }); },
      (api: ReturnType<typeof deps>) => { api.getWindow.mockResolvedValue({ id: 10, type: 'normal', tabs: [{ id: 11, windowId: 10 }] }); },
      (api: ReturnType<typeof deps>) => { api.getWindow.mockResolvedValue({ id: 12, type: 'popup', tabs: [{ id: 11, windowId: 10 }] }); },
      (api: ReturnType<typeof deps>) => { api.getWindow.mockResolvedValue({ id: 10, type: 'popup', tabs: [{ id: 12, windowId: 10 }] }); },
      (api: ReturnType<typeof deps>) => { api.getWindow.mockResolvedValue({ id: 10, type: 'popup', tabs: [{ id: 11, windowId: 10 }, { id: 12, windowId: 10 }] }); },
    ];
    for (const change of cases) {
      const api = deps(); change(api); expect(await closeAzurePrivateWindow(message, sender, api)).toBe(false);
      expect(api.removeTab).not.toHaveBeenCalled();
    }
  });
});
