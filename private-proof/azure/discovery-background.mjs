import { validateAzureDiscoverySelection } from './discovery-selection.mjs';
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const failure = () => ({ status: 'unavailable', verified: false });
const originOf = sender => { try { return new URL(sender.url).origin; } catch { return null; } };

export function createAzureDiscoveryBackground(browser) {
  const routes = new Map();
  const appSender = sender => sender.id === browser.runtime.id && sender.frameId === 0 &&
    Number.isInteger(sender.tab?.id) && typeof sender.documentId === 'string' && sender.documentId.length > 0 &&
    ['http://localhost:5178', 'http://127.0.0.1:5178'].includes(originOf(sender));
  const sameApp = (route, sender, nonce) => appSender(sender) && sender.tab.id === route.appTab &&
    sender.documentId === route.appDocument && originOf(sender) === route.origin && nonce === route.nonce;
  const closeOwnedTab = async route => {
    if (!Number.isInteger(route.portalTab) || !Number.isInteger(route.windowId)) return false;
    try {
      const tab = await browser.tabs.get(route.portalTab), popup = await browser.windows.get(route.windowId);
      if (tab.id === route.portalTab && tab.windowId === route.windowId && popup.id === route.windowId && popup.type === 'popup') {
        await browser.tabs.remove(route.portalTab); return true;
      }
    } catch {}
    return false;
  };
  const remove = async route => {
    routes.delete(route.handle); clearTimeout(route.timer); clearInterval(route.poll);
    route.prepareReject?.(new Error('AZURE_DISCOVERY_UNAVAILABLE')); route.prepareReject = null;
    route.resolve?.(failure()); route.resolve = null;
    if (route.portalTab === undefined) return false;
    let deadline;
    const confirmed = promise => promise.then(ok => ok ? true : new Promise(() => {}));
    try { return await Promise.race([
      confirmed(browser.tabs.sendMessage(route.portalTab, { type: 'AZURE_DISCOVERY_PORTAL_CANCEL', nonce: route.nonce },
        route.portalDocument ? { documentId: route.portalDocument } : undefined).then(reply => reply?.ok === true).catch(() => false)),
      confirmed(closeOwnedTab(route)),
      new Promise(resolve => { deadline = setTimeout(() => resolve(false), 5000); }),
    ]); } finally { clearTimeout(deadline); }
  };
  const fromPortal = (route, sender) => sender.id === browser.runtime.id && sender.frameId === 0 &&
    sender.tab?.id === route.portalTab && typeof sender.documentId === 'string' && originOf(sender) === 'https://portal.azure.com';
  return {
    async handle(message, sender) {
      if (message?.type === 'AZURE_DISCOVERY_PORTAL_HEARTBEAT') {
        const route = [...routes.values()].find(row => row.nonce === message.nonce && fromPortal(row, sender));
        return { ok: !!route && (route.state === 'selecting' || route.portalDocument === sender.documentId) };
      }
      if (message?.type === 'AZURE_DISCOVERY_PORTAL_STATUS') {
        const route = [...routes.values()].find(row => row.nonce === message.nonce && fromPortal(row, sender));
        if (!route || !['ready', 'unavailable'].includes(message.status) ||
            route.state !== 'selecting' && route.portalDocument !== sender.documentId) return { ok: false };
        if (message.status !== 'ready') { remove(route); return { ok: true }; }
        if (route.state !== 'selecting') return { ok: false };
        route.state = 'ready'; route.portalDocument = sender.documentId;
        clearTimeout(route.timer); clearInterval(route.poll);
        route.timer = setTimeout(() => remove(route), 300000);
        route.resolve?.({ status: 'ready', verified: false, handle: route.handle }); route.resolve = null;
        return { ok: true };
      }
      if (!appSender(sender) || typeof message?.nonce !== 'string' || !NONCE.test(message.nonce)) return failure();
      if (message.type === 'START_AZURE_DISCOVERY') {
        if ([...routes.values()].some(row => row.appTab === sender.tab.id)) return failure();
        const route = { handle: crypto.randomUUID(), nonce: message.nonce, state: 'selecting',
          appTab: sender.tab.id, appDocument: sender.documentId, origin: originOf(sender) };
        routes.set(route.handle, route);
        const ready = new Promise(resolve => { route.resolve = resolve; });
        route.timer = setTimeout(() => remove(route), 900000);
        void (async () => {
          try {
            const popup = await browser.windows.create({ url: 'https://portal.azure.com/', type: 'popup', width: 1100, height: 850 });
            if (!routes.has(route.handle)) { await closeOwnedTab({ portalTab: popup.tabs?.[0]?.id, windowId: popup.id }); return failure(); }
            route.windowId = popup.id; route.portalTab = popup.tabs?.[0]?.id;
            if (!Number.isInteger(route.portalTab)) throw new Error();
            const start = () => browser.tabs.sendMessage(route.portalTab,
              { type: 'AZURE_DISCOVERY_PORTAL_START', nonce: route.nonce }).catch(() => {});
            route.poll = setInterval(start, 1000); void start();
          } catch { remove(route); }
        })();
        return ready;
      }
      const route = routes.get(message.handle) ?? (message.type === 'CANCEL_AZURE_DISCOVERY'
        ? [...routes.values()].find(row => sameApp(row, sender, message.nonce)) : null);
      if (!route || !sameApp(route, sender, message.nonce)) return failure();
      if (message.type === 'CANCEL_AZURE_DISCOVERY') return { ok: await remove(route) };
      if (message.type === 'ATTACH_AZURE_DISCOVERY' && route.state === 'ready' && typeof message.proofId === 'string' && UUID.test(message.proofId)) {
        route.state = 'attached'; route.proofId = message.proofId; return { ok: true };
      }
      return failure();
    },
    async prepare(sender, attempt) {
      const route = [...routes.values()].find(row => row.proofId === attempt.proofId && row.state === 'attached' && sameApp(row, sender, row.nonce));
      if (!route) throw new Error('AZURE_DISCOVERY_UNAVAILABLE');
      route.state = 'consuming'; clearTimeout(route.timer);
      try {
        const reply = await Promise.race([
          browser.tabs.sendMessage(route.portalTab,
            { type: 'AZURE_DISCOVERY_PORTAL_PREPARE', nonce: route.nonce, attempt }, { documentId: route.portalDocument }),
          new Promise((_, reject) => { route.prepareReject = reject; }),
          new Promise((_, reject) => { route.timer = setTimeout(() => { remove(route); reject(new Error()); }, 90000); }),
        ]);
        if (!routes.has(route.handle) || reply?.ok !== true || !reply.selection ||
            reply.selection.proofId !== attempt.proofId || reply.selection.nonceMac !== attempt.nonceMac ||
            reply.selection.cutoffMs !== attempt.cutoffMs) throw new Error();
        return validateAzureDiscoverySelection(reply.selection, attempt);
      } catch { throw new Error('AZURE_DISCOVERY_UNAVAILABLE'); }
      finally { remove(route); }
    },
    tabChanged(tabId, documentId) {
      for (const route of routes.values()) if (route.appTab === tabId && documentId !== route.appDocument ||
          route.portalTab === tabId && route.state !== 'selecting' && documentId !== route.portalDocument) remove(route);
    },
    tabRemoved(tabId) { for (const route of routes.values()) if (route.appTab === tabId || route.portalTab === tabId) remove(route); },
  };
}
