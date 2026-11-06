import test from 'node:test';
import assert from 'node:assert/strict';
import { installAzurePortalDiscovery } from './portal-entry.mjs';
import { createPortalSelection } from './portal-selection.mjs';
import { createAzureDiscoveryBackground } from './discovery-background.mjs';
import { syntheticAzureAttempt } from './browser-plan.fixtures.mjs';

const sub = '11111111-1111-4111-8111-111111111111', tenant = '22222222-2222-4222-8222-222222222222';
const actor = '33333333-3333-4333-8333-333333333333', correlation = '44444444-4444-4444-8444-444444444444';
const nonce = 'n'.repeat(43), extensionId = 'synthetic-extension';
const sender = { id: extensionId, frameId: 0, tab: { id: 1 }, documentId: 'app-document', url: 'http://localhost:5178/' };
const portal = { id: extensionId, frameId: 0, tab: { id: 2 }, documentId: 'portal-document', url: 'https://portal.azure.com/' };
const selected = attempt => ({ proofId: attempt.proofId, nonceMac: attempt.nonceMac, cutoffMs: attempt.cutoffMs,
  graph: 'Bearer GRAPH_SYNTHETIC', arm: 'Bearer ARM_SYNTHETIC', subscription: sub, correlation });
function fixture() {
  const expiresOn = String(Math.floor(Date.now() / 1000) + 3600);
  const values = [
    { homeAccountId: 'account', username: 'LOCAL_LABEL' },
    ...['graph', 'arm'].map(kind => ({ credentialType: 'AccessToken', homeAccountId: 'account', realm: tenant,
      expiresOn, target: kind === 'graph' ? 'https://graph.microsoft.com/User.Read' : 'https://management.azure.com/user_impersonation',
      secret: kind === 'graph' ? 'GRAPH_SYNTHETIC' : 'ARM_SYNTHETIC' })),
  ];
  const storage = { get length() { return values.length; }, key: index => String(index), getItem: key => JSON.stringify(values[Number(key)]) };
  const subscription = { subscriptionId: sub, tenantId: tenant, id: '/subscriptions/' + sub, state: 'Enabled', displayName: 'LOCAL_SUBSCRIPTION' };
  const calls = [], started = Date.now();
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url); calls.push(parsed);
    assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error');
    const value = parsed.hostname === 'graph.microsoft.com' ? { id: actor }
      : parsed.pathname === '/subscriptions' ? { value: [subscription] }
        : parsed.pathname === '/subscriptions/' + sub ? subscription : { value: [{
          eventDataId: '55555555-5555-4555-8555-555555555555', operationId: '66666666-6666-4666-8666-666666666666',
          subscriptionId: sub, correlationId: correlation, eventTimestamp: new Date(started - 1000).toISOString(),
          resourceId: `/subscriptions/${sub}/resourceGroups/private/providers/Microsoft.Network/networkSecurityGroups/private/securityRules/private`,
          operationName: { value: 'Microsoft.Network/networkSecurityGroups/securityRules/write' },
          status: { value: 'Succeeded' }, eventName: { value: 'EndRequest' },
          claims: { 'http://schemas.microsoft.com/identity/claims/objectidentifier': actor,
            'http://schemas.microsoft.com/identity/claims/tenantid': tenant },
        }] };
    return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
  };
  return { storage, values, calls, fetchImpl };
}

test('one session and subscription still require explicit choices; prepare recollects at fresh attempt cutoff once', async () => {
  const f = fixture(), flow = createPortalSelection(f);
  try {
    const sessions = flow.listSessions(); assert.equal(sessions.length, 1); assert.equal(f.calls.length, 0);
    await assert.rejects(flow.prepare(syntheticAzureAttempt()));
    const subscriptions = await flow.selectSession(sessions[0].id);
    assert.equal(subscriptions.length, 1); assert.equal(f.calls.length, 2);
    await assert.rejects(flow.prepare(syntheticAzureAttempt()));
    assert.deepEqual(await flow.selectSubscription(subscriptions[0].id), { status: 'ready', verified: false });
    const attempt = syntheticAzureAttempt(), result = await flow.prepare(attempt);
    assert.deepEqual(result, selected(attempt));
    assert.ok(f.calls.at(-1).searchParams.get('$filter').includes(new Date(attempt.cutoffMs).toISOString()));
    assert.ok(f.calls.at(-1).searchParams.get('$filter').includes(correlation));
    await assert.rejects(flow.prepare(attempt));
  } finally { flow.clear(); }
});

test('cache replacement and explicit invalid choices cannot silently rebind the selection', async () => {
  const f = fixture(), flow = createPortalSelection(f);
  try {
    const [session] = flow.listSessions(); await assert.rejects(flow.selectSession('not-a-choice'));
    const [subscription] = await flow.selectSession(session.id);
    f.values[2].secret = 'DIFFERENT_ACCOUNT_TOKEN';
    assert.equal(flow.valid(), false); await assert.rejects(flow.selectSubscription(subscription.id));
    assert.equal(f.calls.length, 2);
  } finally { flow.clear(); }
});

function broker(prepare) {
  const removed = [], messages = [];
  const browser = { runtime: { id: extensionId }, windows: { create: async () => ({ id: 10, tabs: [{ id: 2 }] }), get: async () => ({ id: 10, type: 'popup' }),
    remove: () => { throw new Error('must not close whole window'); } },
  tabs: { get: async () => ({ id: 2, windowId: 10 }), remove: async id => { removed.push(id); },
    sendMessage: async (tab, message, options) => {
      messages.push({ tab, message, options });
      if (message.type === 'AZURE_DISCOVERY_PORTAL_PREPARE') return prepare(message);
      return { ok: true };
    } } };
  const manager = createAzureDiscoveryBackground(browser);
  const ready = async () => {
    const result = manager.handle({ type: 'START_AZURE_DISCOVERY', nonce }, sender);
    await Promise.resolve(); await Promise.resolve();
    await manager.handle({ type: 'AZURE_DISCOVERY_PORTAL_STATUS', nonce, status: 'ready' }, portal);
    return result;
  };
  return { manager, ready, messages, removed, browser };
}

test('handle binds exact caller tab/document/origin/nonce and consumes only once without app secrets', async () => {
  const attempt = syntheticAzureAttempt(), b = broker(async () => ({ ok: true, selection: selected(attempt) }));
  const result = await b.ready();
  assert.deepEqual(Object.keys(result).sort(), ['handle', 'status', 'verified']);
  for (const bad of [{ ...sender, documentId: 'replacement' }, { ...sender, tab: { id: 99 } },
    { ...sender, url: 'https://attacker.invalid' }, { ...sender, frameId: 1 }]) {
    assert.equal((await b.manager.handle({ type: 'ATTACH_AZURE_DISCOVERY', nonce, handle: result.handle, proofId: attempt.proofId }, bad)).status, 'unavailable');
  }
  assert.equal((await b.manager.handle({ type: 'ATTACH_AZURE_DISCOVERY', nonce: 'x'.repeat(43), handle: result.handle, proofId: attempt.proofId }, sender)).status, 'unavailable');
  assert.equal((await b.manager.handle({ type: 'ATTACH_AZURE_DISCOVERY', nonce, handle: result.handle, proofId: attempt.proofId }, sender)).ok, true);
  assert.deepEqual(await b.manager.prepare(sender, attempt), selected(attempt));
  await assert.rejects(b.manager.prepare(sender, attempt));
  await Promise.resolve(); assert.deepEqual(b.removed, [2]);
  assert.equal(b.messages.find(row => row.message.type === 'AZURE_DISCOVERY_PORTAL_PREPARE').options.documentId, portal.documentId);
});

test('ready invalidation and moved-tab cleanup do not close other tabs or accept stale selection', async () => {
  const b = broker(async () => { throw new Error('not expected'); });
  b.browser.tabs.get = async () => ({ id: 2, windowId: 99 });
  await b.ready();
  assert.equal((await b.manager.handle({ type: 'AZURE_DISCOVERY_PORTAL_STATUS', nonce, status: 'unavailable' }, portal)).ok, true);
  assert.equal((await b.manager.handle({ type: 'AZURE_DISCOVERY_PORTAL_HEARTBEAT', nonce }, portal)).ok, false);
  await Promise.resolve(); assert.deepEqual(b.removed, []);
});

test('cancellation settles prepare and rejects late selected credentials', async () => {
  let deliver; const attempt = syntheticAzureAttempt(), b = broker(() => new Promise(resolve => { deliver = resolve; }));
  const result = await b.ready();
  await b.manager.handle({ type: 'ATTACH_AZURE_DISCOVERY', nonce, handle: result.handle, proofId: attempt.proofId }, sender);
  const pending = b.manager.prepare(sender, attempt); const rejected = assert.rejects(pending);
  assert.equal((await b.manager.handle({ type: 'CANCEL_AZURE_DISCOVERY', nonce, handle: result.handle }, sender)).ok, true);
  await rejected; deliver({ ok: true, selection: selected(attempt) });
  await assert.rejects(b.manager.prepare(sender, attempt));
});

test('forged portal status and nonce cannot ready a selection; navigation invalidates an attached handle', async () => {
  const b = broker(async () => { throw new Error('not expected'); });
  const pending = b.manager.handle({ type: 'START_AZURE_DISCOVERY', nonce }, sender);
  await Promise.resolve(); await Promise.resolve();
  for (const bad of [{ ...portal, id: 'forged-extension' }, { ...portal, tab: { id: 99 } },
    { ...portal, url: 'https://attacker.invalid/' }, { ...portal, frameId: 1 }]) {
    assert.equal((await b.manager.handle({ type: 'AZURE_DISCOVERY_PORTAL_STATUS', nonce, status: 'ready' }, bad)).ok, false);
  }
  assert.equal((await b.manager.handle({ type: 'AZURE_DISCOVERY_PORTAL_STATUS', nonce: 'x'.repeat(43), status: 'ready' }, portal)).ok, false);
  await b.manager.handle({ type: 'AZURE_DISCOVERY_PORTAL_STATUS', nonce, status: 'ready' }, portal);
  const result = await pending, attempt = syntheticAzureAttempt();
  await b.manager.handle({ type: 'ATTACH_AZURE_DISCOVERY', nonce, handle: result.handle, proofId: attempt.proofId }, sender);
  b.manager.tabChanged(sender.tab.id, 'replacement-document');
  await assert.rejects(b.manager.prepare(sender, attempt));
  assert.equal((await b.manager.handle({ type: 'ATTACH_AZURE_DISCOVERY', nonce, handle: result.handle, proofId: attempt.proofId }, sender)).status, 'unavailable');
});

test('missing or unresponsive portal module leaves no usable selection and cancellation needs cleanup acknowledgement', async () => {
  const b = broker(async () => { throw new Error('not expected'); });
  b.browser.tabs.sendMessage = async () => new Promise(() => {});
  const pending = b.manager.handle({ type: 'START_AZURE_DISCOVERY', nonce }, sender);
  await Promise.resolve(); await Promise.resolve();
  assert.equal((await b.manager.handle({ type: 'CANCEL_AZURE_DISCOVERY', nonce }, sender)).ok, true);
  assert.deepEqual(await pending, { status: 'unavailable', verified: false });
  assert.deepEqual(b.removed, [2]);
});

test('late popup creation after cancellation removes only the saved popup tab', async () => {
  const b = broker(async () => { throw new Error('not expected'); });
  let created;
  b.browser.windows.create = () => new Promise(resolve => { created = resolve; });
  const pending = b.manager.handle({ type: 'START_AZURE_DISCOVERY', nonce }, sender);
  assert.equal((await b.manager.handle({ type: 'CANCEL_AZURE_DISCOVERY', nonce }, sender)).ok, false);
  assert.deepEqual(await pending, { status: 'unavailable', verified: false });
  assert.deepEqual(b.removed, []); // START must settle while popup creation is still unresolved.
  created({ id: 10, tabs: [{ id: 2 }, { id: 77 }] });
  await new Promise(setImmediate);
  assert.deepEqual(b.removed, [2]);
});

test('unresponsive prepare expires and unacknowledged cleanup is never reported as stopped', async () => {
  const originalTimeout = globalThis.setTimeout, originalClear = globalThis.clearTimeout;
  const timers = new Map(); let next = 0;
  globalThis.setTimeout = (callback, ms) => { const id = ++next; timers.set(id, { callback, ms }); return id; };
  globalThis.clearTimeout = id => timers.delete(id);
  const runDeadline = ms => { const entry = [...timers].find(([, value]) => value.ms === ms); assert.ok(entry); timers.delete(entry[0]); entry[1].callback(); };
  try {
    const attempt = syntheticAzureAttempt(), b = broker(() => new Promise(() => {}));
    const result = await b.ready();
    await b.manager.handle({ type: 'ATTACH_AZURE_DISCOVERY', nonce, handle: result.handle, proofId: attempt.proofId }, sender);
    const pending = assert.rejects(b.manager.prepare(sender, attempt));
    runDeadline(90000); await pending;
    await assert.rejects(b.manager.prepare(sender, attempt));
    const c = broker(async () => { throw new Error('not expected'); });
    const ready = await c.ready();
    c.browser.tabs.get = async () => ({ id: 2, windowId: 99 });
    c.browser.tabs.sendMessage = async () => ({ ok: false });
    const cancelled = c.manager.handle({ type: 'CANCEL_AZURE_DISCOVERY', nonce, handle: ready.handle }, sender);
    while ([...timers.values()].some(value => value.ms === 5000)) runDeadline(5000);
    assert.equal((await cancelled).ok, false);
    assert.deepEqual(c.removed, []);
  } finally { globalThis.setTimeout = originalTimeout; globalThis.clearTimeout = originalClear; }
});

test('portal rejects forged background senders and stale callbacks cannot clear a replacement selection', async () => {
  const names = ['document', 'window', 'location', 'sessionStorage', 'fetch', 'setInterval', 'clearInterval'];
  const saved = new Map(names.map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  const elements = [], intervals = new Map(), messages = []; let listener, nextInterval = 0, releaseFetch, releaseHeartbeat;
  const element = tag => {
    const value = { tag, children: [], style: {}, handlers: {}, removed: false, textContent: '',
      append(...children) { this.children.push(...children); }, replaceChildren(...children) { this.children = children; },
      remove() { this.removed = true; }, setAttribute() {},
      addEventListener(name, callback) { this.handlers[name] = callback; }, attachShadow() { return element('shadow'); } };
    elements.push(value); return value;
  };
  const f = fixture(), fakeWindow = { addEventListener() {} }; fakeWindow.top = fakeWindow;
  const values = { document: { createElement: element, documentElement: element('html') }, window: fakeWindow,
    location: { origin: 'https://portal.azure.com' }, sessionStorage: f.storage,
    fetch: (...args) => new Promise(resolve => { releaseFetch = () => resolve(f.fetchImpl(...args)); }),
    setInterval: callback => { intervals.set(++nextInterval, callback); return nextInterval; }, clearInterval: id => intervals.delete(id) };
  for (const [name, value] of Object.entries(values)) Object.defineProperty(globalThis, name, { value, writable: true, configurable: true });
  const browser = { runtime: { id: extensionId, getURL: path => 'chrome-extension://' + extensionId + '/' + path,
    onMessage: { addListener: callback => { listener = callback; } }, sendMessage: message => {
      messages.push(message);
      return message.type === 'AZURE_DISCOVERY_PORTAL_HEARTBEAT' ? new Promise(resolve => { releaseHeartbeat = resolve; }) : Promise.resolve({ ok: true });
    } } };
  const trusted = { id: extensionId, url: browser.runtime.getURL('background.bundle.js') };
  const start = { type: 'AZURE_DISCOVERY_PORTAL_START', nonce };
  try {
    installAzurePortalDiscovery(browser);
    for (const bad of [{ ...trusted, id: 'forged' }, { ...trusted, tab: { id: 2 } }, { id: extensionId }, { ...trusted, url: 'https://portal.azure.com' }]) {
      assert.equal(listener(start, bad), undefined);
    }
    assert.deepEqual(await listener({ ...start, nonce: 'short' }, trusted), { ok: false });
    await listener(start, trusted);
    const oldHost = values.document.documentElement.children.at(-1);
    const choose = elements.find(row => row.tag === 'button' && row.textContent.includes('LOCAL_LABEL'));
    const pendingClick = choose.handlers.click({ isTrusted: true });
    const pendingHeartbeat = [...intervals.values()][0]();
    assert.deepEqual(await listener({ type: 'AZURE_DISCOVERY_PORTAL_CANCEL', nonce: 'x'.repeat(43) }, trusted), { ok: false });
    await listener({ type: 'AZURE_DISCOVERY_PORTAL_CANCEL', nonce }, trusted);
    await listener(start, trusted); // Same nonce, new selector generation.
    const newHost = values.document.documentElement.children.at(-1);
    releaseFetch(); releaseHeartbeat({ ok: false });
    await pendingClick; await pendingHeartbeat;
    assert.equal(oldHost.removed, true); assert.equal(newHost.removed, false);
    assert.equal(messages.filter(row => row.type === 'AZURE_DISCOVERY_PORTAL_STATUS' && row.status === 'unavailable').length, 0);
    assert.equal(intervals.size, 1);
  } finally {
    if (listener) await listener({ type: 'AZURE_DISCOVERY_PORTAL_CANCEL', nonce }, trusted);
    for (const [name, descriptor] of saved) { if (descriptor) Object.defineProperty(globalThis, name, descriptor); else delete globalThis[name]; }
  }
});
