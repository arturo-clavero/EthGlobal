import { discoverAzureActivity, projectAzureDiscovery } from './browser-discovery.mjs';
import { validateAzureAttempt } from './browser-result.mjs';

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const bearer = value => typeof value === 'string' && /^[A-Za-z0-9._~+/-]+=*$/.test(value) && value.length <= 11993;
const text = value => typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\x00-\x1f\x7f]/.test(value);
const unavailable = () => new Error('AZURE_DISCOVERY_UNAVAILABLE');

// Provider-owned cache entries are choices, never a claim about the portal's active account.
function cachedSessions(storage) {
  if (!Number.isInteger(storage.length) || storage.length > 512) throw unavailable();
  const tokens = [], labels = new Map(); let bytes = 0;
  for (let i = 0; i < storage.length; i++) {
    const raw = storage.getItem(storage.key(i));
    if (typeof raw !== 'string') continue;
    bytes += raw.length;
    if (raw.length > 65536 || bytes > 2097152) throw unavailable();
    let row; try { row = JSON.parse(raw); } catch { continue; }
    if (!row || typeof row !== 'object' || Array.isArray(row)) continue;
    if (text(row.homeAccountId) && text(row.username)) labels.set(row.homeAccountId, row.username);
    if (row.credentialType !== 'AccessToken' || !text(row.homeAccountId) ||
        typeof row.realm !== 'string' || !UUID.test(row.realm.toLowerCase()) || !bearer(row.secret) ||
        !/^\d{1,12}$/.test(String(row.expiresOn))) continue;
    const expiresAt = Number(row.expiresOn) * 1000;
    if (!Number.isSafeInteger(expiresAt) || expiresAt < Date.now() + 60000 || typeof row.target !== 'string') continue;
    const scopes = row.target.split(/\s+/).filter(scope => !['openid', 'profile', 'email'].includes(scope));
    const kind = scopes.length && scopes.every(scope => /^https:\/\/graph\.microsoft\.com\/{1,2}[A-Za-z0-9_.-]+$/i.test(scope)) ? 'graph'
      : scopes.length && scopes.every(scope => /^https:\/\/(?:management\.azure\.com|management\.core\.windows\.net)\/{1,2}[A-Za-z0-9_.-]+$/i.test(scope)) ? 'arm' : null;
    if (kind) tokens.push({ kind, account: row.homeAccountId, tenant: row.realm.toLowerCase(), secret: row.secret, expiresAt });
  }
  const sessions = [];
  for (const key of new Set(tokens.map(row => JSON.stringify([row.account, row.tenant])))) {
    const [account, tenant] = JSON.parse(key), selected = {};
    for (const kind of ['graph', 'arm']) {
      const matches = tokens.filter(row => row.account === account && row.tenant === tenant && row.kind === kind)
        .sort((a, b) => b.expiresAt - a.expiresAt);
      if (!matches.length || matches.some(row => row.expiresAt === matches[0].expiresAt && row.secret !== matches[0].secret)) continue;
      selected[kind] = matches[0];
    }
    if (selected.graph && selected.arm) sessions.push({ key, account, tenant, ...selected,
      label: labels.get(account) ?? `Azure session ${sessions.length + 1}` });
  }
  if (sessions.length > 6) throw unavailable();
  return sessions;
}

export function createPortalSelection({ storage = sessionStorage, fetchImpl = fetch } = {}) {
  let session = null, subscription = null, pin = null, choices = new Map(), subscriptions = new Map();
  let controller = new AbortController(), epoch = 0, spent = false, readyTimer;
  const reset = () => {
    controller.abort(); controller = new AbortController(); epoch++; clearTimeout(readyTimer);
    session = subscription = pin = null; choices.clear(); subscriptions.clear(); spent = false;
  };
  const currentSession = () => {
    const current = session && cachedSessions(storage).find(row => row.key === session.key);
    return current && current.graph.secret === session.graph.secret && current.arm.secret === session.arm.secret &&
      current.graph.expiresAt === session.graph.expiresAt && current.arm.expiresAt === session.arm.expiresAt ? current : null;
  };
  const assertCurrent = version => {
    if (version !== epoch || controller.signal.aborted || !currentSession()) throw unavailable();
  };
  const getContext = () => {
    try { return pin && !controller.signal.aborted && currentSession() ? { ...pin } : null; } catch { return null; }
  };
  const get = async (url, token, version) => {
    assertCurrent(version);
    const response = await fetchImpl(url, { method: 'GET', headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' },
      signal: AbortSignal.any([controller.signal, AbortSignal.timeout(20000)]), credentials: 'omit',
      redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer' });
    const reader = response.body?.getReader();
    try {
      assertCurrent(version);
      if (response.status !== 200 || !reader || !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '')) throw unavailable();
      const chunks = []; let size = 0;
      while (true) {
        const { done, value } = await reader.read(); assertCurrent(version);
        if (done) break;
        size += value.byteLength; if (size > 32768) throw unavailable(); chunks.push(value);
      }
      const body = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
    } finally { await reader?.cancel(); }
  };
  const validateSubscription = value => value && value.state === 'Enabled' && value.tenantId?.toLowerCase() === session.tenant &&
    typeof value.subscriptionId === 'string' && UUID.test(value.subscriptionId.toLowerCase()) &&
    typeof value.id === 'string' && value.id.toLowerCase() === '/subscriptions/' + value.subscriptionId.toLowerCase();
  const authenticate = async version => {
    const me = await get('https://graph.microsoft.com/v1.0/me?$select=id', session.graph.secret, version);
    const selected = await get(`https://management.azure.com/subscriptions/${subscription}?api-version=2022-12-01`, session.arm.secret, version);
    if (typeof me.id !== 'string' || !UUID.test(me.id.toLowerCase()) || !validateSubscription(selected) ||
        selected.subscriptionId.toLowerCase() !== subscription || pin && pin.objectId !== me.id.toLowerCase()) throw unavailable();
    pin = { objectId: me.id.toLowerCase(), tenantId: session.tenant, subscriptionId: subscription,
      homeAccountId: session.account, graphBearer: 'Bearer ' + session.graph.secret, armBearer: 'Bearer ' + session.arm.secret,
      expiresAt: Math.min(session.graph.expiresAt, session.arm.expiresAt) };
  };
  return {
    listSessions() {
      reset();
      const sessions = cachedSessions(storage);
      choices = new Map(sessions.map(row => [crypto.randomUUID(), row]));
      return [...choices].map(([id, row]) => ({ id, label: `${row.label} — tenant ${row.tenant}` }));
    },
    async selectSession(id) {
      if (spent || !choices.has(id)) throw unavailable();
      controller.abort(); controller = new AbortController(); const version = ++epoch;
      clearTimeout(readyTimer); pin = subscription = null; subscriptions.clear(); session = choices.get(id);
      const me = await get('https://graph.microsoft.com/v1.0/me?$select=id', session.graph.secret, version);
      if (typeof me.id !== 'string' || !UUID.test(me.id.toLowerCase())) throw unavailable();
      const result = await get('https://management.azure.com/subscriptions?api-version=2022-12-01', session.arm.secret, version);
      if (!Array.isArray(result.value) || result.nextLink || result.value.length > 100) throw unavailable();
      const rows = result.value.filter(validateSubscription);
      if (!rows.length || new Set(rows.map(row => row.subscriptionId.toLowerCase())).size !== rows.length) throw unavailable();
      subscriptions = new Map(rows.map(row => [crypto.randomUUID(), row]));
      return [...subscriptions].map(([id, row]) => ({ id,
        label: text(row.displayName) ? row.displayName : `Subscription ${row.subscriptionId}` }));
    },
    async selectSubscription(id) {
      if (spent || !session || !subscriptions.has(id)) throw unavailable();
      controller.abort(); controller = new AbortController(); const version = ++epoch;
      clearTimeout(readyTimer); pin = null; subscription = subscriptions.get(id).subscriptionId.toLowerCase();
      await authenticate(version);
      const result = await discoverAzureActivity({ getContext, fetchImpl, signal: controller.signal });
      assertCurrent(version);
      if (result.status !== 'ready') throw unavailable();
      readyTimer = setTimeout(reset, 300000);
      return projectAzureDiscovery(result);
    },
    async prepare(attempt) {
      if (spent || !pin) throw unavailable();
      const valid = validateAzureAttempt(attempt); spent = true; clearTimeout(readyTimer);
      const version = epoch;
      try {
        await authenticate(version);
        const result = await discoverAzureActivity({ getContext, fetchImpl, signal: controller.signal, cutoffMs: valid.cutoffMs });
        assertCurrent(version);
        if (result.status !== 'ready') throw unavailable();
        return { proofId: valid.proofId, nonceMac: valid.nonceMac, cutoffMs: valid.cutoffMs,
          graph: result.context.graphBearer, arm: result.context.armBearer,
          subscription: result.selected.subscriptionId, correlation: result.selected.correlationId };
      } finally { reset(); spent = true; }
    },
    valid() { try { return !session || !!currentSession(); } catch { return false; } },
    clear: reset,
  };
}
