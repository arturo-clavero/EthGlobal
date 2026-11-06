import test from 'node:test';
import assert from 'node:assert/strict';
import { createPortalSelection } from './portal-selection.mjs';
import { validateAzureDiscoverySelection } from './discovery-selection.mjs';
import { syntheticAzureAttempt } from './browser-plan.fixtures.mjs';

const sub = '11111111-1111-4111-8111-111111111111', tenant = '22222222-2222-4222-8222-222222222222';
const actor = '33333333-3333-4333-8333-333333333333', correlation = '44444444-4444-4444-8444-444444444444';
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

const other = '77777777-7777-4777-8777-777777777777';
async function ready(f) {
  const flow = createPortalSelection(f);
  const [session] = flow.listSessions(), [subscription] = await flow.selectSession(session.id);
  await flow.selectSubscription(subscription.id);
  return flow;
}

test('missing, mismatched or ambiguous audience pairs are unavailable before any request', () => {
  const changes = [
    f => f.values.splice(1, 1),
    f => f.values.splice(2, 1),
    f => { f.values[1].homeAccountId = 'other-account'; },
    f => { f.values[1].realm = other; },
    f => { f.values.push({ ...f.values[1], secret: 'AMBIGUOUS_GRAPH' }); },
    f => { f.values[2].target = 'https://attacker.invalid/user_impersonation'; },
  ];
  for (const change of changes) {
    const f = fixture(); change(f); const flow = createPortalSelection(f);
    try { assert.deepEqual(flow.listSessions(), []); assert.equal(f.calls.length, 0); }
    finally { flow.clear(); }
  }
});

test('unrelated cached accounts and tenant credentials cannot replace the explicitly chosen pair', async () => {
  const f = fixture(), seen = [], rawFetch = f.fetchImpl;
  f.fetchImpl = (url, options) => { seen.push(options.headers.Authorization); return rawFetch(url, options); };
  const flow = await ready(f);
  try {
    f.values.push(...f.values.slice(1).map(row => ({ ...row, homeAccountId: 'other-account', realm: other,
      secret: row.target.includes('graph') ? 'UNRELATED_GRAPH' : 'UNRELATED_ARM' })));
    assert.equal(flow.valid(), true);
    const result = await flow.prepare(syntheticAzureAttempt());
    assert.equal(result.graph, 'Bearer GRAPH_SYNTHETIC'); assert.equal(result.arm, 'Bearer ARM_SYNTHETIC');
    assert.equal(seen.some(header => header.includes('UNRELATED')), false);
  } finally { flow.clear(); }
});

test('selected account, tenant, credential and expiry changes reject before another provider request', async () => {
  const changes = [
    f => { f.values[1].homeAccountId = 'other-account'; },
    f => { f.values[2].realm = other; },
    f => { f.values[1].secret = 'ROTATED_GRAPH'; },
    f => { f.values[2].secret = 'ROTATED_ARM'; },
    f => { f.values[1].expiresOn = String(Math.floor(Date.now() / 1000) + 30); },
    f => { f.values.splice(1, 1); },
  ];
  for (const change of changes) {
    const f = fixture(), flow = await ready(f), before = f.calls.length;
    try {
      change(f); assert.equal(flow.valid(), false);
      await assert.rejects(flow.prepare(syntheticAzureAttempt()), /AZURE_DISCOVERY_UNAVAILABLE/);
      assert.equal(f.calls.length, before);
    } finally { flow.clear(); }
  }
});

test('fresh authenticated actor, subscription tenant and subscription ID changes reject before Activity recollection', async () => {
  for (const field of ['actor', 'tenant', 'subscription']) {
    const f = fixture(), rawFetch = f.fetchImpl; let switched = false;
    f.fetchImpl = async (url, options) => {
      const response = await rawFetch(url, options);
      if (!switched) return response;
      const parsed = new URL(url), value = await response.json();
      if (field === 'actor' && parsed.hostname === 'graph.microsoft.com') value.id = other;
      if (parsed.pathname === '/subscriptions/' + sub) {
        if (field === 'tenant') value.tenantId = other;
        if (field === 'subscription') { value.subscriptionId = other; value.id = '/subscriptions/' + other; }
      }
      return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
    };
    const flow = await ready(f), before = f.calls.filter(url => url.pathname.includes('Microsoft.Insights')).length;
    try {
      switched = true;
      await assert.rejects(flow.prepare(syntheticAzureAttempt()), /AZURE_DISCOVERY_UNAVAILABLE/);
      assert.equal(f.calls.filter(url => url.pathname.includes('Microsoft.Insights')).length, before);
    } finally { flow.clear(); }
  }
});

test('a cache switch during a pending authenticated read rejects its late response', async () => {
  const f = fixture(), rawFetch = f.fetchImpl; let hold = false, release;
  f.fetchImpl = async (url, options) => {
    const response = await rawFetch(url, options);
    if (hold) await new Promise(resolve => { release = resolve; });
    return response;
  };
  const flow = await ready(f), before = f.calls.length;
  try {
    hold = true;
    const pending = flow.prepare(syntheticAzureAttempt()), rejected = assert.rejects(pending, /AZURE_DISCOVERY_UNAVAILABLE/);
    await new Promise(setImmediate);
    f.values[2].realm = other; release(); await rejected;
    assert.equal(f.calls.length, before + 1);
  } finally { flow.clear(); }
});

test('internal selection rejects extra fields and foreign attempts and returns an owned copy', () => {
  const attempt = syntheticAzureAttempt(), value = selected(attempt);
  for (const changed of [{ ...value, tenant: other }, { ...value, nonceMac: 'x'.repeat(43) },
    { ...value, proofId: other }, { ...value, cutoffMs: attempt.cutoffMs - 1 },
    { ...value, arm: 'Bearer invalid\r\n' }, { ...value, subscription: 'not-a-uuid' }]) {
    assert.throws(() => validateAzureDiscoverySelection(changed, attempt), /AZURE_DISCOVERY_UNAVAILABLE/);
  }
  const copy = validateAzureDiscoverySelection(value, attempt);
  value.graph = 'Bearer REPLACED'; assert.equal(copy.graph, 'Bearer GRAPH_SYNTHETIC');
  assert.deepEqual(Object.keys(copy).sort(), ['arm', 'correlation', 'cutoffMs', 'graph', 'nonceMac', 'proofId', 'subscription']);
});
