// Structural checks only; no native or cryptographic acceptance is asserted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverAzureActivity, projectAzureDiscovery } from './browser-discovery.mjs';
import { AZURE_ACTIVITY_PROFILES, sanitizeAzurePrivateResult } from './browser-result.mjs';
import { activity, expected, fixture } from './test-fixtures.mjs';
import { inspectActivityReceipt } from './source-receipt.mjs';

const operation = 'Microsoft.Web/sites/slots/slotsswap/action';
const id = digit => `${digit.repeat(8)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(12)}`;
const site = `/subscriptions/${id('a')}/resourcegroups/private/providers/microsoft.web/sites/private-site`;
const resources = [site, `${site}/slots/private-slot`, `${site}/slots/private-slot/slotsswap`,
  `${site}/slotsswap`, `${site}/slots/private-slot/config/web`, `${site}/slots/providers`];

function row(resourceId, cutoffMs = expected('activity').cutoffMs) {
  const value = activity().value[0];
  return { ...value, resourceId, eventTimestamp: new Date(cutoffMs - 1000).toISOString(), operationName: { value: operation }, claims: {
    'http://schemas.microsoft.com/identity/claims/objectidentifier': id('b'),
    'http://schemas.microsoft.com/identity/claims/tenantid': id('c'),
  } };
}

async function discover(resourceId) {
  const cutoffMs = Date.now();
  const context = { subscriptionId: id('a'), objectId: id('b'), tenantId: id('c'), homeAccountId: 'synthetic',
    graphBearer: 'Bearer GRAPH_SYNTHETIC', armBearer: 'Bearer ARM_SYNTHETIC', expiresAt: Date.now() + 3600000 };
  return discoverAzureActivity({ getContext: () => context, cutoffMs,
    fetchImpl: async () => new Response(JSON.stringify({ value: [row(resourceId, cutoffMs)] }), {
      headers: { 'Content-Type': 'application/json' },
    }) });
}

test('swap discovery admits site-owned shapes without exposing or identifying swap endpoints', async () => {
  for (const resource of resources) {
    const result = await discover(resource);
    assert.equal(result.status, 'ready');
    assert.equal(result.selected.candidate.actionLabel, 'web-slot-swap');
    assert.deepEqual(result.selected.candidate.facts, []);
    assert.deepEqual(projectAzureDiscovery(result), { status: 'ready', verified: false });
    const native = fixture('activity', { value: { value: [row(resource)] } });
    const inspected = inspectActivityReceipt(native.receipt, native.context);
    assert.equal(inspected.body.rows.length, 1);
    assert.equal(inspected.requestUuidObligations.length, 2);
    assert.equal(JSON.stringify(inspected).includes(resource), false);
  }
});

test('swap discovery rejects malformed/provider-escaping/dangling site ownership', async () => {
  for (const resource of [site + '/', site + '/slots', site + '/slots/../slotsswap', site + '/slots//private',
    site + '/slots/private/restart', site + '/providers/microsoft.sql/servers/private', site + '/%2e%2e',
    site + '/slots/private?query', site + '/slots/private#fragment', site + '/slots/private\\escape',
    site.replace('microsoft.web', 'microsoft.sql'), site.replace('/sites/', '/slots/'),
    site + '/a/b'.repeat(13)]) {
    const result = await discover(resource);
    assert.equal(result.status, 'unavailable');
    assert.equal(result.selected, undefined);
  }
});

test('swap uses fixed code14 and the existing closed716-field catalog envelope', () => {
  assert.deepEqual(AZURE_ACTIVITY_PROFILES.AZURE_WEB_SLOT_SWAP,
    { circuitId: 'catalog-activity-atoms-v1', code: 14, operations: [operation] });
  assert.deepEqual(AZURE_ACTIVITY_PROFILES.AZURE_WEB_APP_WRITE.operations, ['Microsoft.Web/sites/write']);
  const result = { kind: 'AZURE_PRIVATE_RESULT', version: 1, claim: 'AZURE_WEB_SLOT_SWAP',
    sessionIds: [id('1'), id('2'), id('3')], bindings: {
      graphActorHash: 'a'.repeat(64), identityBinding: 'b'.repeat(64), selectedRow: 0,
      claims: [{ stateHashes: ['c'.repeat(64), 'd'.repeat(64)], identityHashes: ['e'.repeat(64), 'f'.repeat(64)] }],
    }, proofs: [{ circuitId: 'catalog-activity-atoms-v1', proof: 'AA==',
      publicInputs: [...Array(715).fill('0'), '14'] }] };
  assert.equal(sanitizeAzurePrivateResult(result).claim, 'AZURE_WEB_SLOT_SWAP');
  assert.throws(() => sanitizeAzurePrivateResult({ ...result, targetSlot: 'private-target' }));
});
