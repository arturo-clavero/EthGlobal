import test from 'node:test';
import assert from 'node:assert/strict';
import { isDeepStrictEqual as nativeEqual } from 'node:util';
import { isIP as nativeIP } from 'node:net';
import { discoverAzureActivity, projectAzureDiscovery } from './browser-discovery.mjs';
import { isDeepStrictEqual, isIP } from './browser-discovery-platform.mjs';

const subscriptionId = '11111111-1111-4111-8111-111111111111';
const objectId = '22222222-2222-4222-8222-222222222222';
const tenantId = '33333333-3333-4333-8333-333333333333';
const correlationId = '44444444-4444-4444-8444-444444444444';
const operationId = '55555555-5555-4555-8555-555555555555';
const eventDataId = '66666666-6666-4666-8666-666666666666';
const context = () => ({ subscriptionId, objectId, tenantId, homeAccountId: 'synthetic-account',
  graphBearer: 'Bearer GRAPH_SYNTHETIC', armBearer: 'Bearer ARM_SYNTHETIC', expiresAt: Date.now() + 3600000 });
const event = (cutoff, overrides = {}) => ({ eventDataId, subscriptionId, correlationId, operationId,
  eventTimestamp: new Date(cutoff - 1000).toISOString(),
  resourceId: `/subscriptions/${subscriptionId}/resourceGroups/PRIVATE_GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE_NSG/securityRules/PRIVATE_RULE`,
  operationName: { value: 'Microsoft.Network/networkSecurityGroups/securityRules/write' },
  status: { value: 'Succeeded' }, eventName: { value: 'EndRequest' },
  claims: { 'http://schemas.microsoft.com/identity/claims/objectidentifier': objectId,
    'http://schemas.microsoft.com/identity/claims/tenantid': tenantId }, ...overrides });
const json = (rows, extra = {}) => new Response(JSON.stringify({ value: rows, ...extra }),
  { headers: { 'Content-Type': 'application/json' } });

test('14-day grouped discovery drills only one correlation and keeps its private selection out of projection', async () => {
  const cutoffMs = Date.now(), pin = context(), calls = [];
  const result = await discoverAzureActivity({ getContext: () => pin, cutoffMs, fetchImpl: async (url, options) => {
    calls.push(new URL(url));
    assert.equal(options.headers.Authorization, pin.armBearer);
    assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error');
    return json([event(cutoffMs)]);
  } });
  assert.equal(result.status, 'ready'); assert.equal(result.verified, false); assert.equal(calls.length, 2);
  assert.equal(calls[0].searchParams.get('$filter'), `eventTimestamp ge '${new Date(cutoffMs - 14 * 86400000).toISOString()}' and eventTimestamp le '${new Date(cutoffMs).toISOString()}'`);
  assert.equal(calls[1].searchParams.get('$filter'), calls[0].searchParams.get('$filter') + ` and correlationId eq '${correlationId}'`);
  assert.equal(result.selected.correlationId, correlationId); assert.equal(result.context.armBearer, pin.armBearer);
  assert.equal(result.selected.candidate.facts.length, 0); assert.equal(result.diagnostics.groups, 1);
  assert.deepEqual(projectAzureDiscovery(result), { status: 'ready', verified: false });
  for (const privateValue of [subscriptionId, correlationId, 'PRIVATE_', 'SYNTHETIC', objectId, tenantId]) {
    assert.equal(JSON.stringify(projectAzureDiscovery(result)).includes(privateValue), false);
  }
});

test('changed account, scope or either credential discards selection before another request', async () => {
  for (const key of ['homeAccountId', 'objectId', 'tenantId', 'subscriptionId', 'graphBearer', 'armBearer']) {
    const pin = context(), cutoffMs = Date.now(); let calls = 0;
    const result = await discoverAzureActivity({ getContext: () => pin, cutoffMs, fetchImpl: async () => {
      calls++; pin[key] += '-changed'; return json([event(cutoffMs)]);
    } });
    assert.equal(calls, 1); assert.equal(result.reason, 'context-changed'); assert.equal(result.selected, undefined);
    assert.deepEqual(projectAzureDiscovery(result), { status: 'unavailable', verified: false });
  }
});

test('foreign actor, conflicting terminal, partial pagination and changed drilldown never yield a selection', async () => {
  const cutoffMs = Date.now();
  const failed = event(cutoffMs, { eventDataId: '77777777-7777-4777-8777-777777777777', status: { value: 'Failed' } });
  const cases = [
    () => json([event(cutoffMs, { claims: {} })]),
    () => json([event(cutoffMs), failed]),
    () => json([event(cutoffMs)], { nextLink: 'https://attacker.invalid/private' }),
    count => json(count === 1 ? [event(cutoffMs)] : [event(cutoffMs), failed]),
    count => json([event(cutoffMs, count === 1 ? {} : { eventTimestamp: new Date(cutoffMs - 2000).toISOString() })]),
    count => json([event(cutoffMs)], count === 1 ? {} : { nextLink: `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Insights/eventtypes/management/values?$skiptoken=next` }),
  ];
  for (const response of cases) {
    const pin = context(); let calls = 0;
    const result = await discoverAzureActivity({ getContext: () => pin, cutoffMs, fetchImpl: async () => response(++calls) });
    assert.equal(result.status, 'unavailable'); assert.equal(result.selected, undefined);
    assert.ok(calls <= 2);
  }
});

test('cancellation and malformed or near-expired context prevent collection', async () => {
  const controller = new AbortController(); controller.abort();
  let calls = 0; const fetchImpl = async () => { calls++; throw new Error('unexpected request'); };
  for (const [pin, signal] of [[context(), controller.signal], [{ ...context(), expiresAt: Date.now() }, undefined],
    [{ ...context(), armBearer: 'Bearer invalid\r\n' }, undefined], [{ ...context(), subscriptionId: 'not-a-uuid' }, undefined]]) {
    const result = await discoverAzureActivity({ getContext: () => pin, signal, fetchImpl });
    assert.equal(result.status, 'unavailable'); assert.equal(result.selected, undefined);
  }
  assert.equal(calls, 0);
});

test('active cancellation aborts the in-flight fetch and releases the private result', async () => {
  const pin = context(), controller = new AbortController();
  const result = await discoverAzureActivity({ getContext: () => pin, signal: controller.signal,
    fetchImpl: async (_url, options) => {
      controller.abort(); assert.equal(options.signal.aborted, true); throw new Error('PRIVATE_NETWORK_DETAIL');
    } });
  assert.equal(result.reason, 'cancelled'); assert.equal(JSON.stringify(result).includes('PRIVATE_NETWORK_DETAIL'), false);
});

test('discovery pagination and selected response byte limits fail closed', async () => {
  const cutoffMs = Date.now();
  for (const mode of ['pages', 'selected-bytes']) {
    const pin = context(); let calls = 0;
    const result = await discoverAzureActivity({ getContext: () => pin, cutoffMs, fetchImpl: async () => {
      calls++;
      return json([event(cutoffMs)], mode === 'pages'
        ? { nextLink: `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Insights/eventtypes/management/values?$skiptoken=page${calls}` }
        : calls === 1 ? {} : { padding: 'x'.repeat(14336) });
    } });
    assert.equal(result.reason, 'source-incomplete'); assert.equal(result.selected, undefined);
    assert.equal(calls, mode === 'pages' ? 3 : 2);
  }
});

test('browser platform adapter retains the tested plain-record equality and IP behavior', () => {
  const values = [null, true, false, 0, -0, 1, '1', '', undefined, [], {}, [null], [1, 2], [2, 1],
    { a: 1, b: 2 }, { b: 2, a: 1 }, { a: null }, { a: undefined }, JSON.parse('{"__proto__":{"x":1}}'), { a: [{ x: 2 }] }];
  for (const a of values) for (const b of values) assert.equal(isDeepStrictEqual(a, b), nativeEqual(a, b));
  for (const address of ['127.0.0.1', '0.0.0.0', '255.255.255.255', '256.0.0.1', '01.2.3.4', '1.2.3', '::1', '::',
    '2001:db8::1', '::ffff:192.0.2.1', 'fe80::1%eth0', '1:2:3:4:5:6:7:8', '1::2::3', 'example.com', '1.2.3.4/24', '']) {
    assert.equal(isIP(address), nativeIP(address));
  }
});

const catalogPairs = [["Microsoft.Network/networkSecurityGroups/write", "Microsoft.Network/networkSecurityGroups"], ["Microsoft.Network/networkSecurityGroups/delete", "Microsoft.Network/networkSecurityGroups"], ["Microsoft.Compute/virtualMachines/write", "Microsoft.Compute/virtualMachines"], ["Microsoft.Web/sites/write", "Microsoft.Web/sites"], ["Microsoft.ContainerService/managedClusters/write", "Microsoft.ContainerService/managedClusters"], ["Microsoft.Network/virtualNetworks/write", "Microsoft.Network/virtualNetworks"], ["Microsoft.Storage/storageAccounts/write", "Microsoft.Storage/storageAccounts"], ["Microsoft.KeyVault/vaults/write", "Microsoft.KeyVault/vaults"], ["Microsoft.Insights/metricAlerts/write", "Microsoft.Insights/metricAlerts"]];

test('catalog discovery keeps exact action/type pairs and rejects cross-family or child paths', async () => {
  const cutoffMs = Date.now();
  for (const [index, [operation, type]] of catalogPairs.entries()) {
    const other = catalogPairs[(index + 2) % catalogPairs.length][1];
    for (const [resourceType, suffix, ready] of [[type, '', true], [other, '', false], [type, '/child/name', false]]) {
      const pin = context();
      const row = event(cutoffMs, { operationName: { value: operation },
        resourceId: `/subscriptions/${subscriptionId}/resourceGroups/PRIVATE_GROUP/providers/${resourceType}/PRIVATE_NAME${suffix}` });
      const result = await discoverAzureActivity({ getContext: () => pin, cutoffMs, fetchImpl: async () => json([row]) });
      assert.equal(result.status === 'ready', ready);
      assert.equal(projectAzureDiscovery(result).verified, false);
    }
    for (const resourceId of [
      `/subscriptions/${subscriptionId}/providers/${type}/PRIVATE_NAME`,
      `/subscriptions/${subscriptionId}/resourceGroups/PRIVATE_GROUP/providers/Microsoft.Other/parents/PRIVATE_PARENT/providers/${type}/PRIVATE_NAME`,
    ]) {
      const pin = context(), row = event(cutoffMs, { operationName: { value: operation }, resourceId });
      const result = await discoverAzureActivity({ getContext: () => pin, cutoffMs, fetchImpl: async () => json([row]) });
      assert.equal(result.status, 'unavailable');
    }
  }
});

const remainingScopeCases = [[true, "Microsoft.Sql/servers/databases/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.sql/servers/private-server/databases/private-db"], [true, "Microsoft.DataFactory/factories/pipelines/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.datafactory/factories/private-factory/pipelines/private-pipeline"], [true, "Microsoft.Resources/subscriptions/resourceGroups/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group"], [true, "Microsoft.Resources/subscriptions/resourceGroups/delete", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group"], [true, "Microsoft.Resources/deployments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.resources/deployments/private-deployment"], [true, "Microsoft.Resources/deployments/write", "/subscriptions/{SUBSCRIPTION}/providers/microsoft.resources/deployments/private-deployment"], [true, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [true, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [true, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/private-vm/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [true, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.sql/servers/private-server/databases/private-db/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [true, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/private-vm/providers/microsoft.insights/diagnosticsettings/private-diagnostic/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [true, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/providers/microsoft.resources/deployments/private-deployment/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [true, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/providers/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Sql/servers/databases/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.sql/databases/private-db"], [false, "Microsoft.Sql/servers/databases/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.sql/servers/private-server/elasticpools/private-db"], [false, "Microsoft.DataFactory/factories/pipelines/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.sql/factories/private-factory/pipelines/private-pipeline"], [false, "Microsoft.Resources/subscriptions/resourceGroups/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.sql/servers/private-server/databases/private-db"], [false, "Microsoft.Resources/deployments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.apicenter/deployments/private-deployment"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/dddddddd-1111-2222-3333-444444444444/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/providers/microsoft.authorization/roleassignments/private-assignment"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/providers/microsoft.authorization/roleassignments/gddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.compute/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft..compute/virtualmachines/private-vm/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/virtualmachines/private-vm/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/private-vm/providers/microsoft.insights/diagnosticsettings/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444/child/name"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/providers/microsoft.authorization/roledefinitions/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/providers/microsoft.management/managementgroups/private-group/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/../providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/arbitrary/prefix/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.compute/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444"], [true, "Microsoft.Web/sites/slots/slotsswap/action", "/subscriptions/{SUBSCRIPTION}/resourcegroups/private-group/providers/microsoft.web/sites/private-site/slots/private-slot"]];

test('remaining catalog discovery validates complete scope including slot-swap operation ownership', async () => {
  const cutoffMs = Date.now();
  for (const [ready, operation, resource] of remainingScopeCases) {
    const pin = context(), resourceId = resource.replace('{SUBSCRIPTION}', subscriptionId);
    const row = event(cutoffMs, { operationName: { value: operation }, resourceId });
    const result = await discoverAzureActivity({ getContext: () => pin, cutoffMs, fetchImpl: async () => json([row]) });
    assert.equal(result.status === 'ready', ready);
    assert.equal(projectAzureDiscovery(result).verified, false);
  }
});
