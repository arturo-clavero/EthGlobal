import test from 'node:test';
import assert from 'node:assert/strict';
import { probeAzure } from './probe.mjs';

const subscriptionId = '11111111-1111-4111-8111-111111111111';
const objectId = '22222222-2222-4222-8222-222222222222';
const tenantId = '33333333-3333-4333-8333-333333333333';
const cutoff = Date.now();
const input = { source: 'activity', subscriptionId, bearer: 'Bearer fixture-token', cutoff };
const json = data => new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
const event = (overrides = {}) => ({ eventDataId: 'private-event', subscriptionId,
  eventTimestamp: new Date(cutoff - 1000).toISOString(), operationName: { value: 'Microsoft.Compute/virtualMachines/write' },
  status: { value: 'Succeeded' }, eventName: { value: 'EndRequest' },
  claims: { 'http://schemas.microsoft.com/identity/claims/objectidentifier': objectId,
    'http://schemas.microsoft.com/identity/claims/tenantid': tenantId }, ...overrides });
const next = `/subscriptions/${subscriptionId}/providers/Microsoft.Insights/eventtypes/management/values?$skiptoken=page2`;

test('keeps exact actor references, duplicates and terminal records distinct; exports no witness', async () => {
  const privateRow = event({ resourceId: '/private/employer/sentinel', description: 'CUSTOMER-SECRET' });
  let calls = 0;
  const result = await probeAzure({ ...input, actor: { objectId, tenantId } }, async (url, options) => {
    assert.equal(options.redirect, 'error');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.headers.Authorization, input.bearer);
    if (calls++ === 0) {
      const params = new URL(url).searchParams;
      assert.ok(params.get('$select').includes('claims'));
      assert.equal(params.has('$top'), false);
      assert.equal(params.get('$filter').includes('caller'), false);
      return json({ value: [privateRow, event({ eventDataId: 'start', eventName: { value: 'BeginRequest' } })], nextLink: `https://management.azure.com${next}` });
    }
    return json({ value: [privateRow, event({ eventDataId: 'failed', status: { value: 'Failed' }, claims: {} })] });
  });
  assert.equal(result.status, 'complete');
  assert.equal(result.uniqueRows, 3);
  assert.equal(result.duplicateRows, 1);
  assert.equal(result.successfulTerminalRows, 1);
  assert.equal(result.matchingActorRows, 2);
  assert.equal(result.matchingSuccessfulTerminalRows, 1);
  assert.equal(result.actorBinding, 'supplied-reference-only');
  for (const secret of [subscriptionId, objectId, tenantId, 'CUSTOMER-SECRET', '/private/employer', 'fixture-token', privateRow.eventTimestamp]) {
    assert.equal(JSON.stringify(result).includes(secret), false);
  }
});

test('valid health events do not stop later work events or count as terminal work', async () => {
  const health = event({ eventDataId: 'health', operationName: { value: 'Microsoft.ResourceHealth/events/Activated/action' }, eventName: { value: null }, status: { value: 'Active' }, claims: null });
  const result = await probeAzure(input, async () => json({ value: [health, event()] }));
  assert.equal(result.status, 'complete');
  assert.equal(result.uniqueRows, 2);
  assert.equal(result.successfulTerminalRows, 1);
  for (const value of [42, {}, []]) {
    const invalid = await probeAzure(input, async () => json({ value: [event({ eventName: { value } })] }));
    assert.equal(invalid.reason, 'invalid-response');
  }
});

test('another actor or tenant succeeding does not turn the reference actor failure into success', async () => {
  const claims = event().claims;
  const rows = [event({ eventDataId: 'self-failed', status: { value: 'Failed' } }),
    event({ eventDataId: 'other-actor', claims: { ...claims, 'http://schemas.microsoft.com/identity/claims/objectidentifier': subscriptionId } }),
    event({ eventDataId: 'other-tenant', claims: { ...claims, 'http://schemas.microsoft.com/identity/claims/tenantid': subscriptionId } })];
  const result = await probeAzure({ ...input, actor: { objectId, tenantId } }, async () => json({ value: rows }));
  assert.equal(result.successfulTerminalRows, 2);
  assert.equal(result.matchingActorRows, 1);
  assert.equal(result.matchingSuccessfulTerminalRows, 0);
  assert.deepEqual(result.operations['vm-write'], { rows: 3, successfulTerminalRows: 2, matchingActorRows: 1, matchingSuccessfulTerminalRows: 0 });
});

test('duplicate JSON rows ignore object key order but preserve nested value and array differences', async () => {
  const first = event({ properties: { left: true, right: ['first', 'second'] } });
  const reordered = { ...Object.fromEntries(Object.entries(first).reverse()),
    claims: Object.fromEntries(Object.entries(first.claims).reverse()),
    properties: { right: ['first', 'second'], left: true } };
  const report = await probeAzure(input, async () => json({ value: [first, reordered] }));
  assert.equal(report.status, 'complete');
  assert.equal(report.uniqueRows, 1);
  assert.equal(report.duplicateRows, 1);
  for (const properties of [{ right: ['second', 'first'], left: true }, { right: ['first', 'second'], left: false }]) {
    const conflict = await probeAzure(input, async () => json({ value: [first, { ...reordered, properties }] }));
    assert.equal(conflict.status, 'incomplete');
    assert.equal(conflict.reason, 'conflicting-duplicate');
  }
});

test('fixture attribution requires exact resource, action window, actor, tenant and terminal outcome', async () => {
  const resourceId = `/subscriptions/${subscriptionId}/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG/securityRules/PRIVATE-RULE`;
  const fixture = { resourceIds: [resourceId], startedAt: cutoff - 10000, endedAt: cutoff - 1000 };
  const fixtureEvent = overrides => event({ resourceId, operationName: { value: 'Microsoft.Network/networkSecurityGroups/securityRules/write' }, ...overrides });
  const claims = event().claims;
  const good = fixtureEvent({ eventDataId: 'PRIVATE-SUCCESS', eventTimestamp: new Date(fixture.startedAt).toISOString() });
  const rows = [good,
    fixtureEvent({ eventDataId: 'failed', status: { value: 'Failed' } }),
    fixtureEvent({ eventDataId: 'start', eventName: { value: 'BeginRequest' } }),
    fixtureEvent({ eventDataId: 'failed-start', status: { value: 'Failed' }, eventName: { value: 'BeginRequest' } }),
    fixtureEvent({ eventDataId: 'other-resource', resourceId: `${resourceId}-other` }),
    fixtureEvent({ eventDataId: 'child-resource', resourceId: `${resourceId}/child` }),
    fixtureEvent({ eventDataId: 'missing-resource', resourceId: undefined }),
    fixtureEvent({ eventDataId: 'before-action', eventTimestamp: new Date(fixture.startedAt - 1).toISOString() }),
    fixtureEvent({ eventDataId: 'after-action', eventTimestamp: new Date(fixture.endedAt + 1).toISOString() }),
    fixtureEvent({ eventDataId: 'wrong-actor', claims: { ...claims, 'http://schemas.microsoft.com/identity/claims/objectidentifier': subscriptionId } }),
    fixtureEvent({ eventDataId: 'wrong-tenant', claims: { ...claims, 'http://schemas.microsoft.com/identity/claims/tenantid': subscriptionId } }),
    fixtureEvent({ eventDataId: 'missing-claims', claims: null }),
    fixtureEvent({ eventDataId: 'case-insensitive-resource', resourceId: resourceId.toUpperCase() }),
    fixtureEvent({ eventDataId: 'unknown-operation', operationName: { value: 'PRIVATE-OPERATION' } }),
    fixtureEvent({ eventDataId: 'failed-wrong-actor', status: { value: 'Failed' }, claims: { ...claims, 'http://schemas.microsoft.com/identity/claims/objectidentifier': subscriptionId } }),
    good];
  const result = await probeAzure({ ...input, actor: { objectId, tenantId }, fixture }, async () => json({ value: rows }));
  assert.equal(result.status, 'complete');
  assert.equal(result.duplicateRows, 1);
  assert.equal(result.uniqueRows, rows.length - 1);
  assert.deepEqual(result.fixture, {
    rows: 10, matchingActorRows: 6, matchingSuccessfulTerminalRows: 3, matchingFailedTerminalRows: 1,
    operations: { 'network-rule-write': { rows: 9, matchingActorRows: 5, matchingSuccessfulTerminalRows: 2, matchingFailedTerminalRows: 1 } },
  });
  assert.ok(result.matchingSuccessfulTerminalRows > result.fixture.matchingSuccessfulTerminalRows);
  for (const secret of [resourceId, subscriptionId, objectId, tenantId, 'PRIVATE-GROUP', 'PRIVATE-SUCCESS', 'PRIVATE-OPERATION', fixture.startedAt, fixture.endedAt, good.eventTimestamp]) {
    assert.equal(JSON.stringify(result).includes(String(secret)), false);
  }
  const unattributed = await probeAzure({ ...input, fixture }, async () => json({ value: [good] }));
  assert.equal(unattributed.fixture.rows, 1);
  assert.equal(unattributed.fixture.matchingSuccessfulTerminalRows, 0);
});

test('fixture actions use fixed labels for the exercised writes and deletes', async () => {
  const resourceId = `/subscriptions/${subscriptionId}/resourceGroups/PRIVATE-GROUP`;
  const operations = {
    'Microsoft.Network/networkSecurityGroups/write': 'network-security-group-write',
    'Microsoft.Network/networkSecurityGroups/delete': 'network-security-group-delete',
    'Microsoft.Network/networkSecurityGroups/securityRules/delete': 'network-rule-delete',
    'Microsoft.Resources/subscriptions/resourceGroups/delete': 'resource-group-delete',
  };
  const rows = Object.keys(operations).map((operation, index) => event({ resourceId, eventDataId: String(index), operationName: { value: operation } }));
  const result = await probeAzure({ ...input, actor: { objectId, tenantId }, fixture: { resourceIds: [resourceId], startedAt: cutoff - 10000, endedAt: cutoff } }, async () => json({ value: rows }));
  assert.equal(result.status, 'complete');
  for (const label of Object.values(operations)) {
    assert.equal(result.operations[label].matchingSuccessfulTerminalRows, 1);
    assert.equal(result.fixture.operations[label].matchingSuccessfulTerminalRows, 1);
  }
});

test('invalid fixture bounds and resource scopes never reach the provider', async () => {
  const resourceId = `/subscriptions/${subscriptionId}/resourceGroups/PRIVATE-GROUP`;
  const fixture = { resourceIds: [resourceId], startedAt: cutoff - 10000, endedAt: cutoff };
  for (const invalid of [null, [], {}, { ...fixture, resourceIds: [] }, { ...fixture, resourceIds: Array(33).fill(resourceId) },
    { ...fixture, resourceIds: [resourceId, resourceId.toUpperCase()] }, { ...fixture, resourceIds: [42] },
    { ...fixture, resourceIds: [resourceId.replace(subscriptionId, objectId)] },
    ...['/../escape', '?secret=token', '#secret', '/%2Fescape', '\\escape', '\u0000escape', '/'].map(suffix => ({ ...fixture, resourceIds: [`${resourceId}${suffix}`] })),
    { ...fixture, resourceIds: [`${resourceId}${'x'.repeat(4096)}`] },
    { ...fixture, startedAt: cutoff - 7 * 86400000 - 1 }, { ...fixture, endedAt: cutoff + 1 },
    { ...fixture, startedAt: cutoff + 1 }, { ...fixture, startedAt: 'yesterday' }, { ...fixture, endedAt: NaN }]) {
    await assert.rejects(probeAzure({ ...input, fixture: invalid }, () => assert.fail('network access')), /Invalid Azure probe input/);
  }
  await assert.rejects(probeAzure({ ...input, source: 'inventory', fixture }, () => assert.fail('network access')), /Invalid Azure probe input/);
});

test('a bounded page is incomplete even when it has no matching rows', async () => {
  const result = await probeAzure({ ...input, maxPages: 1 }, async () => json({ value: [], nextLink: `https://management.azure.com${next}` }));
  assert.equal(result.status, 'incomplete');
  assert.equal(result.reason, 'page-budget');
  assert.equal(result.requests, 1);
});

test('rejects foreign hosts, changed scope, changed filters and credential-bearing continuation URLs', async () => {
  for (const nextLink of [
    `https://evil.invalid${next}`, `https://management.azure.com.evil.invalid${next}`,
    `https://user@management.azure.com${next}`, `https://management.azure.com${next}#fragment`,
    `https://management.azure.com${next.replace(subscriptionId, objectId)}`,
    `https://management.azure.com${next}&$FILTER=changed`, `https://management.azure.com${next}&$SELECT=claims`,
    `https://management.azure.com${next}&access_token=secret`, `https://management.azure.com${next}&$skipToken=ambiguous`,
  ]) {
    let calls = 0;
    const result = await probeAzure(input, async () => { calls++; return json({ value: [], nextLink }); });
    assert.equal(result.reason, 'pagination-invalid');
    assert.equal(calls, 1);
  }
});

test('rejects repeated cursors and conflicting duplicate events', async () => {
  const repeated = await probeAzure(input, async () => json({ value: [], nextLink: `https://management.azure.com${next}` }));
  assert.equal(repeated.reason, 'pagination-repeated');
  assert.equal(repeated.requests, 2);
  const conflict = await probeAzure(input, async () => json({ value: [event(), event({ status: { value: 'Failed' } })] }));
  assert.equal(conflict.reason, 'conflicting-duplicate');
});

test('does not turn denied, expired, throttled or upstream errors into empty activity', async () => {
  for (const [status, expected] of [[401, 'unauthenticated'], [403, 'denied'], [429, 'throttled'], [500, 'unavailable']]) {
    const result = await probeAzure(input, async () => new Response('PRIVATE-PROVIDER-ERROR', { status }));
    assert.equal(result.status, expected);
    assert.equal(result.requests, 1);
    assert.equal(JSON.stringify(result).includes('PRIVATE-PROVIDER-ERROR'), false);
  }
});

test('bounds streaming bytes and aborts a request at the deadline', async () => {
  const bytes = await probeAzure({ ...input, maxBytes: 20 }, async () => json({ value: [event()] }));
  assert.equal(bytes.reason, 'byte-budget');
  const timed = await probeAzure({ ...input, timeoutMs: 5 }, async (_, options) => new Promise((_, reject) => {
    options.signal.addEventListener('abort', () => reject(new Error('private upstream URL')), { once: true });
  }));
  assert.equal(timed.reason, 'deadline');
});

test('validates JSON, scope and timestamps, and sanitizes unexpected exceptions', async () => {
  for (const payload of [[], { value: {} }, { value: [null] }, { value: [event({ subscriptionId: objectId })] },
    { value: [event({ eventTimestamp: new Date(cutoff + 1000).toISOString() })] }, { value: [event({ operationName: null })] },
    { value: [], error: { message: 'PRIVATE' } }]) {
    const result = await probeAzure(input, async () => json(payload));
    assert.equal(result.status, 'incomplete');
  }
  const invalid = await probeAzure(input, async () => new Response('{invalid', { headers: { 'Content-Type': 'application/json' } }));
  assert.equal(invalid.reason, 'invalid-response');
  const exception = await probeAzure(input, async () => { throw new Error('SECRET token and URL'); });
  assert.equal(exception.reason, 'network-error');
  assert.equal(JSON.stringify(exception).includes('SECRET'), false);
});

test('Resource Graph uses one explicit subscription and keeps source truncation visible', async () => {
  const result = await probeAzure({ ...input, source: 'changes' }, async (_, options) => {
    const request = JSON.parse(options.body);
    assert.deepEqual(request.subscriptions, [subscriptionId]);
    assert.equal(request.options.resultFormat, 'objectArray');
    assert.ok(request.query.startsWith('resourcechanges'));
    assert.equal(request.query.includes('SECRET'), false);
    return json({ data: [{ id: 'private-change', changeTime: new Date(cutoff - 1000).toISOString(), resourceType: 'Microsoft.Compute/virtualMachines', actorType: 'User', actor: 'private@example.invalid' }], resultTruncated: 'true' });
  });
  assert.equal(result.reason, 'source-truncated');
  assert.equal(result.actorKinds.user, 1);
  assert.equal(result.matchingActorRows, 0);
  assert.equal(JSON.stringify(result).includes('private@'), false);
});

test('Resource Graph pages are bounded and inventory has no attribution', async () => {
  let calls = 0;
  const result = await probeAzure({ ...input, source: 'inventory' }, async (_, options) => {
    const body = JSON.parse(options.body);
    if (calls++ === 0) return json({ data: [{ type: 'Microsoft.Storage/storageAccounts', resourceCount: 2 }], resultTruncated: 'true', $skipToken: 'next' });
    assert.equal(body.options.$skipToken, 'next');
    return json({ data: [{ type: 'constructor', resourceCount: 1 }], resultTruncated: false });
  });
  assert.equal(result.status, 'complete');
  assert.deepEqual(result.families, { storage: 2, other: 1 });
  assert.equal(result.actorBinding, 'not-established');
  assert.equal(result.successfulTerminalRows, 0);
});

test('invalid input never reaches the provider', async () => {
  for (const override of [{ subscriptionId: '../escape' }, { bearer: 'Bearer token\r\nx: bad' }, { source: 'arbitrary' },
    { days: 91 }, { source: 'changes', days: 15 }, { maxPages: 11 }, { maxBytes: 2097153 }, { timeoutMs: 60001 },
    { actor: { objectId: 'email', tenantId } }]) {
    await assert.rejects(probeAzure({ ...input, ...override }, () => assert.fail('network access')), /Invalid Azure probe input/);
  }
});

test('documented Activity scopes enforce returned scope and capture private evidence without changing reports', async () => {
  const resourceId = `/subscriptions/${subscriptionId}/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Compute/virtualMachines/PRIVATE-VM`;
  const row = event({ resourceId, operationId: 'PRIVATE-OPERATION', correlationId: 'PRIVATE-CORRELATION', description: 'PRIVATE-DESCRIPTION' });
  for (const scope of [{ resourceId }, { resourceGroup: 'PRIVATE-GROUP' }]) {
    const evidence = [];
    const report = await probeAzure({ ...input, scope, actor: { objectId, tenantId }, onEvidence: row => evidence.push(row) }, async url => {
      const filter = new URL(url).searchParams.get('$filter');
      assert.ok(filter.endsWith(scope.resourceId ? `resourceUri eq '${resourceId}'` : "resourceGroupName eq 'PRIVATE-GROUP'"));
      return json({ value: [row, row] });
    });
    assert.equal(report.status, 'complete');
    assert.equal(report.duplicateRows, 1);
    assert.equal(evidence.length, 1);
    assert.deepEqual(evidence[0], { source: 'activity', eventDataId: row.eventDataId, resourceId: resourceId.toLowerCase(),
      operationId: row.operationId, correlationId: row.correlationId, timestamp: row.eventTimestamp,
      operationName: row.operationName.value.toLowerCase(), eventName: 'EndRequest', status: 'Succeeded', family: 'compute',
      actionLabel: 'vm-write', actorMatched: true, tenantMatched: true, matchesActor: true, successfulTerminal: true });
    for (const secret of [resourceId.toLowerCase(), objectId, tenantId, 'PRIVATE-OPERATION', 'PRIVATE-CORRELATION', 'PRIVATE-DESCRIPTION']) {
      assert.equal(JSON.stringify(report).includes(secret), false);
    }
    assert.equal(JSON.stringify(evidence).includes('PRIVATE-DESCRIPTION'), false);
    const wrongScope = await probeAzure({ ...input, scope }, async () => json({ value: [event({ resourceId: resourceId.replace('PRIVATE-GROUP', 'PRIVATE-GROUP-SUFFIX') })] }));
    assert.equal(wrongScope.reason, 'scope-mismatch');
  }
  const evidence = [];
  await probeAzure({ ...input, actor: { objectId, tenantId: objectId }, onEvidence: row => evidence.push(row) }, async () => json({ value: [row] }));
  assert.equal(evidence[0].actorMatched, true);
  assert.equal(evidence[0].tenantMatched, false);
  assert.equal(evidence[0].matchesActor, false);
});

test('correlation-scoped Activity binds the UUID, returned rows and pagination without assuming actor identity', async () => {
  const correlationId = 'ABCDEF01-2345-4ABC-8DEF-0123456789AB';
  const scoped = { ...input, scope: { correlationId }, actor: { objectId, tenantId } };
  const row = event({ correlationId: correlationId.toLowerCase() });
  const captured = [];
  const report = await probeAzure({ ...scoped, onEvidence: value => captured.push(value) }, async url => {
    assert.ok(new URL(url).searchParams.get('$filter').endsWith(`correlationId eq '${correlationId}'`));
    return json({ value: [row] });
  });
  assert.equal(report.status, 'complete');
  assert.equal(report.matchingSuccessfulTerminalRows, 1);
  assert.equal(captured.length, 1);
  assert.equal(JSON.stringify(report).includes(correlationId.toLowerCase()), false);
  for (const correlation of [objectId, null, "bad'filter"]) {
    const rejected = await probeAzure(scoped, async () => json({ value: [{ ...row, correlationId: correlation }] }));
    assert.equal(rejected.reason, 'scope-mismatch');
  }
  const otherActor = await probeAzure(scoped, async () => json({ value: [{ ...row, claims: {} }] }));
  assert.equal(otherActor.successfulTerminalRows, 1);
  assert.equal(otherActor.matchingSuccessfulTerminalRows, 0);
  let calls = 0;
  const invalidPage = await probeAzure(scoped, async () => {
    calls++;
    return json({ value: [row], nextLink: `${next}&$filter=${encodeURIComponent(`correlationId eq '${objectId}'`)}` });
  });
  assert.equal(invalidPage.reason, 'pagination-invalid');
  assert.equal(calls, 1);
  for (const scope of [{ correlationId: "bad'filter" }, { correlationId: 1 }, { correlationId, resourceGroup: 'private' }]) {
    await assert.rejects(probeAzure({ ...input, scope }, () => assert.fail('network called')), /Invalid Azure probe input/);
  }
  await assert.rejects(probeAzure({ ...scoped, source: 'changes' }, () => assert.fail('network called')), /Invalid Azure probe input/);
});

test('invalid scopes and capture options fail before requests and scoped continuation cannot change filters', async () => {
  const resourceId = `/subscriptions/${subscriptionId}/resourceGroups/fixture`;
  for (const scope of [null, {}, [], { arbitrary: 'filter' }, { resourceId, resourceGroup: 'fixture' },
    { resourceId: resourceId.replace(subscriptionId, objectId) }, { resourceId: `${resourceId}' or true` },
    { resourceId: `${resourceId}/../escape` }, { resourceId: `${resourceId}?secret` },
    { resourceGroup: "fixture' or true" }, { resourceGroup: 'fixture/' }, { resourceGroup: 'trailing.' }]) {
    await assert.rejects(probeAzure({ ...input, scope }, () => assert.fail('network')), /Invalid Azure probe input/);
  }
  await assert.rejects(probeAzure({ ...input, source: 'changes', scope: { resourceId } }, () => assert.fail('network')), /Invalid Azure probe input/);
  await assert.rejects(probeAzure({ ...input, onEvidence: true }, () => assert.fail('network')), /Invalid Azure probe input/);
  let calls = 0;
  const report = await probeAzure({ ...input, scope: { resourceId } }, async () => {
    calls++;
    return json({ value: [], nextLink: `https://management.azure.com${next}&$filter=changed` });
  });
  assert.equal(report.reason, 'pagination-invalid');
  assert.equal(calls, 1);
});

test('ARG captures bounded property differences privately and rejects foreign targets or malformed metadata', async () => {
  const targetResourceId = `/subscriptions/${subscriptionId}/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG`;
  const row = { id: 'PRIVATE-CHANGE', targetResourceId, changeTime: new Date(cutoff - 1000).toISOString(),
    resourceType: 'Microsoft.Network/networkSecurityGroups', changeType: 'Update', actorType: 'User', actor: 'PRIVATE-EMAIL',
    operation: 'Microsoft.Network/networkSecurityGroups/write', correlationId: 'PRIVATE-CORRELATION', changesCount: 1,
    changes: { 'properties.securityRules': { previousValue: ['PRIVATE-BEFORE'], newValue: ['PRIVATE-AFTER'], isTruncated: 'false', extra: 'PRIVATE-EXTRA' } } };
  const evidence = [];
  const report = await probeAzure({ ...input, source: 'changes', onEvidence: row => evidence.push(row) }, async (_, options) => {
    const query = JSON.parse(options.body).query;
    for (const field of ['properties.targetResourceId', 'properties.changeAttributes.correlationId', 'properties.changeAttributes.changesCount', 'changes=properties.changes']) assert.ok(query.includes(field));
    return json({ data: [row], resultTruncated: false });
  });
  assert.equal(report.status, 'complete');
  assert.equal(evidence[0].source, 'changes');
  assert.equal(evidence[0].targetResourceId, targetResourceId.toLowerCase());
  assert.deepEqual(evidence[0].changes, { 'properties.securityRules': { previousValue: ['PRIVATE-BEFORE'], newValue: ['PRIVATE-AFTER'], isTruncated: 'false' } });
  assert.equal(JSON.stringify(report).includes('PRIVATE'), false);
  assert.equal(JSON.stringify(evidence).includes('PRIVATE-EMAIL'), false);
  assert.equal(JSON.stringify(evidence).includes('PRIVATE-EXTRA'), false);
  for (const invalid of [{ targetResourceId: targetResourceId.replace(subscriptionId, objectId) }, { targetResourceId: null },
    { changes: [] }, { changes: { bad: { isTruncated: 'unknown' } } }, { changesCount: -1 }, { correlationId: {} }]) {
    const result = await probeAzure({ ...input, source: 'changes', onEvidence: () => assert.fail('captured invalid row') }, async () => json({ data: [{ ...row, ...invalid }], resultTruncated: false }));
    assert.equal(result.status, 'incomplete');
    assert.ok(['scope-mismatch', 'invalid-response'].includes(result.reason));
  }
});

test('private capture failures are classified without exposing callback errors', async () => {
  const result = await probeAzure({ ...input, onEvidence: () => { throw new Error('PRIVATE-CALLBACK-ERROR'); } }, async () => json({ value: [event()] }));
  assert.equal(result.reason, 'evidence-callback');
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
});

test('older Activity slices have inclusive explicit millisecond bounds and preserve the observation cutoff', async () => {
  const before = cutoff - 14 * 86400000 - 1;
  const report = await probeAzure({ ...input, days: 90, before }, async url => {
    const filter = new URL(url).searchParams.get('$filter');
    assert.ok(filter.includes(new Date(cutoff - 90 * 86400000).toISOString()));
    assert.ok(filter.includes(new Date(before).toISOString()));
    return json({ value: [event({ eventTimestamp: new Date(before).toISOString() })] });
  });
  assert.equal(report.status, 'complete');
  assert.equal(report.windowDays, 90);
  assert.equal(report.windowEndOffsetMs, 14 * 86400000 + 1);
  const outside = await probeAzure({ ...input, days: 90, before }, async () => json({ value: [event({ eventTimestamp: new Date(before + 1).toISOString() })] }));
  assert.equal(outside.reason, 'invalid-response');
  for (const extra of [{ before: cutoff + 1 }, { before: cutoff - 90 * 86400000 - 1 }, { before: 'yesterday' }, { source: 'changes', days: 14, before }]) {
    await assert.rejects(probeAzure({ ...input, days: 90, ...extra }, () => assert.fail('network')), /Invalid Azure probe input/);
  }
});

const deploymentId = `/subscriptions/${subscriptionId}/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Resources/deployments/PRIVATE-DEPLOYMENT`;
const deploymentInput = { ...input, source: 'deployment', scope: { deploymentId } };
const deploymentOperation = (overrides = {}) => ({ operationId: 'operation-1', id: `${deploymentId}/operations/operation-1`, properties: {
  timestamp: new Date(cutoff - 1000).toISOString(), provisioningState: 'Succeeded', provisioningOperation: 'Create', statusCode: 'Created',
  targetResource: { id: `/subscriptions/${subscriptionId}/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG` },
  request: { content: 'PRIVATE-REQUEST' }, response: { content: 'PRIVATE-RESPONSE' }, statusMessage: { error: { message: 'PRIVATE-ERROR' } },
}, ...overrides });

test('fixed deployment GET captures only scoped metadata and distinguishes observation time from Activity cutoff', async () => {
  const evidence = [];
  const timestamp = new Date(cutoff + 1000).toISOString();
  const report = await probeAzure({ ...deploymentInput, onEvidence: row => evidence.push(row) }, async (url, options) => {
    assert.equal(new URL(url).pathname, deploymentId);
    assert.equal(new URL(url).searchParams.get('api-version'), '2025-04-01');
    assert.equal(options.method, 'GET');
    assert.equal(options.body, undefined);
    return json({ id: deploymentId, properties: { timestamp, provisioningState: 'Succeeded', correlationId: 'PRIVATE-CORRELATION',
      parameters: { password: 'PRIVATE-PASSWORD' }, outputs: { data: 'PRIVATE-OUTPUT' }, error: { message: 'PRIVATE-ERROR' } } });
  });
  assert.equal(report.status, 'complete');
  assert.equal(report.windowDays, null);
  assert.equal(report.requestBodyBytes, 0);
  assert.equal(evidence.length, 1);
  assert.deepEqual(Object.keys(evidence[0]).sort(), ['source', 'deploymentId', 'timestamp', 'observedAt', 'provisioningState', 'correlationId'].sort());
  assert.equal(evidence[0].deploymentId, deploymentId.toLowerCase());
  assert.equal(evidence[0].timestamp, timestamp);
  assert.equal(evidence[0].provisioningState, 'Succeeded');
  assert.ok(Number.isSafeInteger(evidence[0].observedAt));
  for (const value of ['PRIVATE-PASSWORD', 'PRIVATE-OUTPUT', 'PRIVATE-ERROR']) assert.equal(JSON.stringify(evidence).includes(value), false);
  assert.equal(JSON.stringify(report).includes('PRIVATE'), false);
});

test('deployment template export fixes POST scope and releases only normalized facts without raw template fields', async () => {
  const evidence = [];
  const report = await probeAzure({ ...deploymentInput, source: 'deployment-template',
    body: { private: 'PRIVATE-UNTRUSTED-BODY' }, onEvidence: row => evidence.push(row) }, async (url, options) => {
    assert.equal(url, `https://management.azure.com${deploymentId}/exportTemplate?api-version=2025-04-01`);
    assert.equal(options.method, 'POST');
    assert.equal(options.body, undefined);
    assert.equal(options.redirect, 'error');
    assert.equal(options.credentials, 'omit');
    return json({ template: { parameters: { password: { defaultValue: 'PRIVATE-PASSWORD' } },
      outputs: { private: { value: 'PRIVATE-OUTPUT' } }, resources: [{ type: 'Microsoft.Web/sites', name: 'PRIVATE-APP',
        properties: { httpsOnly: true, siteConfig: { linuxFxVersion: 'NODE|24-lts', appSettings: [{ name: 'SECRET', value: 'PRIVATE-SECRET' }] } } }],
      private: 'PRIVATE-TEMPLATE' } });
  });
  assert.equal(report.status, 'complete');
  assert.equal(report.windowDays, null);
  assert.equal(report.requestBodyBytes, 0);
  assert.equal(report.submittedFactCount, 2);
  assert.equal(report.rows, 1);
  assert.deepEqual(Object.keys(evidence[0]).sort(), ['source', 'deploymentId', 'observedAt', 'submittedFacts'].sort());
  assert.equal(evidence[0].deploymentId, deploymentId.toLowerCase());
  assert.ok(Number.isSafeInteger(evidence[0].observedAt));
  assert.deepEqual(evidence[0].submittedFacts, [
    { resourceKind: 'web-app', field: 'httpsOnly', value: true },
    { resourceKind: 'web-app', field: 'linuxFxVersion', value: 'NODE|24-lts' },
  ]);
  for (const value of ['PRIVATE-PASSWORD', 'PRIVATE-OUTPUT', 'PRIVATE-TEMPLATE', 'PRIVATE-UNTRUSTED-BODY', 'PRIVATE-APP', 'PRIVATE-SECRET']) {
    assert.equal(JSON.stringify(evidence).includes(value), false);
  }
  assert.equal(JSON.stringify(report).includes('PRIVATE'), false);
});

test('template export rejects malformed templates, foreign scopes and unsupported continuation without capture', async () => {
  const templateInput = { ...deploymentInput, source: 'deployment-template', onEvidence: () => assert.fail('invalid capture') };
  for (const scope of [undefined, { deploymentId: deploymentId.replace(subscriptionId, objectId) },
    { deploymentId: `https://evil.invalid${deploymentId}` }, { deploymentId: `${deploymentId}/exportTemplate` },
    { deploymentId: `${deploymentId}?api-version=other` }, { deploymentId, body: {} }]) {
    await assert.rejects(probeAzure({ ...templateInput, scope }, () => assert.fail('network')), /Invalid Azure probe input/);
  }
  for (const template of [undefined, null, [], true, 'PRIVATE-TEMPLATE']) {
    const report = await probeAzure(templateInput, async () => json({ template }));
    assert.equal(report.reason, 'invalid-response');
    assert.equal(report.requests, 1);
  }
  let calls = 0;
  const continuation = await probeAzure(templateInput, async () => {
    calls++;
    return json({ template: {}, nextLink: 'https://evil.invalid/private' });
  });
  assert.equal(continuation.reason, 'pagination-invalid');
  assert.equal(calls, 1);
  const denied = await probeAzure(templateInput, async () => new Response('PRIVATE-ERROR', { status: 403 }));
  assert.equal(denied.status, 'denied');
  assert.equal(denied.bytes, 0);
  assert.equal(JSON.stringify(denied).includes('PRIVATE'), false);
});

test('deployment operations use their documented route and bounded same-scope continuation', async () => {
  const path = `/subscriptions/${subscriptionId}/resourcegroups/PRIVATE-GROUP/deployments/PRIVATE-DEPLOYMENT/operations`;
  const evidence = [];
  let requests = 0;
  const first = deploymentOperation();
  const report = await probeAzure({ ...deploymentInput, source: 'deployment-operations', onEvidence: row => evidence.push(row) }, async (url, options) => {
    requests++;
    assert.equal(new URL(url).pathname, path);
    assert.equal(options.method, 'GET');
    return json(requests === 1 ? { value: [first], nextLink: `https://management.azure.com${path}?api-version=2025-04-01&$skiptoken=next` }
      : { value: [first, deploymentOperation({ operationId: 'operation-2', id: `${deploymentId}/operations/operation-2`,
        properties: { timestamp: first.properties.timestamp, provisioningState: 'Failed', provisioningOperation: 'Action', statusCode: 'PRIVATE-ERROR-CODE' } })] });
  });
  assert.equal(report.status, 'complete');
  assert.equal(report.requests, 2);
  assert.equal(report.duplicateRows, 1);
  assert.equal(evidence[0].targetResourceId, first.properties.targetResource.id.toLowerCase());
  assert.equal(evidence[1].provisioningState, 'Failed');
  assert.equal(evidence[1].statusCode, null);
  for (const value of ['PRIVATE-REQUEST', 'PRIVATE-RESPONSE', 'PRIVATE-ERROR']) assert.equal(JSON.stringify(evidence).includes(value), false);
  for (const nextLink of [`https://evil.invalid${path}?$skiptoken=next`,
    `https://management.azure.com${path.replace('PRIVATE-GROUP', 'OTHER-GROUP')}?$skiptoken=next`,
    `https://management.azure.com${path}?api-version=2015-04-01&$skiptoken=next`,
    `https://management.azure.com${path}?$skiptoken=next&$filter=changed`]) {
    let calls = 0;
    const invalid = await probeAzure({ ...deploymentInput, source: 'deployment-operations' }, async () => { calls++; return json({ value: [], nextLink }); });
    assert.equal(invalid.reason, 'pagination-invalid');
    assert.equal(calls, 1);
  }
});

test('deployment input and responses reject foreign scopes, malformed times and missing records explicitly', async () => {
  for (const scope of [undefined, {}, { resourceId: deploymentId }, { deploymentId, arbitrary: true },
    { deploymentId: deploymentId.replace(subscriptionId, objectId) }, { deploymentId: `${deploymentId}?token=secret` },
    { deploymentId: deploymentId.replace('PRIVATE-DEPLOYMENT', '..') }, { deploymentId: `${deploymentId}/operations/operation-1` }]) {
    await assert.rejects(probeAzure({ ...deploymentInput, scope }, () => assert.fail('network')), /Invalid Azure probe input/);
  }
  const wrongDeployment = await probeAzure(deploymentInput, async () => json({ id: deploymentId.replace('PRIVATE-DEPLOYMENT', 'OTHER'), properties: {} }));
  assert.equal(wrongDeployment.reason, 'scope-mismatch');
  for (const properties of [{ ...deploymentOperation().properties, targetResource: { id: deploymentId.replace(subscriptionId, objectId) } },
    { ...deploymentOperation().properties, timestamp: 'invalid' }, { ...deploymentOperation().properties, timestamp: new Date(Date.now() + 120000).toISOString() },
    { ...deploymentOperation().properties, provisioningOperation: {} }]) {
    const report = await probeAzure({ ...deploymentInput, source: 'deployment-operations', onEvidence: () => assert.fail('invalid capture') }, async () => json({ value: [deploymentOperation({ properties })] }));
    assert.ok(['scope-mismatch', 'invalid-response'].includes(report.reason));
  }
  const foreignRow = await probeAzure({ ...deploymentInput, source: 'deployment-operations' }, async () => json({ value: [deploymentOperation({ id: `${deploymentId}-OTHER/operations/operation-1` })] }));
  assert.equal(foreignRow.reason, 'scope-mismatch');
  for (const status of [404, 403, 429]) {
    const report = await probeAzure(deploymentInput, async () => new Response('PRIVATE-ERROR-BODY', { status }));
    assert.equal(report.httpStatus, status);
    assert.equal(report.reason, 'http-status');
    assert.equal(report.status, status === 404 ? 'unavailable' : status === 403 ? 'denied' : 'throttled');
    assert.equal(report.requests, 1);
    assert.equal(report.bytes, 0);
  }
});

test('byte accounting measures UTF-8 request bodies, consumed response chunks and their overshoot', async () => {
  const body = { data: [{ type: 'private-é', resourceCount: 1 }], resultTruncated: false };
  const responseBytes = new TextEncoder().encode(JSON.stringify(body)).byteLength;
  let requestBytes;
  const report = await probeAzure({ ...input, source: 'inventory', maxBytes: 1 }, async (_, options) => {
    requestBytes = new TextEncoder().encode(options.body).byteLength;
    return json(body);
  });
  assert.equal(report.reason, 'byte-budget');
  assert.equal(report.requests, 1);
  assert.equal(report.requestBodyBytes, requestBytes);
  assert.equal(report.bytes, responseBytes);
  assert.equal(report.byteOvershoot, responseBytes - 1);
});
