import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectTenantReceipt, inspectActivityReceipt } from './source-receipt.mjs';

import { fixture, tenant, activity } from './test-fixtures.mjs';
const uuid = digit => `${digit.repeat(8)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(12)}`;
const subscription = uuid('a'), correlation = uuid('b');
const inspect = (step, value) => (step === 'tenant' ? inspectTenantReceipt : inspectActivityReceipt)(value.receipt, value.context);
const invalid = /AZURE_PRIVATE_SOURCE_RECEIPT_INVALID/;

test('tenant receipt derives exact native references and mandatory header/scope/state obligations', () => {
  const value = fixture('tenant'), result = inspect('tenant', value);
  assert.equal(result.headerObligations.length, 1);
  assert.equal(result.requestUuidObligations.length, 1);
  assert.equal(result.body.subscription.start, value.bodyStart + value.holes[0].start);
  assert.equal(result.body.state.requiredPredicate, 'subscription-enabled');
  assert.equal(result.requestUuidObligations[0].reference.hash, result.body.subscription.hash);
  for (const privateValue of [subscription, uuid('c'), 'Enabled', 'PRIVATE_CREDENTIAL']) assert.ok(!JSON.stringify(result).includes(privateValue));
});

test('complete Activity rows each require request subscription/correlation links and preserve claims chunks', () => {
  const body = activity(); body.value.push(structuredClone(body.value[0]));
  const value = fixture('activity', { value: body }), result = inspect('activity', value);
  assert.equal(result.body.rows.length, 2); assert.equal(result.requestUuidObligations.length, 4);
  assert.equal(result.body.requiresCompleteCoverageProofs, true);
  for (const [i, row] of result.body.rows.entries()) {
    assert.equal(row.claims.chunks.length, 2); assert.equal(Object.hasOwn(row.claims, 'hash'), false);
    assert.equal(result.requestUuidObligations[i * 2].reference.hash, row.subscription.hash);
    assert.equal(result.requestUuidObligations[i * 2 + 1].reference.hash, row.correlationId.hash);
    assert.equal(row.claims.chunks[1].start - row.claims.chunks[0].start, 512);
  }
  for (const privateValue of ['privateEmployerKey', 'private-value', subscription, correlation, 'Succeeded', '2026-10-29']) {
    assert.ok(!JSON.stringify(result).includes(privateValue));
  }
});

test('field roles follow authenticated JSON keys rather than atom order', () => {
  const value = fixture('tenant', { value: { state: 'Enabled', tenantId: uuid('c'), subscriptionId: subscription } });
  const result = inspect('tenant', value);
  assert.equal(result.body.subscription.start, value.bodyStart + value.holes[2].start);
  assert.equal(result.body.tenant.start, value.bodyStart + value.holes[1].start);
  assert.equal(result.body.state.start, value.bodyStart + value.holes[0].start);
});

test('chunked body wire offsets remain exact; hidden Date and reason require header proofs', () => {
  const value = fixture('tenant', { chunked: true, date: true, reason: 'Private reason' });
  const result = inspect('tenant', value);
  assert.equal(result.body.subscription.start, value.bodyStart + value.holes[0].start);
  assert.equal(result.headerObligations.length, 3);
  assert.ok(result.headerObligations.every(obligation => obligation.circuitId === 'header-v1'));
});

test('source, nonce, role and packaged-build substitutions fail closed', () => {
  for (const mutate of [
    r => { r.server_name = 'graph.microsoft.com'; }, r => { r.session.method = 'AZURE_LOCAL_PILOT'; },
    r => { r.session.nonceMac = 'c'.repeat(43); }, r => { r.session.step = 'identity'; },
    r => { r.session.pluginSha256 = 'c'.repeat(64); }, r => { r.session.id = uuid('3'); },
  ]) {
    const value = fixture('tenant'); mutate(value.receipt);
    assert.throws(() => inspect('tenant', value), invalid);
  }
  const value = fixture('tenant'); value.context.step = 'activity';
  assert.throws(() => inspect('tenant', value), invalid);
});

test('changed windows, narrowed filters, projections and API versions fail closed', () => {
  for (const change of [
    url => url.searchParams.set('api-version', '2020-01-01'),
    url => url.searchParams.set('$select', 'claims,eventTimestamp'),
    url => url.searchParams.set('$filter', url.searchParams.get('$filter').replace('2026-10-17', '2026-10-18')),
    url => url.searchParams.set('$filter', url.searchParams.get('$filter') + " and resourceUri eq 'private'"),
    url => url.searchParams.set('$top', '1'),
  ]) assert.throws(() => inspect('activity', fixture('activity', { url: change })), invalid);
  const value = fixture('activity'); value.context.cutoffMs++;
  assert.throws(() => inspect('activity', value), invalid);
});

test('missing coverage, unexpected keys and missing rows cannot pass source inspection', () => {
  for (const change of [
    body => { body.nextLink = 'private'; }, body => { body.value = []; },
    body => { delete body.value[0].correlationId; },
    body => { body.value[0].claimsUnexpected = body.value[0].claims; delete body.value[0].claims; },
  ]) {
    const body = activity(); change(body);
    assert.throws(() => inspect('activity', fixture('activity', { value: body })), invalid);
  }
});

test('unknown headers, Origin and ambiguous or unsupported HTTP framing fail closed', () => {
  for (const options of [
    { requestExtra: 'Origin: https://portal.azure.com\r\n' },
    { requestExtra: 'Cookie: private\r\n' }, { responseExtra: 'Server: private\r\n' },
    { responseExtra: 'Content-Length: 1\r\n' }, { responseExtra: 'Content-Encoding: gzip\r\n' },
    { responseExtra: 'Transfer-Encoding: chunked\r\n' },
  ]) assert.throws(() => inspect('tenant', fixture('tenant', options)), invalid);
});

test('native atoms and composed claims cannot cross HTTP chunk framing', () => {
  assert.throws(() => inspect('tenant', fixture('tenant', { chunked: true, splitAt: holes => holes[0].start + 10 })), invalid);
  assert.throws(() => inspect('activity', fixture('activity', { chunked: true, splitAt: holes => holes[0].end })), invalid);
});

test('tampered native range coverage and unauthenticated transcript bytes fail closed', () => {
  for (const mutate of [
    r => { r.config.recv.find(range => range.handler.action.kind === 'HASH').end--; },
    r => { r.transcript.recv = 'X' + r.transcript.recv.slice(1); },
    r => { r.results.find(result => result.type === 'RECV' && result.action.kind === 'HASH').value = 'bad'; },
    r => { r.config.sent.find(range => range.handler.action.kind === 'HASH').start++; },
  ]) {
    const value = fixture('tenant'); mutate(value.receipt);
    assert.throws(() => inspect('tenant', value), invalid);
  }
});

const measuredTenant = () => ({ ...tenant(), id: `/subscriptions/${subscription}`, displayName: 'Private employer',
  authorizationSource: 'RoleBased', subscriptionPolicies: { locationPlacementId: 'Private', quotaId: 'Private quota', spendingLimit: 'Off' },
  managedByTenants: [], privateTag: [{ category: 'Private', privateLabel: 'Employer data' }] });

test('measured tenant extras remain private with complete atom and private-key/object obligations', () => {
  const value = fixture('tenant', { value: measuredTenant(), privateTenantExtra: 'privateTag', responseHeaders: {
    'x-ms-request-id': uuid('d'), 'x-msedge-ref': 'private-routing', 'x-cache': 'private-cache', connection: 'close',
  } });
  const result = inspect('tenant', value);
  assert.equal(result.atomObligations.length, 6); assert.equal(result.extraObligations.length, 1);
  assert.ok(result.atomObligations.every(slot => slot.circuitId === 'atom-v1' && slot.kind === 1 && slot.direction === 'RECV'));
  assert.equal(result.extraObligations[0].name, 'tenant-extra-v1');
  assert.equal(result.extraObligations[0].key.kind, 1); assert.equal(result.extraObligations[0].object.kind, 6);
  assert.equal(result.headerObligations.length, 5);
  for (const secret of ['Private employer', 'Private quota', 'privateTag', 'privateLabel', 'Employer data', 'private-routing']) {
    assert.ok(!JSON.stringify(result).includes(secret)); assert.ok(!value.receipt.transcript.recv.includes(secret));
  }
});

test('tenant extra shape, key privacy and measured policy metadata are fail closed', () => {
  assert.throws(() => inspect('tenant', fixture('tenant', { value: measuredTenant() })), invalid);
  for (const mutate of [
    body => { body.privateTag = []; }, body => { body.privateTag.push({ private: 'extra' }); },
    body => { body.privateTag = [{ private: 'x'.repeat(129) }]; },
    body => { body.managedByTenants = [{ tenantId: uuid('d') }]; },
    body => { body.subscriptionPolicies.extra = 'private'; },
  ]) {
    const body = measuredTenant(); mutate(body);
    assert.throws(() => inspect('tenant', fixture('tenant', { value: body, privateTenantExtra: 'privateTag' })), invalid);
  }
  const body = measuredTenant(); body.subscriptionPolicies.quotaId = true;
  const provisional = inspect('tenant', fixture('tenant', { value: body, privateTenantExtra: 'privateTag' }));
  // An opaque boolean can only be rejected by its mandatory proof of string kind.
  assert.ok(provisional.atomObligations.every(slot => slot.kind === 1));
});

test('measured Activity metadata requires private string atom proofs without changing selected-row roles', () => {
  const body = activity(), row = body.value[0];
  row.id = 'private-event-path-' + 'x'.repeat(250); row.submissionTimestamp = '2026-10-29T12:00:00Z';
  row.category = { value: 'Private category', localizedValue: 'Private category display' };
  for (const name of ['eventName', 'operationName', 'status']) row[name].localizedValue = `Private ${name}`;
  const value = fixture('activity', { value: body, responseHeaders: {
    'access-control-allow-origin': '*', 'api-supported-versions': 'private-version-list', 'mise-correlation-id': uuid('d'),
    'request-context': 'private-context', 'x-ms-operation-identifier': 'private-operation', vary: 'private-vary',
  } });
  const result = inspect('activity', value);
  assert.equal(result.atomObligations.length, 7);
  assert.equal(result.atomObligations.filter(slot => slot.length > 64).length, 1);
  assert.equal(result.requestUuidObligations.length, 2); assert.equal(result.extraObligations.length, 0);
  assert.equal(result.headerObligations.length, 7);
  assert.ok(!JSON.stringify(result).includes('Private'));
  assert.throws(() => inspect('tenant', fixture('tenant', { responseExtra: 'x-cache: private-cache\r\n' })), invalid);
});
