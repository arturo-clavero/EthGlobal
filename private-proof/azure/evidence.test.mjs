import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAzureEvidence, countPotentialAzureChangeFacts, extractAzureTemplateFacts, selectAzureEvidence, summarizeAzureEvidence } from './evidence.mjs';

const nsg = '/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG';
const rule = `${nsg}/securityRules/PRIVATE-RULE`;
const timestamp = Date.parse('2026-10-29T08:00:00Z');
const activity = (overrides = {}) => ({ source: 'activity', eventDataId: 'PRIVATE-EVENT', resourceId: rule,
  operationId: 'PRIVATE-OPERATION', correlationId: 'PRIVATE-CORRELATION', timestamp,
  operationName: 'Microsoft.Network/networkSecurityGroups/securityRules/write', eventName: 'EndRequest', status: 'Succeeded',
  family: 'networking', actionLabel: 'network-rule-write', actorMatched: true, tenantMatched: true, matchesActor: true,
  successfulTerminal: true, ...overrides });
const path = field => `properties.securityRules[PRIVATE-RULE].properties.${field}`;
const changes = (overrides = {}) => ({ source: 'changes', id: 'PRIVATE-CHANGE', targetResourceId: nsg,
  correlationId: 'PRIVATE-CORRELATION', changeTime: timestamp + 30000,
  changes: { [path('access')]: { previousValue: null, newValue: 'Deny' },
    [path('direction')]: { previousValue: null, newValue: 'Inbound' },
    [path('protocol')]: { previousValue: null, newValue: 'Tcp' },
    [path('destinationPortRange')]: { previousValue: null, newValue: '8443' },
    [path('priority')]: { previousValue: null, newValue: '400' },
    [path('sourceAddressPrefix')]: { previousValue: null, newValue: '10.20.30.0/24' } }, ...overrides });

test('joins exact private NSG parent/correlation and exposes only normalized excerpts', () => {
  const candidates = buildAzureEvidence([activity(), changes()]);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].eligible, true);
  assert.equal(candidates[0].facts.length, 6);
  const result = summarizeAzureEvidence(candidates);
  assert.deepEqual(result.evidence[0].linkLabels, ['exact-correlation-and-nsg-parent']);
  assert.equal(result.evidence[0].technicalFacts.find(fact => fact.field === 'destinationPortRange').newValue, 'single-user-port');
  assert.equal(result.evidence[0].technicalFacts.every(fact => fact.change === 'added'), true);
  assert.equal(result.evidence[0].depth.outcome, 'control-plane-only');
  for (const secret of ['PRIVATE', '11111111', '8443', '400', '10.20.30', String(timestamp)]) {
    assert.equal(JSON.stringify(result).includes(secret), false, secret);
  }
});

test('discovery prioritizes only supported potential facts and does not grant actor or action credit', () => {
  const record = changes();
  assert.equal(countPotentialAzureChangeFacts(record), 6);
  assert.equal(summarizeAzureEvidence(buildAzureEvidence([record])).counts.selectedActions, 0);
  for (const override of [null, { ...record, changes: [] }, { ...record, targetResourceId: '/private/unsupported' },
    { ...record, changes: { [path('priority')]: { previousValue: '100', newValue: '100' } } },
    { ...record, changes: { [path('access')]: { previousValue: null, newValue: 'PRIVATE-UNKNOWN' } } },
    { ...record, changes: { [path('access')]: { previousValue: null, newValue: 'Deny', isTruncated: true } } }]) {
    assert.equal(countPotentialAzureChangeFacts(override), 0);
  }
});

test('time proximity, missing correlation and similar resource prefixes cannot link evidence', () => {
  for (const changed of [changes({ correlationId: 'OTHER' }), changes({ correlationId: null }),
    changes({ targetResourceId: `${nsg}-other` }), changes({ targetResourceId: `${nsg}/securityRules/OTHER` })]) {
    const result = summarizeAzureEvidence(buildAzureEvidence([activity(), changed]));
    assert.equal(result.counts.linkedConfigurationRecords, 0);
    assert.equal(result.counts.unlinkedConfigurationRecords, 1);
    assert.equal(result.evidence[0].technicalFacts.length, 0);
  }
  const sibling = changes({ changes: { 'properties.securityRules[OTHER].properties.access': { previousValue: null, newValue: 'Deny' } } });
  const result = summarizeAzureEvidence(buildAzureEvidence([activity(), sibling]));
  assert.equal(result.evidence[0].technicalFacts.length, 0);
  assert.equal(result.exclusions.configurationFields['different-rule'], 1);
});

test('rejected actors and start-only correlations cannot authorize a configuration link', () => {
  for (const rejected of [{ actorMatched: false }, { eventName: 'BeginRequest', successfulTerminal: false }]) {
    const candidates = buildAzureEvidence([activity({ correlationId: 'ACCEPTED-ONLY' }),
      activity({ eventDataId: 'REJECTED', timestamp: timestamp + 3600000, ...rejected }), changes()]);
    const result = summarizeAzureEvidence(candidates);
    assert.equal(result.counts.linkedConfigurationRecords, 0);
    assert.equal(result.evidence[0].technicalFacts.length, 0);
    assert.equal(candidates.find(row => row.eligible).timestamp, timestamp);
  }
});

test('actor mismatch, failed/start-only events and unknown operations remain explicit exclusions', () => {
  const variants = [{ actorMatched: false }, { tenantMatched: false }, { matchesActor: false },
    { status: 'Failed', successfulTerminal: false }, { eventName: 'BeginRequest' },
    { operationName: 'PRIVATE/unknown/write', family: 'PRIVATE-FAMILY', actionLabel: 'PRIVATE-ACTION' }];
  const candidates = buildAzureEvidence(variants.map((override, index) => activity({ eventDataId: `e${index}`,
    operationId: `o${index}`, ...override })));
  assert.deepEqual(selectAzureEvidence(candidates), []);
  const result = summarizeAzureEvidence(candidates);
  assert.deepEqual(result.exclusions.activityRows, { 'actor-or-tenant-mismatch': 3,
    'failed-terminal': 1, 'not-successful-terminal': 1, 'unrecognized-action': 1 });
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
});

test('event duplicates and logical-operation rows collapse; conflicting event identities fail closed', () => {
  const start = activity({ eventDataId: 'START', eventName: 'BeginRequest', successfulTerminal: false });
  const end = activity({ eventDataId: 'END' });
  const candidates = buildAzureEvidence([start, end, end, activity({ eventDataId: 'END-SECOND' })]);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].rows.length, 3);
  assert.equal(selectAzureEvidence(candidates).length, 1);
  const counts = summarizeAzureEvidence(candidates).counts;
  assert.equal(counts.logicalActions, 1); assert.equal(counts.duplicateActivityRows, 1);
  assert.throws(() => buildAzureEvidence([end, { ...end, actorMatched: false }]), /EVIDENCE_CONFLICT/);
  const fallback = buildAzureEvidence([activity({ operationId: null }), activity({ operationId: null, eventDataId: 'OTHER' })]);
  assert.equal(fallback.length, 2);
  assert.equal(summarizeAzureEvidence(fallback).evidence[0].missingDepthLabels.includes('logical-action-identity-uncertain'), true);
});

test('reordered ARG object properties are duplicates but changed values still conflict', () => {
  const first = changes();
  const reordered = { ...first, changes: Object.fromEntries(Object.entries(first.changes).reverse()
    .map(([key, value]) => [key, Object.fromEntries(Object.entries(value).reverse())])) };
  const result = summarizeAzureEvidence(buildAzureEvidence([activity(), first, reordered]));
  assert.equal(result.counts.configurationRecords, 1);
  assert.equal(result.counts.linkedConfigurationRecords, 1);
  assert.equal(result.counts.distinctSelectedFacts, 6);
  reordered.changes[path('destinationPortRange')].newValue = '443';
  assert.throws(() => buildAzureEvidence([activity(), first, reordered]), /EVIDENCE_CONFLICT/);
});

test('case differences retain the same private logical key and false terminal metadata does not pass', () => {
  const a = activity(), b = { ...a, resourceId: a.resourceId.toLowerCase(), operationName: a.operationName.toLowerCase() };
  assert.equal(buildAzureEvidence([a])[0].key, buildAzureEvidence([b])[0].key);
  assert.equal(buildAzureEvidence([activity({ timestamp: new Date(timestamp).toISOString() })])[0].eligible, true);
  assert.equal(buildAzureEvidence([activity({ status: 'Failed', successfulTerminal: true })])[0].eligible, false);
  const conflicts = buildAzureEvidence([activity(), activity({ eventDataId: 'failed', status: 'Failed', successfulTerminal: false })]);
  assert.equal(conflicts[0].exclusionReason, 'conflicting-terminal-status');
});

test('numeric ARG rule indexes require exact private sibling identity and never expose it', () => {
  const properties = Object.fromEntries(Object.entries(changes().changes).map(([key, value]) =>
    [key.replace('[PRIVATE-RULE]', '[0]'), value]));
  const named = { ...properties, 'properties.securityRules[0].name': { newValue: 'PRIVATE-RULE' },
    'properties.securityRules[0].id': { newValue: rule } };
  const result = summarizeAzureEvidence(buildAzureEvidence([activity(), changes({ changes: named })]));
  assert.equal(result.evidence[0].technicalFacts.length, 6);
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
  for (const unsafe of [properties, { ...named, 'properties.securityRules[0].name': { newValue: 'OTHER' } },
    { ...named, 'properties.securityRules[0].id': { newValue: `${rule}-OTHER` } },
    { ...named, 'properties.securityRules[0].id': { newValue: rule, isTruncated: true } }]) {
    const summary = summarizeAzureEvidence(buildAzureEvidence([activity(), changes({ changes: unsafe })]));
    assert.equal(summary.evidence[0].technicalFacts.length, 0);
  }
});

test('no-op, truncated, unknown and private configuration values never become technical facts', () => {
  const record = changes({ changes: {
    [path('access')]: { previousValue: 'Deny', newValue: 'Deny' },
    [path('direction')]: { previousValue: null, newValue: 'Inbound', isTruncated: 'true' },
    [path('protocol')]: { previousValue: null, newValue: 'PRIVATE-PROTOCOL' },
    [path('sourceAddressPrefix')]: { previousValue: null, newValue: 'PRIVATE-ADDRESS.example' },
    [path('description')]: { previousValue: null, newValue: 'PRIVATE-DESCRIPTION' },
    [path('destinationPortRange')]: { previousValue: '8443', newValue: '9443' },
  } });
  const result = summarizeAzureEvidence(buildAzureEvidence([activity(), record]));
  assert.equal(result.evidence[0].technicalFacts.length, 1);
  assert.equal(result.evidence[0].technicalFacts[0].change, 'changed-within-category');
  assert.deepEqual(result.exclusions.configurationFields, { 'unsupported-field': 1, 'truncated-value': 1,
    'unsafe-or-unknown-value': 2, 'no-op': 1 });
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
});

test('selection rewards distinct facts and families; duplicate facts get only bounded recurrence', () => {
  const records = Array.from({ length: 5 }, (_, index) => activity({ eventDataId: `e${index}`, operationId: `o${index}`,
    timestamp: timestamp + index * 1800000 }));
  const rich = activity({ eventDataId: 'rich', operationId: 'rich', timestamp: timestamp - 1000 });
  const monitoring = activity({ eventDataId: 'monitoring', operationId: 'monitoring', resourceId: `${nsg}/OTHER`,
    operationName: 'Microsoft.Insights/metricAlerts/write', timestamp: timestamp - 2000 });
  const candidates = buildAzureEvidence([...records, rich, monitoring, changes()]);
  assert.equal(selectAzureEvidence(candidates, { strategy: 'latest' }).length, 6);
  assert.equal(selectAzureEvidence(candidates, { strategy: 'one-per-family' }).length, 2);
  const selected = selectAzureEvidence(candidates);
  assert.equal(selected.some(row => row.family === 'monitoring'), true);
  assert.equal(selected.filter(row => row.family === 'networking').length, 2);
  const sameWindow = buildAzureEvidence(records.map(record => ({ ...record, timestamp })));
  assert.equal(selectAzureEvidence(sameWindow).length, 1);
  assert.throws(() => selectAzureEvidence(candidates, { limit: 7 }), /EVIDENCE_INVALID/);
});

test('summary allowlists labels and strips forged facts and selected-object payloads', () => {
  const candidates = buildAzureEvidence([activity()]);
  candidates[0].family = 'PRIVATE-FAMILY'; candidates[0].actionLabel = 'PRIVATE-ACTION';
  candidates[0].facts.push({ field: 'PRIVATE-FIELD', previousValue: null, newValue: 'PRIVATE-VALUE', change: 'added' });
  candidates[0].sourceLinks.push('PRIVATE-LINK');
  const result = summarizeAzureEvidence(candidates, [{ ...candidates[0], operationName: 'PRIVATE-OPERATION' }]);
  assert.equal(result.evidence[0].family, 'networking');
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
});

test('cards explain marginal evidence without double-counting repeated technical values', () => {
  const candidates = buildAzureEvidence([activity(), activity({ eventDataId: 'OTHER', operationId: 'OTHER' }), changes()]);
  const summary = summarizeAzureEvidence(candidates);
  assert.deepEqual(summary.evidence[0].contributionLabels, ['new-family', 'new-action', 'new-technical-fact', 'new-group']);
  assert.deepEqual(summary.evidence[1].contributionLabels, ['repeated-evidence']);
  assert.equal(summary.counts.distinctSelectedFacts, 6);
  assert.equal(summary.evidence[0].missingDepthLabels.includes('identity-reference-not-cryptographic-proof'), true);
});

const deploymentId = nsg.replace('Microsoft.Network/networkSecurityGroups/PRIVATE-NSG', 'Microsoft.Resources/deployments/PRIVATE-DEPLOYMENT');
const deploymentActivity = (overrides = {}) => activity({ resourceId: deploymentId,
  operationName: 'Microsoft.Resources/deployments/write', ...overrides });
const deployment = (overrides = {}) => ({ source: 'deployment', deploymentId, timestamp,
  observedAt: timestamp + 60000, provisioningState: 'Succeeded', correlationId: 'PRIVATE-CORRELATION', ...overrides });
const deploymentOperation = (overrides = {}) => ({ source: 'deployment-operations', deploymentId, operationId: 'PRIVATE-TARGET-OPERATION',
  timestamp: timestamp + 10000, observedAt: timestamp + 60000, provisioningOperation: 'Create', provisioningState: 'Succeeded',
  statusCode: 'OK', targetResourceId: nsg, executionBinding: 'stable-deployment-before-and-after',
  deploymentCorrelationId: 'PRIVATE-CORRELATION', ...overrides });

test('exact actor-correlated deployment and target operation add only ARM provisioning depth', () => {
  const candidates = buildAzureEvidence([deploymentActivity(), deployment(), deploymentOperation()]);
  const result = summarizeAzureEvidence(candidates), card = result.evidence[0];
  assert.equal(result.counts.eligibleActions, 1);
  assert.equal(result.counts.linkedDeploymentRecords, 1);
  assert.equal(result.counts.linkedDeploymentOperationRecords, 1);
  assert.equal(result.counts.distinctSelectedProvisionedTargets, 1);
  assert.deepEqual(card.linkLabels, ['exact-deployment-resource-and-correlation', 'exact-deployment-operation-parent',
    'stable-deployment-before-and-after']);
  assert.deepEqual(card.provisioningTargets, [{ alias: 'T1', resourceTypeLabel: 'network-security-group',
    provisioningOperation: 'create', statusCode: 'OK', provisioningState: 'Succeeded' }]);
  assert.equal(card.sourceFields.some(field => field.source === 'arm-deployment-operations'
    && field.field === 'properties.statusCode' && field.value === 'OK'), true);
  assert.equal(card.contributionLabels.includes('new-provisioning-outcome'), true);
  assert.equal(card.contributionLabels.includes('new-provisioned-target'), true);
  assert.equal(card.depth.outcome, 'arm-provisioning-only');
  assert.equal(card.depth.workflow, 'not-established');
  assert.equal(card.missingDepthLabels.includes('runtime-outcome-not-checked'), true);
  assert.equal(card.missingDepthLabels.includes('arm-provisioning-is-not-runtime-health'), true);
  for (const secret of ['PRIVATE', '11111111', String(timestamp)]) assert.equal(JSON.stringify(result).includes(secret), false, secret);
});

test('deployment outcomes require exact resource and accepted actor correlation', () => {
  for (const override of [{ correlationId: 'OTHER' }, { correlationId: null }, { deploymentId: `${deploymentId}-OTHER` },
    { provisioningState: 'Failed' }, { timestamp: 'PRIVATE-TIME' }, { observedAt: timestamp - 60001 }]) {
    const result = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(override), deploymentOperation()]));
    assert.equal(result.counts.linkedDeploymentRecords, 0);
    assert.equal(result.counts.linkedDeploymentOperationRecords, 0);
    assert.equal(result.evidence[0].depth.outcome, 'control-plane-only');
  }
  for (const rejected of [{ actorMatched: false }, { eventName: 'BeginRequest', successfulTerminal: false }]) {
    const result = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity({ correlationId: 'ACCEPTED' }),
      deploymentActivity({ eventDataId: 'REJECTED', ...rejected }), deployment(), deploymentOperation()]));
    assert.equal(result.counts.linkedDeploymentRecords, 0);
  }
  const wrongAction = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity({ operationName: 'Microsoft.Web/sites/write' }), deployment()]));
  assert.equal(wrongAction.counts.linkedDeploymentRecords, 0);
});

test('outcome source timestamps match the probe sixty-second observation tolerance', () => {
  for (const offset of [0, 60000]) {
    const summary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(),
      deployment({ timestamp: timestamp + offset, observedAt: timestamp })]));
    assert.equal(summary.counts.linkedDeploymentRecords, 1);
  }
  for (const sourceTime of [timestamp + 60001, -1]) {
    const summary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(),
      deployment({ timestamp: sourceTime, observedAt: timestamp })]));
    assert.equal(summary.counts.linkedDeploymentRecords, 0);
    assert.equal(summary.exclusions.outcomeRecords['invalid-outcome-record'], 1);
  }
});

test('duplicate outcome identities collapse and conflicting snapshots fail closed', () => {
  const result = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(), deployment(),
    deploymentOperation(), deploymentOperation(), deploymentOperation({ operationId: 'OTHER-READ-OF-SAME-TARGET' })]));
  assert.equal(result.counts.duplicateOutcomeRows, 2);
  assert.equal(result.counts.deploymentRecords, 1);
  assert.equal(result.counts.linkedDeploymentOperationRecords, 2);
  assert.equal(result.counts.distinctSelectedProvisionedTargets, 1);
  assert.equal(result.evidence[0].provisioningTargets.length, 1);
  for (const conflicting of [deployment({ provisioningState: 'Failed' }), deployment({ correlationId: 'OTHER' }),
    deployment({ timestamp: timestamp + 1 }), deployment({ observedAt: NaN })]) {
    const summary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(), conflicting, deploymentOperation()]));
    assert.equal(summary.counts.linkedDeploymentRecords, 0);
    assert.equal(summary.counts.linkedDeploymentOperationRecords, 0);
  }
  const conflict = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(), deploymentOperation(),
    deploymentOperation({ targetResourceId: `${nsg}-OTHER` })]));
  assert.equal(conflict.counts.linkedDeploymentOperationRecords, 0);
  assert.equal(conflict.exclusions.outcomeRecords['conflicting-outcome-record'], 1);
});

test('only successful terminal target Create/Delete operations add target depth', () => {
  for (const override of [{ provisioningState: 'Failed' }, { provisioningState: 'Running' }, { provisioningOperation: 'Read' },
    { provisioningOperation: 'Action' }, { provisioningOperation: 'PRIVATE-OPERATION' }, { statusCode: 'Accepted' },
    { statusCode: '202' }, { statusCode: '500' }, { statusCode: null }, { targetResourceId: null },
    { targetResourceId: deploymentId }, { targetResourceId: `${nsg}?PRIVATE=VALUE` },
    { targetResourceId: nsg.replace('11111111', '22222222') }, { deploymentId: `${deploymentId}-OTHER` }]) {
    const summary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(), deploymentOperation(override)]));
    assert.equal(summary.counts.linkedDeploymentOperationRecords, 0, JSON.stringify(override));
    assert.equal(summary.counts.distinctSelectedProvisionedTargets, 0);
    assert.equal(summary.evidence[0].outcomeLabels.includes('arm-target-provisioning-succeeded'), false);
  }
  const summary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(),
    deploymentOperation({ provisioningOperation: 'Delete', statusCode: '204' })]));
  assert.equal(summary.evidence[0].provisioningTargets[0].statusCode, 'NoContent');
  assert.equal(summary.evidence[0].provisioningTargets[0].provisioningOperation, 'delete');
});

test('operation outcomes require the same verified deployment execution across the read', () => {
  for (const override of [{ executionBinding: undefined }, { executionBinding: 'PRIVATE-UNVERIFIED' },
    { deploymentCorrelationId: undefined }, { deploymentCorrelationId: 'PRIVATE-OTHER-EXECUTION' }]) {
    const summary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(), deploymentOperation(override)]));
    assert.equal(summary.counts.linkedDeploymentRecords, 1);
    assert.equal(summary.counts.linkedDeploymentOperationRecords, 0);
    assert.equal(summary.counts.distinctSelectedProvisionedTargets, 0);
    assert.equal(summary.evidence[0].linkLabels.includes('stable-deployment-before-and-after'), false);
    assert.equal(JSON.stringify(summary).includes('PRIVATE'), false);
  }
  const summary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(),
    deploymentOperation({ deploymentCorrelationId: 'private-correlation' })]));
  assert.equal(summary.counts.linkedDeploymentOperationRecords, 1);
  assert.equal(summary.evidence[0].linkLabels.includes('stable-deployment-before-and-after'), true);
});

test('incremental selection values target outcome evidence with bounded distinct-target repetition', () => {
  const records = Array.from({ length: 5 }, (_, index) => {
    const id = `${deploymentId}-${index}`, correlationId = `PRIVATE-CORRELATION-${index}`;
    return [deploymentActivity({ resourceId: id, correlationId, eventDataId: `e${index}`, operationId: `o${index}` }),
      deployment({ deploymentId: id, correlationId }),
      deploymentOperation({ deploymentId: id, targetResourceId: `${nsg}-${index}`, deploymentCorrelationId: correlationId })];
  }).flat();
  const candidates = buildAzureEvidence(records), selected = selectAzureEvidence(candidates);
  assert.equal(selected.length, 2);
  assert.equal(summarizeAzureEvidence(candidates, selected).counts.distinctSelectedProvisionedTargets, 2);
  assert.equal(selectAzureEvidence(candidates, { strategy: 'latest' }).length, 5);
  assert.equal(selectAzureEvidence(candidates, { strategy: 'one-per-family' }).length, 1);
  const richer = buildAzureEvidence([deploymentActivity(), deployment(), deploymentOperation(),
    deploymentActivity({ resourceId: `${deploymentId}-new`, timestamp: timestamp + 1, eventDataId: 'new', operationId: 'new' })]);
  assert.equal(selectAzureEvidence(richer, { limit: 1 })[0].resourceId, deploymentId.toLowerCase());
});

test('outcome summary strips forged target labels and never exports caller fields', () => {
  const candidates = buildAzureEvidence([deploymentActivity(), deployment({ author: 'PRIVATE-AUTHOR' }),
    deploymentOperation({ statusMessage: 'PRIVATE-MESSAGE' })]);
  const action = candidates.find(row => row.eligible);
  action.provisioningTargets[0].resourceTypeLabel = 'PRIVATE-TYPE';
  action.provisioningTargets.push({ targetResourceId: nsg, provisioningOperation: 'PRIVATE-OP', statusCode: 'OK' });
  assert.equal(JSON.stringify(summarizeAzureEvidence(candidates)).includes('PRIVATE'), false);
});

const submittedFact = { resourceKind: 'web-app', field: 'httpsOnly', value: true };
const deploymentTemplate = (overrides = {}) => ({ source: 'deployment-template', deploymentId,
  observedAt: timestamp + 60000, deploymentTimestamp: timestamp, deploymentCorrelationId: 'PRIVATE-CORRELATION',
  executionBinding: 'stable-deployment-before-and-after', submittedFacts: [submittedFact], ...overrides });

test('template extraction reads fixture constants, never resolves expressions or policy identities', () => {
  const template = { parameters: { sku: { defaultValue: 'F1' }, secret: { defaultValue: 'PRIVATE-SECRET' } },
    outputs: { secret: { value: 'PRIVATE-OUTPUT' } }, resources: [
      { type: 'Microsoft.Web/serverfarms', name: "[parameters('PRIVATE-PLAN')]", sku: { name: "[parameters('sku')]" },
        properties: { reserved: true } },
      { type: 'Microsoft.Web/sites', name: 'PRIVATE-SITE', properties: { httpsOnly: true, siteConfig: {
        linuxFxVersion: 'NODE|24-lts', minTlsVersion: '1.2', scmMinTlsVersion: '1.2', ftpsState: 'Disabled',
        alwaysOn: false, appCommandLine: 'node fixture-app.mjs', appSettings: [{ name: 'SECRET', value: 'PRIVATE-SECRET' }] } } },
      ...['ftp', 'scm'].map(policy => ({ type: 'Microsoft.Web/sites/basicPublishingCredentialsPolicies',
        name: `[concat(parameters('PRIVATE-SITE'), '/${policy}')]`, properties: { allow: false } })),
    ] };
  const facts = extractAzureTemplateFacts(template);
  assert.equal(facts.length, 9);
  assert.equal(facts.filter(fact => fact.resourceKind === 'web-app').length, 7);
  assert.deepEqual(facts.filter(fact => fact.resourceKind === 'app-service-plan'),
    [{ resourceKind: 'app-service-plan', field: 'reserved', value: true }]);
  assert.deepEqual(facts.filter(fact => fact.resourceKind === 'publishing-policy'),
    [{ resourceKind: 'publishing-policy', field: 'basicPublishingAllowed', value: false }]);
  assert.equal(facts.find(fact => fact.field === 'startupCommand').value, 'native-node-entrypoint');
  assert.equal(JSON.stringify(facts).includes('PRIVATE'), false);
  assert.equal(JSON.stringify(facts).includes('fixture-app.mjs'), false);
  template.resources[0].sku.name = 'F1';
  assert.equal(extractAzureTemplateFacts(template).length, 10);
  assert.equal(extractAzureTemplateFacts(template).find(fact => fact.field === 'sku').value, 'F1');
});

test('template extraction rejects unknown values, expressions, unresolved branches and nested resource walks', () => {
  const resource = { type: 'Microsoft.Web/sites', properties: { httpsOnly: true } };
  for (const override of [{ condition: false }, { condition: '[true()]' }, { condition: null }, { copy: {} },
    { type: 'PRIVATE-TYPE' }, { properties: { httpsOnly: 'true' } }]) {
    assert.deepEqual(extractAzureTemplateFacts({ resources: [{ ...resource, ...override }] }), []);
  }
  assert.deepEqual(extractAzureTemplateFacts({ resources: [{ ...resource, condition: true }] }), [submittedFact]);
  const secret = 'PRIVATE-SECRET';
  const template = { resources: [{ type: 'Microsoft.Web/sites', properties: { httpsOnly: '[true()]', siteConfig: {
    linuxFxVersion: secret, minTlsVersion: secret, scmMinTlsVersion: '[parameters(\'tls\')]',
    ftpsState: secret, alwaysOn: 'false', appCommandLine: `node ${secret}.mjs` } } },
  { type: 'Microsoft.Web/serverfarms', sku: { name: secret }, properties: { reserved: 'true' } },
  { type: 'Microsoft.Web/sites/basicPublishingCredentialsPolicies', properties: { allow: '[false()]' } },
  { type: 'Microsoft.Resources/deployments', properties: { template: { resources: [resource] } } }],
  parameters: { known: resource }, outputs: { known: resource } };
  assert.deepEqual(extractAzureTemplateFacts(template), []);
  for (const input of [null, [], {}, { resources: {} }]) assert.deepEqual(extractAzureTemplateFacts(input), []);
});

test('exact deployment-bound submitted facts stay separate from deltas and runtime claims', () => {
  const candidates = buildAzureEvidence([deploymentActivity(), deployment(), deploymentTemplate()]);
  const summary = summarizeAzureEvidence(candidates), card = summary.evidence[0];
  assert.equal(summary.counts.deploymentTemplateRecords, 1);
  assert.equal(summary.counts.linkedDeploymentTemplateRecords, 1);
  assert.equal(summary.counts.distinctSelectedSubmittedFacts, 1);
  assert.equal(summary.counts.distinctSelectedFacts, 0);
  assert.deepEqual(card.submittedFacts, [submittedFact]);
  assert.deepEqual(card.technicalFacts, []);
  assert.deepEqual(card.technicalFactContributionSources, ['submitted-template']);
  assert.equal(card.sourceLabels.includes('submitted-template'), true);
  assert.equal(card.linkLabels.includes('exact-deployment-template-parent'), true);
  assert.deepEqual(card.sourceFields.find(field => field.source === 'submitted-template'),
    { source: 'submitted-template', ...submittedFact });
  assert.equal(card.depth.configuration, 'not-observed');
  assert.equal(card.depth.submittedConfiguration, 'whole-deployment-constants-observed');
  assert.equal(card.depth.outcome, 'arm-provisioning-only');
  assert.equal(card.outcomeLabels.includes('configuration-delta-observed'), false);
  for (const label of ['submitted-template-is-not-effective-configuration', 'submitted-template-not-bound-to-specific-target',
    'template-authorship-not-established', 'runtime-outcome-not-checked']) assert.equal(card.missingDepthLabels.includes(label), true);
  assert.equal(JSON.stringify(summary).includes('PRIVATE'), false);
});

test('submitted template observations require exact actor, execution, snapshot and valid observation time', () => {
  for (const override of [{ deploymentId: `${deploymentId}-OTHER` }, { deploymentCorrelationId: undefined },
    { deploymentCorrelationId: 'OTHER' }, { executionBinding: undefined }, { executionBinding: 'PRIVATE-UNVERIFIED' },
    { deploymentTimestamp: undefined }, { deploymentTimestamp: timestamp + 1 },
    { deploymentTimestamp: new Date(timestamp).toISOString() }, { observedAt: NaN }, { observedAt: timestamp - 60001 }]) {
    const summary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(), deploymentTemplate(override)]));
    assert.equal(summary.counts.linkedDeploymentTemplateRecords, 0);
    assert.equal(summary.counts.distinctSelectedSubmittedFacts, 0);
    assert.equal(summary.counts.excludedDeploymentTemplateRecords, 1);
  }
  for (const actor of [{ actorMatched: false }, { tenantMatched: false }, { matchesActor: false },
    { correlationId: 'OTHER' }, { eventName: 'BeginRequest' }, { status: 'Failed' }]) {
    const summary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(actor), deployment(), deploymentTemplate()]));
    assert.equal(summary.counts.linkedDeploymentTemplateRecords, 0);
  }
  const failed = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment({ provisioningState: 'Failed' }), deploymentTemplate()]));
  assert.equal(failed.counts.linkedDeploymentTemplateRecords, 0);
  const startSpoof = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity({ correlationId: 'OTHER' }),
    deploymentActivity({ eventDataId: 'REJECTED', eventName: 'BeginRequest' }), deployment(), deploymentTemplate()]));
  assert.equal(startSpoof.counts.linkedDeploymentTemplateRecords, 0);
  const boundary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(),
    deploymentTemplate({ observedAt: timestamp - 60000 })]));
  assert.equal(boundary.counts.linkedDeploymentTemplateRecords, 1);
});

test('template duplicates collapse while conflicting or malformed observations add no fact credit', () => {
  const summary = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(), deploymentTemplate(),
    deploymentTemplate({ submittedFacts: [submittedFact, submittedFact], observedAt: timestamp + 120000 })]));
  assert.equal(summary.counts.deploymentTemplateRecords, 1);
  assert.equal(summary.counts.duplicateDeploymentTemplateRows, 1);
  assert.equal(summary.counts.duplicateOutcomeRows, 0);
  assert.equal(summary.counts.distinctSelectedSubmittedFacts, 1);
  for (const submittedFacts of [[{ ...submittedFact, value: false }], [{ ...submittedFact, value: 'PRIVATE-SECRET' }],
    [{ ...submittedFact, resourceKind: 'PRIVATE-TYPE' }], [{ ...submittedFact, field: 'PRIVATE-FIELD' }],
    [{ ...submittedFact, privateName: 'PRIVATE-NAME' }], null, {}, [null]]) {
    const result = summarizeAzureEvidence(buildAzureEvidence([deploymentActivity(), deployment(), deploymentTemplate(),
      deploymentTemplate({ submittedFacts })]));
    assert.equal(result.counts.linkedDeploymentTemplateRecords, 0);
    assert.equal(result.counts.distinctSelectedSubmittedFacts, 0);
    assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
  }
  const candidates = buildAzureEvidence([deploymentActivity(), deployment(), deploymentTemplate()]);
  candidates.find(candidate => candidate.eligible).submittedFacts.push({ resourceKind: 'PRIVATE-TYPE', field: 'PRIVATE', value: 'PRIVATE' });
  const forged = summarizeAzureEvidence(candidates);
  assert.equal(forged.counts.distinctSelectedSubmittedFacts, 0);
  assert.equal(JSON.stringify(forged).includes('PRIVATE'), false);
});

test('incremental selection values novel submitted facts and gives repeated settings no extra fact credit', () => {
  const records = Array.from({ length: 5 }, (_, index) => {
    const id = `${deploymentId}-${index}`, correlationId = `PRIVATE-CORRELATION-${index}`;
    return [deploymentActivity({ resourceId: id, correlationId, eventDataId: `e${index}`, operationId: `o${index}`,
      timestamp: timestamp + index }), deployment({ deploymentId: id, correlationId }),
    deploymentTemplate({ deploymentId: id, deploymentCorrelationId: correlationId,
      submittedFacts: index ? [submittedFact] : [{ resourceKind: 'web-app', field: 'minTlsVersion', value: '1.2' }] })];
  }).flat();
  const candidates = buildAzureEvidence(records), selected = selectAzureEvidence(candidates);
  assert.equal(selected.length, 2);
  assert.equal(selected[0].resourceId, `${deploymentId}-4`.toLowerCase());
  assert.equal(selected[1].resourceId, `${deploymentId}-0`.toLowerCase());
  const summary = summarizeAzureEvidence(candidates, selected);
  assert.equal(summary.counts.distinctSelectedSubmittedFacts, 2);
  assert.equal(summary.evidence.every(card => card.contributionLabels.includes('new-technical-fact')), true);
  const latest = summarizeAzureEvidence(candidates, selectAzureEvidence(candidates, { strategy: 'latest' }));
  assert.equal(latest.counts.selectedActions, 5);
  assert.equal(latest.evidence[1].contributionLabels.includes('new-technical-fact'), false);
  assert.deepEqual(latest.evidence[1].technicalFactContributionSources, []);
});
