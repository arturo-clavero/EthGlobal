import { isIP } from 'node:net';
import { isDeepStrictEqual } from 'node:util';

const ACTIONS = Object.fromEntries([
  ['microsoft.compute/virtualmachines/write', 'compute', 'vm-write'],
  ['microsoft.web/sites/write', 'application-hosting', 'web-app-write'],
  ['microsoft.web/sites/slots/slotsswap/action', 'application-hosting', 'web-slot-swap'],
  ['microsoft.containerservice/managedclusters/write', 'kubernetes', 'aks-cluster-write'],
  ['microsoft.network/networksecuritygroups/write', 'networking', 'network-security-group-write'],
  ['microsoft.network/networksecuritygroups/delete', 'networking', 'network-security-group-delete'],
  ['microsoft.network/networksecuritygroups/securityrules/write', 'networking', 'network-rule-write'],
  ['microsoft.network/networksecuritygroups/securityrules/delete', 'networking', 'network-rule-delete'],
  ['microsoft.network/virtualnetworks/write', 'networking', 'virtual-network-write'],
  ['microsoft.storage/storageaccounts/write', 'storage', 'storage-account-write'],
  ['microsoft.sql/servers/databases/write', 'databases', 'sql-database-write'],
  ['microsoft.authorization/roleassignments/write', 'access-control', 'role-assignment-write'],
  ['microsoft.keyvault/vaults/write', 'secrets-management', 'key-vault-write'],
  ['microsoft.insights/metricalerts/write', 'monitoring', 'metric-alert-write'],
  ['microsoft.datafactory/factories/pipelines/write', 'data-pipelines', 'data-pipeline-write'],
  ['microsoft.resources/deployments/write', 'resource-management', 'arm-deployment-write'],
  ['microsoft.resources/subscriptions/resourcegroups/write', 'resource-management', 'resource-group-write'],
  ['microsoft.resources/subscriptions/resourcegroups/delete', 'resource-management', 'resource-group-delete'],
].map(([operation, family, actionLabel]) => [operation, { family, actionLabel }]));
const FIELDS = { access: 'access', direction: 'direction', protocol: 'protocol',
  destinationportrange: 'destinationPortRange', priority: 'priority',
  sourceaddressprefix: 'sourceAddressPrefix', destinationaddressprefix: 'destinationAddressPrefix' };
const VALUES = {
  access: ['allow', 'deny'], direction: ['inbound', 'outbound'], protocol: ['tcp', 'udp', 'icmp', 'esp', 'ah', '*'],
  destinationPortRange: ['all-ports', 'single-system-port', 'single-user-port', 'single-dynamic-port', 'port-range'],
  priority: ['priority-100-499', 'priority-500-1999', 'priority-2000-4096'],
  sourceAddressPrefix: ['any-address', 'virtual-network-tag', 'internet-tag', 'azure-load-balancer-tag',
    'azure-cloud-tag', 'ipv4-address', 'ipv4-network', 'ipv6-address', 'ipv6-network'],
};
VALUES.destinationAddressPrefix = VALUES.sourceAddressPrefix;
const SUBMITTED_VALUES = {
  'web-app': { httpsOnly: [true, false], linuxFxVersion: ['NODE|24-lts'],
    minTlsVersion: ['1.0', '1.1', '1.2', '1.3'], scmMinTlsVersion: ['1.0', '1.1', '1.2', '1.3'],
    ftpsState: ['Disabled', 'FtpsOnly', 'AllAllowed'], alwaysOn: [true, false],
    startupCommand: ['native-node-entrypoint'] },
  'app-service-plan': { sku: ['F1'], reserved: [true, false] },
  'publishing-policy': { basicPublishingAllowed: [true, false] },
};
const ROW_EXCLUSIONS = ['unrecognized-action', 'failed-terminal', 'not-successful-terminal', 'actor-or-tenant-mismatch'];
const ACTION_EXCLUSIONS = [...ROW_EXCLUSIONS, 'missing-resource-or-time', 'conflicting-terminal-status',
  'configuration-without-attributed-action'];
const FIELD_EXCLUSIONS = ['unsupported-field', 'different-rule', 'truncated-value', 'unsafe-or-unknown-value', 'no-op'];
const OUTCOME_EXCLUSIONS = ['invalid-outcome-record', 'conflicting-outcome-record', 'outcome-not-succeeded',
  'outcome-without-attributed-deployment', 'operation-without-successful-deployment', 'not-target-provisioning',
  'invalid-target-resource', 'nonterminal-or-unsuccessful-status', 'deployment-execution-not-verified',
  'deployment-execution-correlation-mismatch', 'deployment-execution-timestamp-mismatch',
  'template-without-successful-deployment'];
const LINKS = ['exact-correlation-and-resource', 'exact-correlation-and-nsg-parent',
  'exact-deployment-resource-and-correlation', 'exact-deployment-operation-parent', 'exact-deployment-template-parent',
  'stable-deployment-before-and-after'];
const SUCCESS_CODES = { '200': 'OK', '201': 'Created', '204': 'NoContent', ok: 'OK', created: 'Created', nocontent: 'NoContent' };
const TARGET_TYPES = { 'microsoft.web/serverfarms': 'app-service-plan', 'microsoft.web/sites': 'web-app',
  'microsoft.network/networksecuritygroups': 'network-security-group',
  'microsoft.network/networksecuritygroups/securityrules': 'network-security-rule',
  'microsoft.storage/storageaccounts': 'storage-account', 'microsoft.compute/virtualmachines': 'virtual-machine',
  'microsoft.resources/deployments': 'nested-deployment' };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const canonical = value => typeof value === 'string' && value.length > 0 && value.length <= 4096
  && !/[\u0000-\u001f]/.test(value) ? value.toLowerCase() : null;
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const increment = (counts, key, amount = 1) => { counts[key] = (counts[key] ?? 0) + amount; };
const knownAction = operation => Object.hasOwn(ACTIONS, operation ?? '') ? ACTIONS[operation] : null;
const timestamp = value => typeof value === 'number' ? value
  : typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value) ? Date.parse(value) : NaN;
const factKey = fact => JSON.stringify([fact.field, fact.previousValue, fact.newValue, fact.change]);
const distinctFacts = facts => [...new Map(facts.map(fact => [factKey(fact), fact])).values()];
const invalid = () => { throw new Error('AZURE_EVIDENCE_INVALID'); };
const submittedFactKey = fact => JSON.stringify([fact.resourceKind, fact.field, fact.value]);

function normalizedSubmittedFacts(facts) {
  if (!Array.isArray(facts) || facts.some(fact => !object(fact)
    || Object.keys(fact).some(key => !['resourceKind', 'field', 'value'].includes(key))
    || !Object.hasOwn(SUBMITTED_VALUES, fact.resourceKind ?? '')
    || !Object.hasOwn(SUBMITTED_VALUES[fact.resourceKind], fact.field ?? '')
    || !SUBMITTED_VALUES[fact.resourceKind][fact.field].includes(fact.value))) return null;
  return [...new Map(facts.map(({ resourceKind, field, value }) => {
    const fact = { resourceKind, field, value };
    return [submittedFactKey(fact), fact];
  })).values()].sort((a, b) => submittedFactKey(a).localeCompare(submittedFactKey(b)));
}

// Constants describe the submitted deployment as a whole; never resolve ARM expressions or resource identities.
export function extractAzureTemplateFacts(template) {
  if (!object(template) || !Array.isArray(template.resources)) return [];
  const facts = [];
  const add = (resourceKind, field, value) => {
    if (SUBMITTED_VALUES[resourceKind][field].includes(value)) facts.push({ resourceKind, field, value });
  };
  for (const resource of template.resources) {
    if (!object(resource) || Object.hasOwn(resource, 'copy')
      || (Object.hasOwn(resource, 'condition') && resource.condition !== true) || !object(resource.properties)) continue;
    const properties = resource.properties;
    switch (canonical(resource.type)) {
      case 'microsoft.web/sites': {
        add('web-app', 'httpsOnly', properties.httpsOnly);
        const config = object(properties.siteConfig) ? properties.siteConfig : {};
        for (const field of ['linuxFxVersion', 'minTlsVersion', 'scmMinTlsVersion', 'ftpsState', 'alwaysOn']) {
          add('web-app', field, config[field]);
        }
        if (config.appCommandLine === 'node fixture-app.mjs') add('web-app', 'startupCommand', 'native-node-entrypoint');
        break;
      }
      case 'microsoft.web/serverfarms':
        add('app-service-plan', 'reserved', properties.reserved);
        add('app-service-plan', 'sku', object(resource.sku) ? resource.sku.name : undefined);
        break;
      case 'microsoft.web/sites/basicpublishingcredentialspolicies':
        add('publishing-policy', 'basicPublishingAllowed', properties.allow);
        break;
    }
  }
  return normalizedSubmittedFacts(facts);
}

function activityRow(record) {
  const row = { eventDataId: canonical(record.eventDataId), resourceId: canonical(record.resourceId),
    operationName: canonical(record.operationName), operationId: canonical(record.operationId),
    correlationId: canonical(record.correlationId), timestamp: timestamp(record.timestamp),
    eventName: canonical(record.eventName), status: canonical(record.status),
    actorMatched: record.actorMatched === true && record.tenantMatched === true && record.matchesActor === true,
    successfulTerminal: record.successfulTerminal === true };
  if (!row.eventDataId) invalid();
  row.reason = !knownAction(row.operationName) ? 'unrecognized-action'
    : row.eventName === 'endrequest' && ['failed', 'canceled', 'cancelled'].includes(row.status) ? 'failed-terminal'
      : row.eventName !== 'endrequest' || row.status !== 'succeeded' || !row.successfulTerminal ? 'not-successful-terminal'
        : !row.actorMatched ? 'actor-or-tenant-mismatch' : null;
  return row;
}

function safeValue(field, value) {
  if (value == null) return null;
  if (!['string', 'number'].includes(typeof value)) return undefined;
  const text = String(value).toLowerCase();
  if (['access', 'direction', 'protocol'].includes(field)) return VALUES[field].includes(text) ? text : undefined;
  if (field === 'priority' && /^\d{3,4}$/.test(text)) {
    const n = Number(text);
    if (n >= 100 && n <= 4096) return n < 500 ? 'priority-100-499' : n < 2000 ? 'priority-500-1999' : 'priority-2000-4096';
  }
  if (field === 'destinationPortRange') {
    if (text === '*') return 'all-ports';
    if (/^\d{1,5}$/.test(text) && Number(text) <= 65535) {
      return Number(text) < 1024 ? 'single-system-port' : Number(text) < 49152 ? 'single-user-port' : 'single-dynamic-port';
    }
    const range = /^(\d{1,5})-(\d{1,5})$/.exec(text);
    if (range && Number(range[1]) <= Number(range[2]) && Number(range[2]) <= 65535) return 'port-range';
  }
  if (field === 'sourceAddressPrefix' || field === 'destinationAddressPrefix') {
    const tags = { '*': 'any-address', virtualnetwork: 'virtual-network-tag', internet: 'internet-tag',
      azureloadbalancer: 'azure-load-balancer-tag', azurecloud: 'azure-cloud-tag' };
    if (Object.hasOwn(tags, text)) return tags[text];
    const parts = text.split('/'), version = isIP(parts[0]);
    if (version && parts.length === 1) return `ipv${version}-address`;
    if (version && parts.length === 2 && /^\d{1,3}$/.test(parts[1]) && Number(parts[1]) <= (version === 4 ? 32 : 128)) {
      return `ipv${version}-network`;
    }
  }
  return undefined;
}

function nsgResource(resource) {
  return /^\/subscriptions\/[a-f0-9-]{36}\/resourcegroups\/[^/]+\/providers\/microsoft\.network\/networksecuritygroups\/[^/]+(?:\/securityrules\/([^/]+))?$/.exec(resource ?? '');
}

function ruleMatches(change, selector, candidate) {
  const rule = nsgResource(candidate.resourceId)?.[1];
  if (!rule) return true;
  const prefix = `properties.securityrules[${selector.toLowerCase()}].`;
  const identities = Object.entries(change.changes ?? {}).filter(([path]) =>
    [`${prefix}name`, `${prefix}id`].includes(path.toLowerCase()));
  if (identities.length) return identities.every(([path, value]) => object(value)
    && ![true, 'true'].includes(value.isTruncated)
    && [value.previousValue, value.newValue].some(side => side != null)
    && [value.previousValue, value.newValue].every(side => side == null
      || canonical(side) === (path.toLowerCase().endsWith('.id') ? candidate.resourceId : rule)));
  return canonical(selector) === rule;
}

function configurationFacts(change, candidate) {
  const facts = [], exclusions = {};
  const resource = nsgResource(candidate.resourceId);
  for (const [path, value] of Object.entries(change.changes ?? {})) {
    const nested = /^properties\.securityrules\[([^\[\]]+)\]\.properties\.([a-z]+)$/i.exec(path);
    const fieldName = (nested?.[2] ?? '').toLowerCase();
    const field = Object.hasOwn(FIELDS, fieldName) ? FIELDS[fieldName] : null;
    if (!resource || !field || !object(value)) { increment(exclusions, 'unsupported-field'); continue; }
    if (!ruleMatches(change, nested[1], candidate)) { increment(exclusions, 'different-rule'); continue; }
    if (value.isTruncated === true || value.isTruncated === 'true') { increment(exclusions, 'truncated-value'); continue; }
    const before = value.previousValue, after = value.newValue;
    if (before === after || before == null && after == null) { increment(exclusions, 'no-op'); continue; }
    const previousValue = safeValue(field, before), newValue = safeValue(field, after);
    if (previousValue === undefined || newValue === undefined) { increment(exclusions, 'unsafe-or-unknown-value'); continue; }
    facts.push({ field, previousValue, newValue, change: previousValue === null ? 'added' : newValue === null ? 'removed'
      : previousValue === newValue ? 'changed-within-category' : 'changed' });
  }
  return { facts: distinctFacts(facts), exclusions };
}

// Discovery priority only; these potential facts have no actor or action binding.
export function countPotentialAzureChangeFacts(record) {
  if (!object(record) || !object(record.changes)) return 0;
  return configurationFacts(record, { resourceId: canonical(record.targetResourceId) }).facts.length;
}

function linkChange(change, candidate) {
  if (!change.correlationId || !candidate.correlationIds.includes(change.correlationId)) return null;
  if (change.targetResourceId === candidate.resourceId) return 'exact-correlation-and-resource';
  const resource = nsgResource(candidate.resourceId), target = nsgResource(change.targetResourceId);
  if (resource?.[1] && target && !target[1]
      && candidate.resourceId === `${change.targetResourceId}/securityrules/${resource[1]}`) {
    return 'exact-correlation-and-nsg-parent';
  }
  return null;
}

function armResource(value) {
  const id = canonical(value);
  if (!id || /[?#%\\]/.test(id)) return null;
  const match = /^\/subscriptions\/([a-f0-9-]{36})\/resourcegroups\/([^/]+)\/providers\/([^/]+)\/(.+)$/.exec(id);
  if (!match || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(match[1])) return null;
  const parts = match[4].split('/');
  if (parts.length % 2 || parts.some(part => !part || part === '.' || part === '..')) return null;
  return { id, subscription: match[1], type: `${match[3]}/${parts.filter((_, index) => index % 2 === 0).join('/')}` };
}

function outcomeRows(records) {
  const outcomes = new Map();
  for (const record of records.filter(row => ['deployment', 'deployment-operations', 'deployment-template'].includes(row.source))) {
    const deployment = armResource(record.deploymentId), operation = record.source === 'deployment-operations';
    const template = record.source === 'deployment-template', bound = operation || template;
    const row = { source: record.source, deploymentId: deployment?.id ?? null,
      operationId: operation ? canonical(record.operationId) : null,
      correlationId: bound ? null : canonical(record.correlationId),
      timestamp: timestamp(template ? record.deploymentTimestamp : record.timestamp),
      deploymentTimestamp: template ? record.deploymentTimestamp : operation ? null : record.timestamp,
      provisioningState: template ? null : canonical(record.provisioningState),
      provisioningOperation: operation ? canonical(record.provisioningOperation) : null,
      statusCode: operation ? canonical(record.statusCode) : null,
      targetResourceId: operation ? canonical(record.targetResourceId) : null,
      executionBinding: bound ? canonical(record.executionBinding) : null,
      deploymentCorrelationId: bound ? canonical(record.deploymentCorrelationId) : null,
      submittedFacts: template ? normalizedSubmittedFacts(record.submittedFacts) : null };
    const observedAt = timestamp(record.observedAt);
    const valid = deployment?.type === 'microsoft.resources/deployments' && Number.isFinite(row.timestamp)
      && Number.isFinite(observedAt) && row.timestamp >= 0 && row.timestamp <= observedAt + 60000
      && (!operation || (row.operationId && !/[/?#%\\]/.test(row.operationId)))
      && (!template || row.submittedFacts !== null);
    const key = row.deploymentId && (!operation || row.operationId)
      ? JSON.stringify([record.source, row.deploymentId, row.operationId]) : `invalid-outcome:${outcomes.size}`;
    const previous = outcomes.get(key);
    if (previous) {
      if (JSON.stringify(previous.row) !== JSON.stringify(row)) previous.exclusionReason = 'conflicting-outcome-record';
      else previous.duplicateRows++;
      if (!valid && !previous.exclusionReason) previous.exclusionReason = 'invalid-outcome-record';
    } else outcomes.set(key, { key: `outcome:${key}`, source: record.source, row, eligible: false,
      duplicateRows: 0, linked: false, exclusionReason: valid ? null : 'invalid-outcome-record' });
  }
  return [...outcomes.values()];
}

function attachOutcomes(candidates, outcomes) {
  const successful = new Map();
  for (const outcome of outcomes.filter(item => item.source === 'deployment')) {
    const row = outcome.row;
    if (outcome.exclusionReason) continue;
    if (row.provisioningState !== 'succeeded') { outcome.exclusionReason = 'outcome-not-succeeded'; continue; }
    const linked = candidates.filter(candidate => candidate.eligible
      && candidate.operationName === 'microsoft.resources/deployments/write'
      && candidate.resourceId === row.deploymentId && row.correlationId
      && candidate.correlationIds.includes(row.correlationId));
    if (!linked.length) { outcome.exclusionReason = 'outcome-without-attributed-deployment'; continue; }
    outcome.linked = true; successful.set(row.deploymentId, { candidates: linked, correlationId: row.correlationId,
      deploymentTimestamp: row.deploymentTimestamp });
    for (const candidate of linked) {
      candidate.deploymentIds.push(row.deploymentId);
      candidate.sourceLinks.push('exact-deployment-resource-and-correlation');
    }
  }
  for (const outcome of outcomes.filter(item => item.source === 'deployment-operations')) {
    const row = outcome.row;
    if (outcome.exclusionReason) continue;
    if (row.provisioningState !== 'succeeded') { outcome.exclusionReason = 'outcome-not-succeeded'; continue; }
    if (!successful.has(row.deploymentId)) { outcome.exclusionReason = 'operation-without-successful-deployment'; continue; }
    if (row.executionBinding !== 'stable-deployment-before-and-after') {
      outcome.exclusionReason = 'deployment-execution-not-verified'; continue;
    }
    if (row.deploymentCorrelationId !== successful.get(row.deploymentId).correlationId) {
      outcome.exclusionReason = 'deployment-execution-correlation-mismatch'; continue;
    }
    if (!['create', 'delete'].includes(row.provisioningOperation)) { outcome.exclusionReason = 'not-target-provisioning'; continue; }
    const target = armResource(row.targetResourceId), deployment = armResource(row.deploymentId);
    if (!target || target.subscription !== deployment.subscription || target.id === deployment.id) {
      outcome.exclusionReason = 'invalid-target-resource'; continue;
    }
    const statusCode = Object.hasOwn(SUCCESS_CODES, row.statusCode ?? '') ? SUCCESS_CODES[row.statusCode] : null;
    if (!statusCode) { outcome.exclusionReason = 'nonterminal-or-unsuccessful-status'; continue; }
    outcome.linked = true;
    for (const candidate of successful.get(row.deploymentId).candidates) {
      candidate.deploymentOperationKeys.push(outcome.key);
      candidate.provisioningTargets.push({ targetResourceId: target.id,
        resourceTypeLabel: Object.hasOwn(TARGET_TYPES, target.type) ? TARGET_TYPES[target.type] : 'other-arm-resource',
        provisioningOperation: row.provisioningOperation, statusCode });
      if (!candidate.sourceLinks.includes('exact-deployment-operation-parent')) candidate.sourceLinks.push('exact-deployment-operation-parent');
      if (!candidate.sourceLinks.includes('stable-deployment-before-and-after')) candidate.sourceLinks.push('stable-deployment-before-and-after');
    }
  }
  for (const outcome of outcomes.filter(item => item.source === 'deployment-template')) {
    const row = outcome.row, parent = successful.get(row.deploymentId);
    if (outcome.exclusionReason) continue;
    if (!parent) { outcome.exclusionReason = 'template-without-successful-deployment'; continue; }
    if (row.executionBinding !== 'stable-deployment-before-and-after') {
      outcome.exclusionReason = 'deployment-execution-not-verified'; continue;
    }
    if (row.deploymentCorrelationId !== parent.correlationId) {
      outcome.exclusionReason = 'deployment-execution-correlation-mismatch'; continue;
    }
    if (row.deploymentTimestamp !== parent.deploymentTimestamp) {
      outcome.exclusionReason = 'deployment-execution-timestamp-mismatch'; continue;
    }
    outcome.linked = true;
    for (const candidate of parent.candidates) {
      candidate.deploymentTemplateKeys.push(outcome.key);
      candidate.submittedFacts = normalizedSubmittedFacts([...candidate.submittedFacts, ...row.submittedFacts]);
      candidate.sourceLinks.push('exact-deployment-template-parent');
      if (!candidate.sourceLinks.includes('stable-deployment-before-and-after')) candidate.sourceLinks.push('stable-deployment-before-and-after');
    }
  }
}

export function buildAzureEvidence(records) {
  if (!Array.isArray(records) || records.some(record => !object(record)
    || !['activity', 'changes', 'deployment', 'deployment-operations', 'deployment-template'].includes(record.source))) invalid();
  const events = new Map(), changes = new Map(), candidates = new Map();
  for (const record of records.filter(row => ['activity', 'changes'].includes(row.source))) {
    const activity = record.source === 'activity';
    const row = activity ? activityRow(record) : { id: canonical(record.id), targetResourceId: canonical(record.targetResourceId),
      correlationId: canonical(record.correlationId), changeTime: record.changeTime, changes: record.changes ?? {} };
    if (!activity && (!row.id || !row.targetResourceId || !object(row.changes))) invalid();
    const id = activity ? row.eventDataId : row.id, collection = activity ? events : changes;
    const previous = collection.get(id);
    if (previous && !isDeepStrictEqual(previous.row, row)) throw new Error('AZURE_EVIDENCE_CONFLICT');
    if (previous) previous.duplicates++;
    else collection.set(id, { row, duplicates: 0 });
  }
  for (const { row, duplicates } of events.values()) {
    const key = JSON.stringify(row.operationId && row.resourceId && row.operationName
      ? ['operation', row.resourceId, row.operationName, row.operationId] : ['event', row.eventDataId]);
    if (!candidates.has(key)) candidates.set(key, { key, source: 'activity', resourceId: row.resourceId,
      operationName: row.operationName, operationId: row.operationId, eventIds: [], correlationIds: [],
      rows: [], duplicateRows: 0, facts: [], changeIds: [], sourceLinks: [], configurationExclusions: {},
      deploymentIds: [], deploymentOperationKeys: [], provisioningTargets: [], deploymentTemplateKeys: [], submittedFacts: [] });
    const candidate = candidates.get(key);
    candidate.rows.push(row); candidate.eventIds.push(row.eventDataId); candidate.duplicateRows += duplicates;
  }
  for (const candidate of candidates.values()) {
    const accepted = candidate.rows.filter(row => !row.reason);
    candidate.correlationIds = [...new Set(accepted.map(row => row.correlationId).filter(Boolean))];
    const action = knownAction(candidate.operationName);
    candidate.family = action?.family ?? 'unrecognized'; candidate.actionLabel = action?.actionLabel ?? 'unrecognized-action';
    candidate.timestamp = Math.max(...(accepted.length ? accepted : candidate.rows)
      .map(row => Number.isFinite(row.timestamp) ? row.timestamp : -Infinity));
    candidate.eventExclusions = {};
    candidate.rows.forEach(row => { if (row.reason) increment(candidate.eventExclusions, row.reason); });
    candidate.exclusionReason = !accepted.length ? candidate.rows[0].reason
      : candidate.eventExclusions['failed-terminal'] ? 'conflicting-terminal-status'
        : !candidate.resourceId || !Number.isFinite(candidate.timestamp) ? 'missing-resource-or-time' : null;
    candidate.eligible = candidate.exclusionReason === null;
    candidate.uncertainLogicalIdentity = !candidate.operationId;
    // shortcut: fixed half-hour windows can split adjacent work; only authenticated causal links justify workflow claims.
    candidate.groupKey = candidate.eligible ? JSON.stringify([candidate.resourceId, Math.floor(candidate.timestamp / 1800000)]) : null;
    for (const { row: change } of changes.values()) {
      const link = candidate.eligible && linkChange(change, candidate);
      if (!link) continue;
      candidate.changeIds.push(change.id);
      if (!candidate.sourceLinks.includes(link)) candidate.sourceLinks.push(link);
      const extracted = configurationFacts(change, candidate);
      candidate.facts.push(...extracted.facts);
      Object.entries(extracted.exclusions).forEach(([reason, total]) => increment(candidate.configurationExclusions, reason, total));
    }
    candidate.facts = distinctFacts(candidate.facts);
  }
  const linked = new Set([...candidates.values()].flatMap(candidate => candidate.changeIds));
  for (const { row, duplicates } of changes.values()) {
    if (!linked.has(row.id)) candidates.set(`change:${row.id}`, { key: `change:${row.id}`, source: 'changes',
      eligible: false, exclusionReason: 'configuration-without-attributed-action', changeIds: [row.id], duplicateRows: duplicates });
  }
  const outcomes = outcomeRows(records);
  attachOutcomes([...candidates.values()], outcomes);
  for (const outcome of outcomes) candidates.set(outcome.key, outcome);
  return [...candidates.values()].sort((a, b) => a.key.localeCompare(b.key));
}

const factValues = candidate => candidate.facts.flatMap(fact => [fact.previousValue, fact.newValue]
  .filter(value => value !== null).map(value => `${fact.field}:${value}`));
const hasProvisioningOutcome = candidate => candidate.operationName === 'microsoft.resources/deployments/write'
  && (candidate.deploymentIds ?? []).some(id => armResource(id)?.type === 'microsoft.resources/deployments');
const safeSubmittedFacts = candidate => hasProvisioningOutcome(candidate) && candidate.deploymentTemplateKeys?.length
  ? normalizedSubmittedFacts(candidate.submittedFacts) ?? [] : [];

function safeProvisioningTargets(candidate) {
  if (!hasProvisioningOutcome(candidate)) return [];
  const targets = (candidate.provisioningTargets ?? []).filter(target => object(target) && armResource(target.targetResourceId)
    && ['create', 'delete'].includes(target.provisioningOperation) && ['OK', 'Created', 'NoContent'].includes(target.statusCode));
  return [...new Map(targets.map(target => [JSON.stringify([target.targetResourceId, target.provisioningOperation, target.statusCode]),
    { targetResourceId: target.targetResourceId, provisioningOperation: target.provisioningOperation, statusCode: target.statusCode,
      resourceTypeLabel: TARGET_TYPES[armResource(target.targetResourceId).type] ?? 'other-arm-resource' }])).values()];
}

export function selectAzureEvidence(candidates, { strategy = 'incremental', limit = 6 } = {}) {
  if (!Array.isArray(candidates) || !['latest', 'one-per-family', 'incremental'].includes(strategy)
      || !Number.isInteger(limit) || limit < 0 || limit > 6) invalid();
  const remaining = [...new Map(candidates.filter(candidate => candidate.eligible).map(candidate => [candidate.key, candidate])).values()];
  remaining.sort((a, b) => b.timestamp - a.timestamp || a.key.localeCompare(b.key));
  if (strategy === 'latest') return remaining.slice(0, limit);
  if (strategy === 'one-per-family') return [...new Map(remaining.map(row => [row.family, row]).reverse()).values()]
    .sort((a, b) => b.timestamp - a.timestamp || a.key.localeCompare(b.key)).slice(0, limit);
  const selected = [], families = new Set(), actions = new Set(), facts = new Set(), submittedFacts = new Set(),
    groups = new Map(), targets = new Map();
  let provisioningObserved = false;
  const gain = row => Number(!families.has(row.family)) * 100 + Number(!actions.has(row.actionLabel)) * 10
    + new Set(factValues(row).filter(fact => !facts.has(fact))).size * 5
    + safeSubmittedFacts(row).filter(fact => !submittedFacts.has(submittedFactKey(fact))).length * 5
    + Number(hasProvisioningOutcome(row) && !provisioningObserved) * 5
    + Math.max(0, Math.min(2 - (targets.get(row.family)?.size ?? 0),
      new Set(safeProvisioningTargets(row).map(target => target.targetResourceId)
        .filter(target => !targets.get(row.family)?.has(target))).size)) * 5
    + Number(!groups.get(row.family)?.has(row.groupKey) && (groups.get(row.family)?.size ?? 0) < 2);
  while (remaining.length && selected.length < limit) {
    remaining.sort((a, b) => gain(b) - gain(a) || b.facts.length - a.facts.length
      || b.timestamp - a.timestamp || a.key.localeCompare(b.key));
    const row = remaining.shift();
    if (gain(row) === 0) break;
    selected.push(row); families.add(row.family); actions.add(row.actionLabel);
    factValues(row).forEach(fact => facts.add(fact));
    safeSubmittedFacts(row).forEach(fact => submittedFacts.add(submittedFactKey(fact)));
    provisioningObserved ||= hasProvisioningOutcome(row);
    if (!targets.has(row.family)) targets.set(row.family, new Set());
    safeProvisioningTargets(row).forEach(target => targets.get(row.family).add(target.targetResourceId));
    if (!groups.has(row.family)) groups.set(row.family, new Set());
    groups.get(row.family).add(row.groupKey);
  }
  return selected;
}

function safeFacts(candidate) {
  return distinctFacts((candidate.facts ?? []).filter(fact => object(fact) && Object.hasOwn(VALUES, fact.field)
    && [fact.previousValue, fact.newValue].every(value => value === null || VALUES[fact.field].includes(value))
    && ['added', 'removed', 'changed', 'changed-within-category'].includes(fact.change))
    .map(({ field, previousValue, newValue, change }) => ({ field, previousValue, newValue, change })));
}

export function summarizeAzureEvidence(candidates, selected = candidates) {
  if (!Array.isArray(candidates) || !Array.isArray(selected)) invalid();
  const byKey = new Map(candidates.map(candidate => [candidate.key, candidate]));
  if (selected.some(candidate => !byKey.has(candidate.key))) invalid();
  const chosen = [...new Map(selected.map(candidate => [candidate.key, byKey.get(candidate.key)])).values()]
    .filter(candidate => candidate.eligible && knownAction(candidate.operationName));
  const activity = candidates.filter(candidate => candidate.source === 'activity');
  const allChanges = new Set(candidates.flatMap(candidate => candidate.changeIds ?? []));
  const linkedChanges = new Set(activity.flatMap(candidate => candidate.changeIds ?? []));
  const outcomeRecords = candidates.filter(candidate => ['deployment', 'deployment-operations'].includes(candidate.source));
  const templateRecords = candidates.filter(candidate => candidate.source === 'deployment-template');
  const exclusions = { activityRows: {}, logicalActions: {}, configurationFields: {}, outcomeRecords: {}, submittedTemplateRecords: {} };
  for (const candidate of candidates) {
    for (const reason of ROW_EXCLUSIONS) if (count(candidate.eventExclusions?.[reason])) {
      increment(exclusions.activityRows, reason, count(candidate.eventExclusions[reason]));
    }
    if (ACTION_EXCLUSIONS.includes(candidate.exclusionReason)) increment(exclusions.logicalActions, candidate.exclusionReason);
    for (const reason of FIELD_EXCLUSIONS) if (count(candidate.configurationExclusions?.[reason])) {
      increment(exclusions.configurationFields, reason, count(candidate.configurationExclusions[reason]));
    }
    if (OUTCOME_EXCLUSIONS.includes(candidate.exclusionReason)) {
      increment(candidate.source === 'deployment-template' ? exclusions.submittedTemplateRecords : exclusions.outcomeRecords,
        candidate.exclusionReason);
    }
  }
  const groups = new Map(), families = new Set(), actions = new Set(), factCoverage = new Set(),
    submittedFactCoverage = new Set(), targetAliases = new Map();
  let provisioningObserved = false;
  const evidence = chosen.map((candidate, index) => {
    const action = knownAction(candidate.operationName), facts = safeFacts(candidate);
    const submittedFacts = safeSubmittedFacts(candidate);
    const provisioning = hasProvisioningOutcome(candidate), targets = safeProvisioningTargets(candidate);
    const values = factValues({ facts });
    const technicalFactContributionSources = [values.some(value => !factCoverage.has(value)) && 'resource-graph-changes',
      submittedFacts.some(fact => !submittedFactCoverage.has(submittedFactKey(fact))) && 'submitted-template'].filter(Boolean);
    const contributionLabels = [!families.has(action.family) && 'new-family', !actions.has(action.actionLabel) && 'new-action',
      technicalFactContributionSources.length > 0 && 'new-technical-fact',
      provisioning && !provisioningObserved && 'new-provisioning-outcome',
      targets.some(target => !targetAliases.has(target.targetResourceId)) && 'new-provisioned-target',
      !groups.has(candidate.groupKey) && 'new-group'].filter(Boolean);
    if (!contributionLabels.length) contributionLabels.push('repeated-evidence');
    families.add(action.family); actions.add(action.actionLabel); values.forEach(value => factCoverage.add(value));
    submittedFacts.forEach(fact => submittedFactCoverage.add(submittedFactKey(fact)));
    provisioningObserved ||= provisioning;
    const provisioningTargets = targets.map(({ targetResourceId, ...target }) => {
      if (!targetAliases.has(targetResourceId)) targetAliases.set(targetResourceId, `T${targetAliases.size + 1}`);
      return { alias: targetAliases.get(targetResourceId), ...target, provisioningState: 'Succeeded' };
    });
    if (!groups.has(candidate.groupKey)) groups.set(candidate.groupKey, `G${groups.size + 1}`);
    return { alias: `E${index + 1}`, groupAlias: groups.get(candidate.groupKey), ...action,
      contributionLabels, technicalFactContributionSources,
      claimLabel: 'attributed-successful-control-plane-action',
      sourceLabels: ['activity-log', ...(candidate.changeIds.length ? ['resource-graph-changes'] : []),
        ...(provisioning ? ['arm-deployment'] : []), ...(targets.length ? ['arm-deployment-operations'] : []),
        ...(submittedFacts.length ? ['submitted-template'] : [])],
      linkLabels: LINKS.filter(link => candidate.sourceLinks.includes(link)),
      outcomeLabels: ['control-plane-succeeded', ...(facts.length ? ['configuration-delta-observed'] : []),
        ...(provisioning ? ['arm-deployment-provisioning-succeeded'] : []),
        ...(targets.length ? ['arm-target-provisioning-succeeded'] : [])],
      technicalFacts: facts, submittedFacts, provisioningTargets,
      sourceFields: [{ source: 'activity-log', field: 'operationName', value: candidate.operationName },
        { source: 'activity-log', field: 'eventName', value: 'EndRequest' },
        { source: 'activity-log', field: 'status', value: 'Succeeded' },
        ...facts.map(fact => ({ source: 'resource-graph-changes', field: `properties.securityRules[].properties.${fact.field}`,
          previousValue: fact.previousValue, newValue: fact.newValue, change: fact.change })),
        ...submittedFacts.map(fact => ({ source: 'submitted-template', ...fact })),
        ...(provisioning ? [{ source: 'arm-deployment', field: 'properties.provisioningState', value: 'Succeeded' }] : []),
        ...provisioningTargets.flatMap(target => [
          { source: 'arm-deployment-operations', targetAlias: target.alias, field: 'properties.provisioningState', value: 'Succeeded' },
          { source: 'arm-deployment-operations', targetAlias: target.alias, field: 'properties.provisioningOperation', value: target.provisioningOperation },
          { source: 'arm-deployment-operations', targetAlias: target.alias, field: 'properties.statusCode', value: target.statusCode }])],
      depth: { actor: 'supplied-reference-matched', action: 'terminal-success',
        configuration: facts.length ? 'safe-delta-observed' : 'not-observed',
        submittedConfiguration: submittedFacts.length ? 'whole-deployment-constants-observed' : 'not-observed',
        outcome: provisioning ? 'arm-provisioning-only' : 'control-plane-only', workflow: 'not-established' },
      missingDepthLabels: ['runtime-outcome-not-checked', 'causal-workflow-not-established', 'production-use-not-established',
        'expertise-not-established', 'identity-reference-not-cryptographic-proof',
        ...(provisioning ? ['arm-provisioning-is-not-runtime-health'] : []),
        ...(submittedFacts.length ? ['submitted-template-is-not-effective-configuration',
          'submitted-template-not-bound-to-specific-target', 'template-authorship-not-established'] : []),
        ...(facts.length ? ['partial-configuration-only']
          : [submittedFacts.length ? 'effective-configuration-not-observed' : 'configuration-details-absent']),
        ...(candidate.uncertainLogicalIdentity ? ['logical-action-identity-uncertain'] : [])],
      counts: { activityRows: candidate.rows.length, configurationRecords: candidate.changeIds.length, configurationFacts: facts.length,
        deploymentRecords: count(candidate.deploymentIds?.length), deploymentOperationRecords: count(candidate.deploymentOperationKeys?.length),
        deploymentTemplateRecords: count(candidate.deploymentTemplateKeys?.length), submittedFacts: submittedFacts.length,
        provisionedTargets: new Set(targets.map(target => target.targetResourceId)).size } };
  });
  return { schemaVersion: 1, assurance: 'local-source-observation', actorBinding: 'supplied-reference-only',
    coverage: 'selected-research-sample', grouping: 'exact-resource-half-hour-window',
    counts: { inputActivityRows: activity.reduce((sum, row) => sum + row.rows.length + row.duplicateRows, 0),
      uniqueActivityRows: activity.reduce((sum, row) => sum + row.rows.length, 0),
      duplicateActivityRows: activity.reduce((sum, row) => sum + row.duplicateRows, 0),
      logicalActions: activity.length, eligibleActions: activity.filter(row => row.eligible).length,
      selectedActions: evidence.length, selectedGroups: groups.size,
      configurationRecords: allChanges.size, linkedConfigurationRecords: linkedChanges.size,
      unlinkedConfigurationRecords: allChanges.size - linkedChanges.size,
      distinctSelectedFacts: factCoverage.size,
      distinctSelectedSubmittedFacts: submittedFactCoverage.size,
      deploymentRecords: outcomeRecords.filter(row => row.source === 'deployment').length,
      linkedDeploymentRecords: outcomeRecords.filter(row => row.source === 'deployment' && row.linked).length,
      deploymentOperationRecords: outcomeRecords.filter(row => row.source === 'deployment-operations').length,
      linkedDeploymentOperationRecords: outcomeRecords.filter(row => row.source === 'deployment-operations' && row.linked).length,
      deploymentTemplateRecords: templateRecords.length,
      linkedDeploymentTemplateRecords: templateRecords.filter(row => row.linked).length,
      duplicateDeploymentTemplateRows: templateRecords.reduce((sum, row) => sum + count(row.duplicateRows), 0),
      excludedDeploymentTemplateRecords: templateRecords.filter(row => row.exclusionReason).length,
      duplicateOutcomeRows: outcomeRecords.reduce((sum, row) => sum + count(row.duplicateRows), 0),
      excludedOutcomeRecords: outcomeRecords.filter(row => row.exclusionReason).length,
      distinctSelectedProvisionedTargets: targetAliases.size,
      selectedActionsWithProvisioningOutcome: evidence.filter(row => row.depth.outcome === 'arm-provisioning-only').length },
    exclusions, evidence };
}
