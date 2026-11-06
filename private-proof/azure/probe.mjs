import { isDeepStrictEqual } from 'node:util';
import { extractAzureTemplateFacts } from './evidence.mjs';

function resourceSubscription(id) {
  const match = typeof id === 'string' && id.length <= 4096
    && id.match(/^\/subscriptions\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/(?:[^/?#%'\\\s\x00-\x1f\x7f]+\/)*[^/?#%'\\\s\x00-\x1f\x7f]+$/i);
  return match && !id.split('/').some(part => part === '.' || part === '..') ? match[1].toLowerCase() : null;
}

function deploymentScope(scope) {
  if (!scope || typeof scope !== 'object' || Array.isArray(scope) || Object.keys(scope).length !== 1
    || !Object.hasOwn(scope, 'deploymentId') || !resourceSubscription(scope.deploymentId)) return null;
  const parts = scope.deploymentId.match(/^\/subscriptions\/([^/]+)\/resourcegroups\/([\p{L}\p{N}_().-]{1,90})\/providers\/microsoft\.resources\/deployments\/([\p{L}\p{N}_().-]{1,64})$/iu);
  return parts && !parts[2].endsWith('.') ? parts : null;
}

export function validateProbeOptions({ source, days = 7, cutoff = Date.now(), maxPages = 3,
  maxBytes = 524288, timeoutMs = 20000, scope, onEvidence, before }, subscriptionId) {
  const invalid = () => { throw new Error('Invalid Azure probe input'); };
  if (!['inventory', 'activity', 'changes', 'deployment', 'deployment-operations', 'deployment-template'].includes(source)
    || !Number.isSafeInteger(cutoff) || cutoff > Date.now() + 60000 || cutoff < Date.now() - 86400000
    || !Number.isInteger(days) || days < 1 || days > (source === 'changes' ? 14 : 90)
    || !Number.isInteger(maxPages) || maxPages < 1 || maxPages > 10
    || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 2097152
    || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000
    || (onEvidence !== undefined && typeof onEvidence !== 'function')) invalid();
  if (before !== undefined && (source !== 'activity' || !Number.isSafeInteger(before)
    || before < cutoff - days * 86400000 || before > cutoff)) invalid();
  if (['deployment', 'deployment-operations', 'deployment-template'].includes(source)) {
    const parts = deploymentScope(scope);
    if (!parts || (subscriptionId !== undefined && (typeof subscriptionId !== 'string'
      || parts[1].toLowerCase() !== subscriptionId.toLowerCase()))) invalid();
  } else if (scope !== undefined) {
    if (source !== 'activity' || !scope || typeof scope !== 'object' || Array.isArray(scope)
      || Object.keys(scope).length !== 1) invalid();
    if (Object.hasOwn(scope, 'resourceId')) {
      const selected = resourceSubscription(scope.resourceId);
      if (!selected || (subscriptionId !== undefined && (typeof subscriptionId !== 'string'
        || selected !== subscriptionId.toLowerCase()))) invalid();
    } else if (Object.hasOwn(scope, 'correlationId')) {
      if (typeof scope.correlationId !== 'string'
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(scope.correlationId)) invalid();
    } else if (!Object.hasOwn(scope, 'resourceGroup') || typeof scope.resourceGroup !== 'string'
      || !/^[\p{L}\p{N}_().-]{1,90}$/u.test(scope.resourceGroup) || scope.resourceGroup.endsWith('.')) invalid();
  }
}

export function validateActivityFixture(fixture, { source, days, cutoff, subscriptionId }) {
  if (fixture === undefined) return;
  const invalid = () => { throw new Error('Invalid Azure probe input'); };
  if (source !== 'activity' || !fixture || typeof fixture !== 'object' || Array.isArray(fixture)
    || !Array.isArray(fixture.resourceIds) || fixture.resourceIds.length < 1 || fixture.resourceIds.length > 32
    || !Number.isSafeInteger(fixture.startedAt) || !Number.isSafeInteger(fixture.endedAt)
    || fixture.startedAt < cutoff - days * 86400000 || fixture.endedAt > cutoff || fixture.startedAt > fixture.endedAt) invalid();
  let expectedSubscription = subscriptionId?.toLowerCase();
  const ids = new Set();
  for (const id of fixture.resourceIds) {
    const selected = resourceSubscription(id);
    if (!selected || ids.has(id.toLowerCase())) invalid();
    expectedSubscription ??= selected;
    if (selected !== expectedSubscription) invalid();
    ids.add(id.toLowerCase());
  }
  return ids;
}

// Collection is independent of CLI authentication so it can run in the browser.
export async function probeAzure(input, fetchImpl = fetch) {
  const { source, subscriptionId, bearer, cutoff = Date.now(), days = 7,
    maxPages = 3, maxBytes = 524288, timeoutMs = 20000, actor, fixture, scope, onEvidence, before } = input;
  validateProbeOptions(input, subscriptionId);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const isUuid = value => typeof value === 'string' && uuid.test(value);
  const validObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const optionalText = value => {
    if (value === undefined || value === null || value === '') return null;
    if (typeof value !== 'string' || value.length > 4096 || /[\x00-\x1f\x7f]/.test(value)) throw new Error('invalid-response');
    return value;
  };
  const capture = record => {
    try { onEvidence(record); } catch { throw new Error('evidence-callback'); }
  };
  if (!isUuid(subscriptionId)
    || typeof bearer !== 'string' || !/^Bearer [A-Za-z0-9._~+/-]+=*$/.test(bearer) || bearer.length > 32768
    || (actor !== undefined && (!validObject(actor) || !isUuid(actor.objectId) || !isUuid(actor.tenantId)))) {
    throw new Error('Invalid Azure probe input');
  }
  const fixtureIds = validateActivityFixture(fixture, { source, days, cutoff, subscriptionId });
  const started = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = new Date(cutoff - days * 86400000).toISOString();
  const end = new Date(before ?? cutoff).toISOString();
  const origin = 'https://management.azure.com';
  const outcome = ['deployment', 'deployment-operations', 'deployment-template'].includes(source);
  const graph = source === 'inventory' || source === 'changes';
  const deployment = outcome ? deploymentScope(scope) : null;
  const path = source === 'deployment-template' ? `${scope.deploymentId}/exportTemplate`
    : source === 'deployment' ? scope.deploymentId : source === 'deployment-operations'
    ? `/subscriptions/${subscriptionId}/resourcegroups/${deployment[2]}/deployments/${deployment[3]}/operations`
    : `/subscriptions/${subscriptionId}/providers/Microsoft.Insights/eventtypes/management/values`;
  const filter = `eventTimestamp ge '${start}' and eventTimestamp le '${end}'`
    + (scope?.resourceId ? ` and resourceUri eq '${scope.resourceId}'` : scope?.resourceGroup ? ` and resourceGroupName eq '${scope.resourceGroup}'`
      : scope?.correlationId ? ` and correlationId eq '${scope.correlationId}'` : '');
  const select = 'claims,eventDataId,eventName,eventTimestamp,operationId,operationName,status,correlationId,resourceId,subscriptionId';
  const initial = new URL(graph ? '/providers/Microsoft.ResourceGraph/resources' : path, origin);
  const apiVersion = graph ? '2024-04-01' : outcome ? '2025-04-01' : '2015-04-01';
  initial.searchParams.set('api-version', apiVersion);
  if (source === 'activity') {
    initial.searchParams.set('$filter', filter);
    initial.searchParams.set('$select', select);
  }
  const query = source === 'inventory'
    ? 'Resources | summarize resourceCount=count() by type | order by type asc'
    : `resourcechanges | extend changeTime=todatetime(properties.changeAttributes.timestamp) | where changeTime >= datetime(${start}) and changeTime <= datetime(${end}) | project id, changeTime, resourceType=tostring(properties.targetResourceType), changeType=tostring(properties.changeType), actorType=tostring(properties.changeAttributes.changedByType), operation=tostring(properties.changeAttributes.operation)${onEvidence ? ', targetResourceId=tostring(properties.targetResourceId), correlationId=tostring(properties.changeAttributes.correlationId), changesCount=tolong(properties.changeAttributes.changesCount), changes=properties.changes' : ''} | order by changeTime desc, id asc`;
  const body = { subscriptions: [subscriptionId], query, options: { resultFormat: 'objectArray', $top: 100 } };
  const families = {
    'microsoft.compute': 'compute', 'microsoft.web': 'application-hosting',
    'microsoft.app': 'containers', 'microsoft.containerservice': 'kubernetes',
    'microsoft.network': 'networking', 'microsoft.storage': 'storage',
    'microsoft.sql': 'databases', 'microsoft.dbforpostgresql': 'databases',
    'microsoft.documentdb': 'databases', 'microsoft.datafactory': 'data-pipelines',
    'microsoft.synapse': 'data-pipelines', 'microsoft.authorization': 'access-control',
    'microsoft.keyvault': 'secrets-management', 'microsoft.insights': 'monitoring',
    'microsoft.operationalinsights': 'monitoring', 'microsoft.resources': 'resource-management',
    'microsoft.servicebus': 'messaging', 'microsoft.eventhub': 'messaging',
    'microsoft.machinelearningservices': 'machine-learning', 'microsoft.cognitiveservices': 'ai-services',
  };
  const operations = {
    'microsoft.compute/virtualmachines/write': 'vm-write',
    'microsoft.web/sites/write': 'web-app-write',
    'microsoft.web/sites/slots/slotsswap/action': 'web-slot-swap',
    'microsoft.containerservice/managedclusters/write': 'aks-cluster-write',
    'microsoft.network/networksecuritygroups/write': 'network-security-group-write',
    'microsoft.network/networksecuritygroups/delete': 'network-security-group-delete',
    'microsoft.network/networksecuritygroups/securityrules/write': 'network-rule-write',
    'microsoft.network/networksecuritygroups/securityrules/delete': 'network-rule-delete',
    'microsoft.network/virtualnetworks/write': 'virtual-network-write',
    'microsoft.storage/storageaccounts/write': 'storage-account-write',
    'microsoft.sql/servers/databases/write': 'sql-database-write',
    'microsoft.authorization/roleassignments/write': 'role-assignment-write',
    'microsoft.keyvault/vaults/write': 'key-vault-write',
    'microsoft.insights/metricalerts/write': 'metric-alert-write',
    'microsoft.datafactory/factories/pipelines/write': 'data-pipeline-write',
    'microsoft.resources/deployments/write': 'arm-deployment-write',
    'microsoft.resources/subscriptions/resourcegroups/write': 'resource-group-write',
    'microsoft.resources/subscriptions/resourcegroups/delete': 'resource-group-delete',
  };
  const report = { version: 2, source, assurance: 'local-source-observation', actorBinding: actor ? 'supplied-reference-only' : 'not-established',
    status: 'incomplete', reason: 'page-budget', windowDays: source === 'inventory' || outcome ? null : days,
    windowEndOffsetMs: source === 'activity' ? cutoff - (before ?? cutoff) : null,
    requests: 0, pages: 0, bytes: 0, requestBodyBytes: 0, byteOvershoot: 0, rows: 0, uniqueRows: 0, duplicateRows: 0,
    successfulTerminalRows: 0, actorClaimRows: 0, matchingActorRows: 0, matchingSuccessfulTerminalRows: 0,
    actorKinds: { user: 0, application: 0, system: 0, unresolved: 0 }, families: {}, operations: {}, elapsedMs: 0 };
  if (fixture) report.fixture = { rows: 0, matchingActorRows: 0, matchingSuccessfulTerminalRows: 0, matchingFailedTerminalRows: 0, operations: {} };
  const seen = new Map();
  const cursors = new Set();
  let url = initial.href;
  try {
    for (let page = 0; page < maxPages; page++) {
      if (performance.now() - started >= timeoutMs || controller.signal.aborted) throw new Error('deadline');
      const requestBody = graph ? JSON.stringify(body) : undefined;
      if (requestBody) report.requestBodyBytes += new TextEncoder().encode(requestBody).byteLength;
      report.requests++;
      const response = await fetchImpl(url, {
        method: graph || source === 'deployment-template' ? 'POST' : 'GET',
        headers: { Authorization: bearer, Accept: 'application/json', ...(graph ? { 'Content-Type': 'application/json' } : {}) },
        ...(graph ? { body: requestBody } : {}),
        signal: controller.signal, redirect: 'error', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer',
      });
      if (response.status !== 200) {
        await response.body?.cancel();
        report.status = ({401: 'unauthenticated', 403: 'denied', 429: 'throttled'})[response.status] ?? 'unavailable';
        report.reason = 'http-status';
        report.httpStatus = response.status;
        break;
      }
      if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '') || !response.body) {
        await response.body?.cancel();
        throw new Error('invalid-response');
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8', { fatal: true });
      let text = '';
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          report.bytes += value.byteLength;
          if (report.bytes > maxBytes) throw new Error('byte-budget');
          text += decoder.decode(value, { stream: true });
        }
        text += decoder.decode();
      } finally { await reader.cancel(); }
      let data;
      try { data = JSON.parse(text); } catch { throw new Error('invalid-response'); }
      if (!validObject(data) || data.error || data.errors) throw new Error('invalid-response');
      if (source === 'deployment-template') {
        if (!validObject(data.template)) throw new Error('invalid-response');
        if (data.nextLink) throw new Error('pagination-invalid');
        let submittedFacts;
        try { submittedFacts = extractAzureTemplateFacts(data.template); } catch { throw new Error('invalid-response'); }
        report.pages++;
        report.rows++;
        report.uniqueRows++;
        report.submittedFactCount = submittedFacts.length;
        if (onEvidence) capture({ source, deploymentId: scope.deploymentId.toLowerCase(), observedAt: Date.now(), submittedFacts });
        report.status = 'complete';
        report.reason = 'pages-exhausted';
        break;
      }
      const rows = source === 'deployment' ? [data] : graph ? data.data : data.value;
      if (!Array.isArray(rows)) throw new Error('invalid-response');
      report.pages++;
      for (const row of rows) {
        report.rows++;
        if (!validObject(row)) throw new Error('invalid-response');
        const id = source === 'activity' ? row.eventDataId : source === 'deployment-operations' ? row.operationId
          : source === 'inventory' ? row.type : row.id;
        if (typeof id !== 'string' || !id || id.length > 4096) throw new Error('invalid-response');
        const serialized = JSON.stringify(row);
        if (seen.has(id)) {
          if (!isDeepStrictEqual(JSON.parse(seen.get(id)), row)) throw new Error('conflicting-duplicate');
          report.duplicateRows++;
          continue;
        }
        seen.set(id, serialized);
        if (outcome) {
          if (!validObject(row.properties)) throw new Error('invalid-response');
          if (source === 'deployment' && row.id.toLowerCase() !== scope.deploymentId.toLowerCase()) throw new Error('scope-mismatch');
          if (source === 'deployment-operations' && (typeof row.id !== 'string'
            || row.id.toLowerCase() !== `${scope.deploymentId}/operations/${id}`.toLowerCase())) throw new Error('scope-mismatch');
          const properties = row.properties, timestamp = optionalText(properties.timestamp), observedAt = Date.now();
          if (!timestamp || !Number.isFinite(Date.parse(timestamp)) || Date.parse(timestamp) < 0
            || Date.parse(timestamp) > observedAt + 60000) throw new Error('invalid-response');
          const states = ['NotSpecified', 'Accepted', 'Running', 'Ready', 'Creating', 'Created', 'Deleting', 'Deleted', 'Canceled', 'Failed', 'Succeeded', 'Updating'];
          const provisioningState = states.includes(properties.provisioningState) ? properties.provisioningState : 'Unknown';
          if (typeof properties.provisioningState !== 'string') throw new Error('invalid-response');
          const record = { source, deploymentId: scope.deploymentId.toLowerCase(), timestamp, observedAt, provisioningState };
          if (source === 'deployment') record.correlationId = optionalText(properties.correlationId);
          else {
            const operations = ['NotSpecified', 'Create', 'Delete', 'Waiting', 'AzureAsyncOperationWaiting', 'ResourceCacheWaiting', 'Action', 'Read', 'EvaluateDeploymentOutput', 'DeploymentCleanup'];
            const targetResourceId = properties.targetResource?.id;
            if (properties.targetResource != null && !validObject(properties.targetResource)) throw new Error('invalid-response');
            if (targetResourceId != null && resourceSubscription(targetResourceId) !== subscriptionId.toLowerCase()) throw new Error('scope-mismatch');
            const statusCode = optionalText(properties.statusCode);
            const provisioningOperation = optionalText(properties.provisioningOperation);
            Object.assign(record, { operationId: id,
              provisioningOperation: operations.includes(provisioningOperation) ? provisioningOperation : 'Unknown',
              statusCode: statusCode && /^(?:[1-5][0-9]{2}|OK|Created|Accepted|NoContent|BadRequest|Unauthorized|Forbidden|NotFound|Conflict|TooManyRequests|InternalServerError|ServiceUnavailable)$/.test(statusCode) ? statusCode : null,
              targetResourceId: targetResourceId?.toLowerCase() ?? null });
          }
          report.uniqueRows++;
          if (onEvidence) capture(record);
          continue;
        }
        const time = source === 'activity' ? row.eventTimestamp : row.changeTime;
        if (source !== 'inventory' && (typeof time !== 'string' || !Number.isFinite(Date.parse(time))
          || Date.parse(time) < Date.parse(start) || Date.parse(time) > Date.parse(end))) throw new Error('invalid-response');
        if (source === 'activity' && (typeof row.subscriptionId !== 'string'
          || row.subscriptionId.toLowerCase() !== subscriptionId.toLowerCase())) throw new Error('scope-mismatch');
        if (source === 'activity' && (scope || onEvidence)) {
          if (row.resourceId != null && resourceSubscription(row.resourceId) !== subscriptionId.toLowerCase()) throw new Error('scope-mismatch');
          const id = row.resourceId?.toLowerCase();
          const group = `/subscriptions/${subscriptionId}/resourcegroups/${scope?.resourceGroup}`.toLowerCase();
          if ((scope?.resourceId && id !== scope.resourceId.toLowerCase())
            || (scope?.resourceGroup && id !== group && !id?.startsWith(`${group}/`))
            || (scope?.correlationId && (!isUuid(row.correlationId)
              || row.correlationId.toLowerCase() !== scope.correlationId.toLowerCase()))) throw new Error('scope-mismatch');
        }
        if (source === 'changes' && (onEvidence || row.targetResourceId !== undefined)
          && resourceSubscription(row.targetResourceId) !== subscriptionId.toLowerCase()) throw new Error('scope-mismatch');
        if (source === 'inventory' && (!Number.isSafeInteger(row.resourceCount) || row.resourceCount < 0)) throw new Error('invalid-response');
        report.uniqueRows++;
        const operation = source === 'activity' ? row.operationName?.value : row.operation;
        const type = source === 'inventory' ? row.type : source === 'changes' ? row.resourceType : operation;
        const provider = typeof type === 'string' ? type.toLowerCase().split('/')[0] : '';
        const family = Object.hasOwn(families, provider) ? families[provider] : 'other';
        report.families[family] = (report.families[family] ?? 0) + (source === 'inventory' ? row.resourceCount : 1);
        if (source === 'activity') {
          if (!validObject(row.operationName) || typeof operation !== 'string' || !validObject(row.status)
            || typeof row.status.value !== 'string' || !validObject(row.eventName)
            || (row.eventName.value !== null && typeof row.eventName.value !== 'string')) throw new Error('invalid-response');
          const terminal = row.status.value.toLowerCase() === 'succeeded' && row.eventName.value?.toLowerCase() === 'endrequest';
          if (terminal) report.successfulTerminalRows++;
          const claims = validObject(row.claims) ? row.claims : {};
          const oid = claims['http://schemas.microsoft.com/identity/claims/objectidentifier'];
          const tenant = claims['http://schemas.microsoft.com/identity/claims/tenantid'];
          const actorMatched = Boolean(actor && isUuid(oid) && oid.toLowerCase() === actor.objectId.toLowerCase());
          const tenantMatched = Boolean(actor && isUuid(tenant) && tenant.toLowerCase() === actor.tenantId.toLowerCase());
          let matchesActor = false;
          if (typeof oid === 'string' && uuid.test(oid) && typeof tenant === 'string' && uuid.test(tenant)) {
            report.actorClaimRows++;
            matchesActor = actorMatched && tenantMatched;
          }
          if (matchesActor) report.matchingActorRows++;
          if (matchesActor && terminal) report.matchingSuccessfulTerminalRows++;
          const label = Object.hasOwn(operations, operation.toLowerCase()) ? operations[operation.toLowerCase()] : null;
          if (label) {
            report.operations[label] ??= { rows: 0, successfulTerminalRows: 0, matchingActorRows: 0, matchingSuccessfulTerminalRows: 0 };
            report.operations[label].rows++;
            if (terminal) report.operations[label].successfulTerminalRows++;
            if (matchesActor) report.operations[label].matchingActorRows++;
            if (matchesActor && terminal) report.operations[label].matchingSuccessfulTerminalRows++;
          }
          if (fixtureIds && typeof row.resourceId === 'string' && fixtureIds.has(row.resourceId.toLowerCase())
            && Date.parse(time) >= fixture.startedAt && Date.parse(time) <= fixture.endedAt) {
            const failedTerminal = row.status.value.toLowerCase() === 'failed' && row.eventName.value?.toLowerCase() === 'endrequest';
            report.fixture.rows++;
            if (matchesActor) report.fixture.matchingActorRows++;
            if (matchesActor && terminal) report.fixture.matchingSuccessfulTerminalRows++;
            if (matchesActor && failedTerminal) report.fixture.matchingFailedTerminalRows++;
            if (label) {
              report.fixture.operations[label] ??= { rows: 0, matchingActorRows: 0, matchingSuccessfulTerminalRows: 0, matchingFailedTerminalRows: 0 };
              const counts = report.fixture.operations[label];
              counts.rows++;
              if (matchesActor) counts.matchingActorRows++;
              if (matchesActor && terminal) counts.matchingSuccessfulTerminalRows++;
              if (matchesActor && failedTerminal) counts.matchingFailedTerminalRows++;
            }
          }
          if (onEvidence) capture({ source, eventDataId: id, resourceId: row.resourceId?.toLowerCase() ?? null,
            operationId: optionalText(row.operationId), correlationId: optionalText(row.correlationId), timestamp: time,
            operationName: optionalText(operation)?.toLowerCase() ?? null, eventName: optionalText(row.eventName.value),
            status: optionalText(row.status.value), family, actionLabel: label, actorMatched, tenantMatched,
            matchesActor, successfulTerminal: terminal });
        } else if (source === 'changes') {
          const kind = row.actorType === 'User' ? 'user' : row.actorType === 'Application' ? 'application' : row.actorType === 'System' ? 'system' : 'unresolved';
          report.actorKinds[kind]++;
          if (onEvidence) {
            if (row.changes != null && !validObject(row.changes)) throw new Error('invalid-response');
            if (row.changesCount != null && (!Number.isSafeInteger(row.changesCount) || row.changesCount < 0)) throw new Error('invalid-response');
            const changes = Object.fromEntries(Object.entries(row.changes ?? {}).map(([name, change]) => {
              if (!optionalText(name) || !validObject(change)
                || (change.isTruncated !== undefined && ![true, false, 'true', 'false'].includes(change.isTruncated))) throw new Error('invalid-response');
              return [name, Object.fromEntries(['previousValue', 'newValue', 'isTruncated']
                .filter(key => Object.hasOwn(change, key)).map(key => [key, change[key]]))];
            }));
            capture({ source, id, targetResourceId: row.targetResourceId.toLowerCase(), correlationId: optionalText(row.correlationId),
              changeTime: time, resourceType: optionalText(row.resourceType)?.toLowerCase() ?? null,
              changeType: optionalText(row.changeType), actorType: optionalText(row.actorType), operation: optionalText(operation),
              changesCount: row.changesCount ?? null, changes });
          }
        }
      }
      let cursor;
      if (!graph) {
        cursor = data.nextLink;
        if (source === 'deployment' && cursor) throw new Error('pagination-invalid');
        if (cursor !== undefined && cursor !== null && cursor !== '') {
          if (typeof cursor !== 'string' || cursor.length > 16384) throw new Error('pagination-invalid');
          let next;
          try { next = new URL(cursor); } catch { throw new Error('pagination-invalid'); }
          if (next.origin !== origin || next.username || next.password || next.hash
            || next.pathname.toLowerCase() !== initial.pathname.toLowerCase()) throw new Error('pagination-invalid');
          for (const [key, value] of next.searchParams) {
            if (!(source === 'activity' ? ['api-version', '$filter', '$select', '$skiptoken'] : ['api-version', '$skiptoken']).includes(key.toLowerCase())
              || [...next.searchParams.keys()].filter(k => k.toLowerCase() === key.toLowerCase()).length !== 1
              || (key.toLowerCase() === 'api-version' && value !== apiVersion)
              || (key.toLowerCase() === '$filter' && value !== filter) || (key.toLowerCase() === '$select' && value !== select)) throw new Error('pagination-invalid');
          }
          url = next.href;
        }
      } else {
        if (![true, false, 'true', 'false'].includes(data.resultTruncated)) throw new Error('invalid-response');
        cursor = data.$skipToken;
        if (cursor !== undefined && (typeof cursor !== 'string' || !cursor || cursor.length > 16384)) throw new Error('pagination-invalid');
        if ((data.resultTruncated === true || data.resultTruncated === 'true') && !cursor) {
          report.reason = 'source-truncated';
          break;
        }
        if (cursor) body.options.$skipToken = cursor;
      }
      if (!cursor) { report.status = 'complete'; report.reason = 'pages-exhausted'; break; }
      if (cursors.has(cursor)) throw new Error('pagination-repeated');
      cursors.add(cursor);
    }
  } catch (error) {
    const reason = controller.signal.aborted ? 'deadline' : error.message;
    report.reason = ['deadline', 'byte-budget', 'invalid-response', 'scope-mismatch', 'conflicting-duplicate', 'pagination-invalid', 'pagination-repeated', 'evidence-callback'].includes(reason) ? reason : 'network-error';
    report.status = 'incomplete';
  } finally {
    clearTimeout(timer);
    controller.abort();
    report.elapsedMs = Math.round(performance.now() - started);
    report.byteOvershoot = Math.max(0, report.bytes - maxBytes);
    seen.clear();
  }
  return report;
}
