import { isDeepStrictEqual } from 'node:util';
import { probeAzure } from './probe.mjs';
import { buildAzureEvidence, selectAzureEvidence } from './evidence.mjs';

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const CONTEXT = ['objectId', 'tenantId', 'subscriptionId', 'homeAccountId', 'graphBearer', 'armBearer', 'expiresAt'];
// Candidate filtering only. Noir independently checks the authenticated full path.
function roleAssignmentResource(resourceId) {
  if (typeof resourceId !== 'string' || resourceId.length > 512 || !/^\/[a-z0-9_().\/-]+$/.test(resourceId)) return false;
  const parts = resourceId.slice(1).split('/'), count = parts.length;
  if (count < 6 || count > 32 || parts.some(part => !part || part === '.' || part === '..') ||
      parts[0] !== 'subscriptions' || !UUID.test(parts[1]) ||
      parts.at(-4) !== 'providers' || parts.at(-3) !== 'microsoft.authorization' ||
      parts.at(-2) !== 'roleassignments' || !UUID.test(parts.at(-1))) return false;
  const end = count - 4, base = end >= 4 && parts[2] === 'resourcegroups' ? 4 : 2;
  if (end === base) return true;
  let state = 0;
  for (let i = base; i < end; i++) {
    const marker = parts[i] === 'providers';
    if (state === 0) { if (!marker) return false; state = 1; }
    else if (state === 1) { if (!/^[a-z][a-z0-9]*(?:\.[a-z0-9]+)+$/.test(parts[i])) return false; state = 2; }
    else if (state === 2) { if (marker) return false; state = 3; }
    else if (state === 3) state = 4;
    else state = marker ? 1 : 3;
  }
  return state === 4;
}

// Site ownership only; the authenticated action supplies swap semantics.
function slotSwapResource(resourceId) {
  if (typeof resourceId !== 'string' || resourceId.length > 512 || !/^\/[a-z0-9_().\/-]+$/.test(resourceId)) return false;
  const parts = resourceId.slice(1).split('/');
  if (parts.length < 8 || parts.length > 32 || parts.some(part => !part || part === '.' || part === '..') ||
      parts[0] !== 'subscriptions' || !UUID.test(parts[1]) || parts[2] !== 'resourcegroups' ||
      parts[4] !== 'providers' || parts[5] !== 'microsoft.web' || parts[6] !== 'sites') return false;
  if (parts.length % 2 === 1 && parts.pop() !== 'slotsswap') return false;
  for (let i = 8; i < parts.length; i += 2) if (parts[i] === 'providers') return false;
  return true;
}

const eligible = candidate => candidate.eligible && !candidate.uncertainLogicalIdentity &&
  UUID.test(candidate.operationId) && candidate.eventIds.every(id => UUID.test(id)) &&
  candidate.correlationIds.length === 1 && UUID.test(candidate.correlationIds[0]) &&
  ((['network-rule-write', 'network-rule-delete'].includes(candidate.actionLabel) &&
      /\/providers\/microsoft\.network\/networksecuritygroups\/[^/]+\/securityrules\/[^/]+$/.test(candidate.resourceId)) ||
    (["network-security-group-write", "network-security-group-delete"].includes(candidate.actionLabel) &&
      /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+\/providers\/microsoft\.network\/networksecuritygroups\/[^/]+$/.test(candidate.resourceId)) ||
    (["vm-write"].includes(candidate.actionLabel) &&
      /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+\/providers\/microsoft\.compute\/virtualmachines\/[^/]+$/.test(candidate.resourceId)) ||
    (["web-app-write"].includes(candidate.actionLabel) &&
      /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+\/providers\/microsoft\.web\/sites\/[^/]+$/.test(candidate.resourceId)) ||
    (["aks-cluster-write"].includes(candidate.actionLabel) &&
      /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+\/providers\/microsoft\.containerservice\/managedclusters\/[^/]+$/.test(candidate.resourceId)) ||
    (["virtual-network-write"].includes(candidate.actionLabel) &&
      /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+\/providers\/microsoft\.network\/virtualnetworks\/[^/]+$/.test(candidate.resourceId)) ||
    (["storage-account-write"].includes(candidate.actionLabel) &&
      /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+\/providers\/microsoft\.storage\/storageaccounts\/[^/]+$/.test(candidate.resourceId)) ||
    (["key-vault-write"].includes(candidate.actionLabel) &&
      /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+\/providers\/microsoft\.keyvault\/vaults\/[^/]+$/.test(candidate.resourceId)) ||
    (["metric-alert-write"].includes(candidate.actionLabel) &&
      /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+\/providers\/microsoft\.insights\/metricalerts\/[^/]+$/.test(candidate.resourceId)) ||
    (candidate.actionLabel === 'sql-database-write' && /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+\/providers\/microsoft\.sql\/servers\/[^/]+\/databases\/[^/]+$/.test(candidate.resourceId)) ||
    (candidate.actionLabel === 'data-pipeline-write' && /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+\/providers\/microsoft\.datafactory\/factories\/[^/]+\/pipelines\/[^/]+$/.test(candidate.resourceId)) ||
    (['resource-group-write', 'resource-group-delete'].includes(candidate.actionLabel) && /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourcegroups\/[^/]+$/.test(candidate.resourceId)) ||
    (candidate.actionLabel === 'arm-deployment-write' && /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?:\/resourcegroups\/[^/]+)?\/providers\/microsoft\.resources\/deployments\/[^/]+$/.test(candidate.resourceId)) ||
    (candidate.actionLabel === 'role-assignment-write' && roleAssignmentResource(candidate.resourceId)) ||
    (candidate.actionLabel === 'web-slot-swap' && slotSwapResource(candidate.resourceId)));

// Context is a browser-local routing reference, never authenticated proof of identity.
export async function discoverAzureActivity({ getContext, fetchImpl = fetch, signal, cutoffMs = Date.now() }) {
  const controller = new AbortController(), started = performance.now();
  const timer = setTimeout(() => controller.abort(), 30000);
  const combined = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
  let pin, failure = null, requests = 0, bytes = 0;
  const records = [];
  const fail = reason => { failure = reason; throw new Error(reason); };
  const check = () => {
    if (signal?.aborted) fail('cancelled');
    if (controller.signal.aborted || performance.now() - started >= 30000) fail('budget');
    if (Date.now() >= pin.expiresAt) fail('expired');
    const current = getContext();
    if (!current || CONTEXT.some(key => current[key] !== pin[key])) fail('context-changed');
  };
  try {
    const context = getContext();
    if (!context || CONTEXT.some(key => !Object.hasOwn(context, key)) ||
        !['objectId', 'tenantId', 'subscriptionId'].every(key => typeof context[key] === 'string' && UUID.test(context[key])) ||
        typeof context.homeAccountId !== 'string' || !context.homeAccountId.length || context.homeAccountId.length > 256 ||
        !['graphBearer', 'armBearer'].every(key => typeof context[key] === 'string' &&
          /^Bearer [A-Za-z0-9._~+/-]+=*$/.test(context[key]) && context[key].length <= 12000) ||
        !Number.isSafeInteger(context.expiresAt) || context.expiresAt < Date.now() + 60000 ||
        !Number.isSafeInteger(cutoffMs) || cutoffMs > Date.now() || cutoffMs < Date.now() - 60000) fail('invalid-context');
    pin = Object.fromEntries(CONTEXT.map(key => [key, context[key]]));
    check();
    const read = async correlationId => {
      check(); records.length = 0;
      const remaining = Math.floor(30000 - (performance.now() - started));
      if (remaining < 1 || requests >= 12 || bytes >= 2097152) fail('budget');
      const report = await probeAzure({ source: 'activity', subscriptionId: pin.subscriptionId,
        bearer: pin.armBearer, actor: { objectId: pin.objectId, tenantId: pin.tenantId }, cutoff: cutoffMs, days: 14,
        maxPages: correlationId ? 1 : Math.min(3, 12 - requests),
        maxBytes: Math.min(correlationId ? 14336 : 2097152, 2097152 - bytes), timeoutMs: remaining,
        ...(correlationId ? { scope: { correlationId } } : {}), onEvidence: row => records.push(row),
      }, async (url, options) => {
        check();
        if (++requests > 12) fail('budget');
        const response = await fetchImpl(url, { ...options, signal: AbortSignal.any([options.signal, combined]) });
        try { check(); } catch (error) { await response.body?.cancel(); throw error; }
        return response;
      });
      bytes += report.bytes;
      check();
      if (failure) fail(failure);
      if (report.status !== 'complete') fail('source-incomplete');
      return buildAzureEvidence(records);
    };
    const discovered = (await read()).filter(eligible);
    const [selected] = selectAzureEvidence(discovered, { strategy: 'incremental', limit: 1 });
    if (!selected) fail('no-eligible-selection');
    const confirmed = (await read(selected.correlationIds[0])).find(row => row.key === selected.key && eligible(row));
    const sortedRows = candidate => candidate.rows.slice().sort((a, b) => a.eventDataId.localeCompare(b.eventDataId));
    if (!confirmed || !isDeepStrictEqual(sortedRows(selected), sortedRows(confirmed))) fail('selection-changed');
    check();
    return { status: 'ready', verified: false, context: pin,
      selected: { subscriptionId: pin.subscriptionId, correlationId: confirmed.correlationIds[0],
        cutoffMs, candidate: confirmed },
      diagnostics: { requests, bytes, groups: new Set(discovered.map(row => row.groupKey)).size } };
  } catch {
    return { status: 'unavailable', verified: false, reason: failure ?? 'failed' };
  } finally { clearTimeout(timer); records.length = 0; }
}

// Only this projection may cross the browser discovery boundary into application UI.
export function projectAzureDiscovery(result) {
  return { status: result?.status === 'ready' ? 'ready' : 'unavailable', verified: false };
}
