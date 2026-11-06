// Synthetic test data only. These receipts never establish live service provenance.
import { createHash, randomBytes } from 'node:crypto';
import { planAzureSession } from './browser-plan.mjs';

const id = byte => `${byte.repeat(8)}-${byte.repeat(4)}-${byte.repeat(4)}-${byte.repeat(4)}-${byte.repeat(12)}`;
export function syntheticAzureAttempt() {
  const now = Date.now();
  return { proofId: id('1'), pluginSha256: 'a'.repeat(64), nonceMac: 'b'.repeat(43), challenge: 'c'.repeat(64),
    cutoffMs: now, issuedAt: now, expiresAt: now + 3600000 };
}

export function syntheticAzureSources(attempt, { rows = 1 } = {}) {
  const actor = id('a'), tenantId = id('b'), subscriptionId = id('c'), correlationId = id('f');
  const projection = 'claims,eventDataId,eventName,eventTimestamp,operationId,operationName,status,correlationId,resourceId,subscriptionId';
  const activityTarget = new URL(`/subscriptions/${subscriptionId}/providers/Microsoft.Insights/eventtypes/management/values`, 'https://management.azure.com');
  activityTarget.searchParams.set('api-version', '2015-04-01');
  activityTarget.searchParams.set('$filter', `eventTimestamp ge '${new Date(attempt.cutoffMs - 14 * 86400000).toISOString()}' and eventTimestamp le '${new Date(attempt.cutoffMs).toISOString()}' and correlationId eq '${correlationId}'`);
  activityTarget.searchParams.set('$select', projection);
  const targets = ['/v1.0/me?$select=id', `/subscriptions/${subscriptionId}?api-version=2022-12-01`, activityTarget.pathname + activityTarget.search];
  const bodies = [JSON.stringify({ '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#users(id)/$entity', id: actor }),
    JSON.stringify({ subscriptionId, tenantId, state: 'Enabled' }),
    JSON.stringify({ value: Array.from({ length: rows }, (_, index) => ({
      claims: { 'http://schemas.microsoft.com/identity/claims/objectidentifier': actor,
        'http://schemas.microsoft.com/identity/claims/tenantid': tenantId, employerPrivateKey: 'x'.repeat(600) },
      eventDataId: id(index ? '2' : 'd'), eventName: { value: index ? 'BeginRequest' : 'EndRequest' },
      eventTimestamp: new Date(attempt.cutoffMs - (index ? 2000 : 1000)).toISOString(), operationId: id('e'),
      operationName: { value: 'Microsoft.Network/networkSecurityGroups/securityRules/write' },
      status: { value: index ? 'Started' : 'Succeeded' }, correlationId,
      resourceId: `/subscriptions/${subscriptionId}/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule`, subscriptionId,
    })) })];
  return ['identity', 'tenant', 'activity'].map((step, index) => {
    const serverName = index ? 'management.azure.com' : 'graph.microsoft.com', sessionId = id(String(index + 3));
    const sent = Buffer.from(`GET ${targets[index]} HTTP/1.1\r\nHost: ${serverName}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nx-azure-proof-nonce: ${attempt.nonceMac}\r\nx-azure-proof-step: ${step}\r\nAuthorization: Bearer PRIVATE_${step}\r\n\r\n`);
    const recv = Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(bodies[index])}\r\n\r\n${bodies[index]}`);
    return { meta: { sessionId, serverName, step, proofId: attempt.proofId, nonceMac: attempt.nonceMac }, sent, recv };
  });
}

export function syntheticAzureWitnesses(attempt, options) {
  return syntheticAzureSources(attempt, options).map(source => {
    const { meta, sent, recv } = options?.transformSource ? options.transformSource(source) : source;
    const planned = planAzureSession(meta, { sent, recv }, attempt), openings = { sent: [], recv: [] }, results = [], transcript = {};
    for (const direction of ['sent', 'recv']) {
      const bytes = direction === 'sent' ? sent : recv, redacted = Buffer.from(bytes);
      for (const range of planned.selections[direction]) {
        let value;
        if (range.handler.action.kind === 'HASH') {
          const blinder = randomBytes(16), hash = createHash('sha256').update(bytes.subarray(range.start, range.end)).update(blinder).digest();
          openings[direction].push({ start: range.start, end: range.end, hash: Uint8Array.from(hash), blinder: Uint8Array.from(blinder) });
          value = hash.toString('hex'); redacted.fill(0, range.start, range.end);
        } else value = bytes.subarray(range.start, range.end).toString();
        results.push({ ...range.handler, value });
      }
      transcript[direction] = redacted.toString(); transcript[`${direction}_length`] = bytes.length;
    }
    return { ...meta, sent, recv, selections: planned.selections, openings,
      syntheticReceipt: { server_name: meta.serverName, session: { id: meta.sessionId, proofId: attempt.proofId,
        pluginSha256: attempt.pluginSha256, nonceMac: attempt.nonceMac, method: 'AZURE_WORK_PRIVATE', mode: 'Proxy', step: meta.step },
      config: planned.selections, results, transcript } };
  });
}
