const fail = () => { throw new Error('AZURE_PRIVATE_BUNDLE_INVALID'); };
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
export const AZURE_ACTIVITY_PROFILES = Object.freeze({
  AZURE_NSG_RULE_OPERATION: Object.freeze({ circuitId: 'activity-atoms-v1', operations: Object.freeze([
    'Microsoft.Network/networkSecurityGroups/securityRules/write', 'Microsoft.Network/networkSecurityGroups/securityRules/delete',
  ]) }),
  AZURE_NSG_OPERATION: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 1, operations: Object.freeze(['Microsoft.Network/networkSecurityGroups/write', 'Microsoft.Network/networkSecurityGroups/delete']) }),
  AZURE_VM_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 2, operations: Object.freeze(['Microsoft.Compute/virtualMachines/write']) }),
  AZURE_WEB_APP_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 3, operations: Object.freeze(['Microsoft.Web/sites/write']) }),
  AZURE_AKS_CLUSTER_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 4, operations: Object.freeze(['Microsoft.ContainerService/managedClusters/write']) }),
  AZURE_VIRTUAL_NETWORK_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 5, operations: Object.freeze(['Microsoft.Network/virtualNetworks/write']) }),
  AZURE_STORAGE_ACCOUNT_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 6, operations: Object.freeze(['Microsoft.Storage/storageAccounts/write']) }),
  AZURE_KEY_VAULT_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 7, operations: Object.freeze(['Microsoft.KeyVault/vaults/write']) }),
  AZURE_METRIC_ALERT_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 8, operations: Object.freeze(['Microsoft.Insights/metricAlerts/write']) }),
  AZURE_SQL_DATABASE_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 9, operations: Object.freeze(["Microsoft.Sql/servers/databases/write"]) }),
  AZURE_DATA_PIPELINE_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 10, operations: Object.freeze(["Microsoft.DataFactory/factories/pipelines/write"]) }),
  AZURE_RESOURCE_GROUP_OPERATION: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 11, operations: Object.freeze(["Microsoft.Resources/subscriptions/resourceGroups/write", "Microsoft.Resources/subscriptions/resourceGroups/delete"]) }),
  AZURE_DEPLOYMENT_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 12, operations: Object.freeze(["Microsoft.Resources/deployments/write"]) }),
  AZURE_ROLE_ASSIGNMENT_WRITE: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 13, operations: Object.freeze(["Microsoft.Authorization/roleAssignments/write"]) }),
  AZURE_WEB_SLOT_SWAP: Object.freeze({ circuitId: 'catalog-activity-atoms-v1', code: 14, operations: Object.freeze(['Microsoft.Web/sites/slots/slotsswap/action']) }),
});

const COUNTS = Object.freeze({ 'identity-v1': 97, 'header-v1': 33, 'identity-link-v1': 96,
  'scope-link-v1': 192, 'activity-atoms-v1': 715, 'catalog-activity-atoms-v1': 716, 'claims-chunk-v1': 163, 'request-uuid-v1': 64,
  'subscription-state-v1': 32, 'atom-v1': 34, 'atoms-small-v1': 272, 'headers-small-v1': 528, 'tenant-extra-v1': 66 });

export function validateAzureAttempt(value, now = Date.now()) {
  if (!exact(value, ['proofId', 'pluginSha256', 'nonceMac', 'challenge', 'cutoffMs', 'issuedAt', 'expiresAt']) ||
      typeof value.proofId !== 'string' || !UUID.test(value.proofId) ||
      typeof value.pluginSha256 !== 'string' || !HASH.test(value.pluginSha256) ||
      typeof value.challenge !== 'string' || !HASH.test(value.challenge) ||
      typeof value.nonceMac !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.nonceMac) ||
      ![value.cutoffMs, value.issuedAt, value.expiresAt, now].every(Number.isSafeInteger) ||
      value.issuedAt < 0 || value.cutoffMs !== value.issuedAt || value.issuedAt > now ||
      value.expiresAt <= now || value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > 3600000) fail();
  return Object.freeze({ ...value });
}

/** Closed public schema only; this function does not authenticate sources or verify proofs. */
export function azureProofFields(entry) {
  if (!exact(entry, ['circuitId', 'proof', 'publicInputs']) || !Object.hasOwn(COUNTS, entry.circuitId) ||
      typeof entry.proof !== 'string' || !entry.proof.length || entry.proof.length > 32768 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(entry.proof) ||
      btoa(atob(entry.proof)) !== entry.proof || !Array.isArray(entry.publicInputs) ||
      entry.publicInputs.length !== COUNTS[entry.circuitId]) fail();
  return Array.from(entry.publicInputs, value => {
    if (typeof value !== 'string' || !/^(?:0x[0-9a-f]{1,64}|0|[1-9][0-9]{0,19})$/.test(value)) fail();
    const number = BigInt(value);
    if (number > 0xffffffffffffffffn) fail();
    return number;
  });
}

export function sanitizeAzurePrivateResult(value) {
  if (!exact(value, ['kind', 'version', 'claim', 'sessionIds', 'bindings', 'proofs']) ||
      value.kind !== 'AZURE_PRIVATE_RESULT' || value.version !== 1 || typeof value.claim !== 'string' || !Object.hasOwn(AZURE_ACTIVITY_PROFILES, value.claim) ||
      !Array.isArray(value.sessionIds) || value.sessionIds.length !== 3 ||
      Array.from(value.sessionIds).some(id => typeof id !== 'string' || !UUID.test(id)) ||
      new Set(value.sessionIds.map(id => id.toLowerCase())).size !== 3 ||
      !Array.isArray(value.proofs) || !value.proofs.length || value.proofs.length > 128) fail();
  const b = value.bindings;
  if (!exact(b, ['graphActorHash', 'identityBinding', 'selectedRow', 'claims']) ||
      typeof b.graphActorHash !== 'string' || !HASH.test(b.graphActorHash) ||
      typeof b.identityBinding !== 'string' || !HASH.test(b.identityBinding) ||
      !Array.isArray(b.claims) || !b.claims.length || b.claims.length > 8 ||
      !Number.isInteger(b.selectedRow) || b.selectedRow < 0 || b.selectedRow >= b.claims.length) fail();
  const claims = Array.from(b.claims, entry => {
    if (!exact(entry, ['stateHashes', 'identityHashes']) || !Array.isArray(entry.stateHashes) ||
        entry.stateHashes.length < 2 || entry.stateHashes.length > 6 || !Array.isArray(entry.identityHashes) ||
        entry.identityHashes.length !== 2 || Array.from([...entry.stateHashes, ...entry.identityHashes])
          .some(hash => typeof hash !== 'string' || !HASH.test(hash))) fail();
    return { stateHashes: [...entry.stateHashes], identityHashes: [...entry.identityHashes] };
  });
  const proofs = Array.from(value.proofs, entry => {
    azureProofFields(entry);
    return { circuitId: entry.circuitId, proof: entry.proof, publicInputs: [...entry.publicInputs] };
  });
  const result = { kind: 'AZURE_PRIVATE_RESULT', version: 1, claim: value.claim, sessionIds: [...value.sessionIds],
    bindings: { graphActorHash: b.graphActorHash, identityBinding: b.identityBinding, selectedRow: b.selectedRow, claims }, proofs };
  if (JSON.stringify(result).length > 4 * 1024 * 1024) fail();
  return result;
}

/** Own inputs before calling this; never erase a caller's transcript buffer implicitly. */
export function eraseAzureInputs(value) {
  const pending = [value], seen = new Set();
  while (pending.length) {
    const item = pending.pop();
    if (!item || typeof item !== 'object' || seen.has(item)) continue;
    seen.add(item);
    if (ArrayBuffer.isView(item) && typeof item.fill === 'function') { item.fill(0); continue; }
    for (const key of Object.keys(item)) {
      const child = item[key];
      if (child && typeof child === 'object') pending.push(child);
      else if (typeof child === 'string') item[key] = '';
      else if (typeof child === 'number' || typeof child === 'bigint') item[key] = 0;
      else if (typeof child === 'boolean') item[key] = false;
    }
  }
}
