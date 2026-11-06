import type { sanitizeAzurePrivateResult } from '../../src/azure-private/browser-result.mjs';

// Closed-schema fixtures only: these bytes are not cryptographic proofs or authenticated sources.
export const azureCatalogClaims = [
  'AZURE_NSG_RULE_OPERATION',
  'AZURE_NSG_OPERATION',
  'AZURE_VM_WRITE',
  'AZURE_WEB_APP_WRITE',
  'AZURE_AKS_CLUSTER_WRITE',
  'AZURE_VIRTUAL_NETWORK_WRITE',
  'AZURE_STORAGE_ACCOUNT_WRITE',
  'AZURE_KEY_VAULT_WRITE',
  'AZURE_METRIC_ALERT_WRITE',
  'AZURE_SQL_DATABASE_WRITE',
  'AZURE_DATA_PIPELINE_WRITE',
  'AZURE_RESOURCE_GROUP_OPERATION',
  'AZURE_DEPLOYMENT_WRITE',
  'AZURE_ROLE_ASSIGNMENT_WRITE',
  'AZURE_WEB_SLOT_SWAP',
] as const;
export function azureCatalogResult(claim: typeof azureCatalogClaims[number] = azureCatalogClaims[0]): ReturnType<typeof sanitizeAzurePrivateResult> {
  const code = azureCatalogClaims.indexOf(claim), hash = 'a'.repeat(64);
  const publicInputs = Array<string>(code === 0 ? 715 : 716).fill('0');
  if (code !== 0) publicInputs[715] = String(code);
  return { kind: 'AZURE_PRIVATE_RESULT', version: 1, claim,
    sessionIds: ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222', '33333333-3333-4333-8333-333333333333'],
    bindings: { graphActorHash: hash, identityBinding: hash, selectedRow: 0,
      claims: [{ stateHashes: [hash, hash], identityHashes: [hash, hash] }] },
    proofs: [{ circuitId: code === 0 ? 'activity-atoms-v1' : 'catalog-activity-atoms-v1', proof: 'AQID', publicInputs }] };
}
