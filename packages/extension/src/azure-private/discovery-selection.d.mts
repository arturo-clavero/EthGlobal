export interface AzureDiscoverySelection {
  proofId: string; nonceMac: string; cutoffMs: number;
  graph: string; arm: string; subscription: string; correlation: string;
}
export function validateAzureDiscoverySelection(value: unknown, attempt: unknown): AzureDiscoverySelection;
