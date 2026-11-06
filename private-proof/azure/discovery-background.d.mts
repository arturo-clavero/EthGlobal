import type { AzureDiscoverySelection } from './discovery-selection.mjs';
export function createAzureDiscoveryBackground(browser: unknown): {
  handle(message: unknown, sender: unknown): Promise<unknown>;
  prepare(sender: unknown, attempt: unknown): Promise<AzureDiscoverySelection>;
  tabChanged(tabId: number, documentId?: string): void;
  tabRemoved(tabId: number): void;
};
