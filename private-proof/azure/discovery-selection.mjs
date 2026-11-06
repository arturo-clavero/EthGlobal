import { validateAzureAttempt } from './browser-result.mjs';

export function validateAzureDiscoverySelection(value, attempt) {
  const valid = validateAzureAttempt(attempt);
  const keys = ['proofId', 'nonceMac', 'cutoffMs', 'graph', 'arm', 'subscription', 'correlation'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || Reflect.ownKeys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key)) || value.proofId !== valid.proofId ||
      value.nonceMac !== valid.nonceMac || value.cutoffMs !== valid.cutoffMs ||
      !['graph', 'arm'].every(key => typeof value[key] === 'string' && value[key].length <= 12000 && /^Bearer [A-Za-z0-9._~+/-]+=*$/.test(value[key])) ||
      !['subscription', 'correlation'].every(key => typeof value[key] === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value[key]))) {
    throw new Error('AZURE_DISCOVERY_UNAVAILABLE');
  }
  return Object.fromEntries(keys.map(key => [key, value[key]]));
}
