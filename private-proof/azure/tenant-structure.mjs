import { parseJsonStructure } from '../gcp/json-structure.mjs';

const fail = () => { throw new Error('AZURE_PRIVATE_TENANT_STRUCTURE_INVALID'); };

// Every returned reference still requires authenticated source binding and the stated semantic proof.
export function inspectTenantBody(bytes, privateSlots) {
  try {
    const parsed = parseJsonStructure(bytes, privateSlots, true), root = parsed.root;
    if (root.type !== 'object' || root.privateSlot !== undefined) fail();
    const privateEntries = root.entries.filter(entry => entry.key.privateSlot !== undefined);
    const entries = new Map(root.entries.filter(entry => entry.key.privateSlot === undefined).map(entry => [entry.key.value, entry.value]));
    const known = ['subscriptionId', 'tenantId', 'state', 'id', 'displayName', 'authorizationSource', 'subscriptionPolicies', 'managedByTenants'];
    if (![3, 8].includes(entries.size) || [...entries.keys()].some(key => !known.includes(key)) || privateEntries.length > 1) fail();
    if (!['subscriptionId', 'tenantId', 'state'].every(key => entries.has(key))) fail();
    const used = new Set();
    const slot = (node, kind, maximum, exact, requiredPredicate) => {
      if (!Number.isInteger(node?.privateSlot) || node.kind !== kind || used.has(node.privateSlot)) fail();
      used.add(node.privateSlot);
      const value = parsed.slots[node.privateSlot];
      const length = value.end - value.start;
      if (length > maximum || (exact !== undefined && length !== exact)) fail();
      return { ...value, length, ...(requiredPredicate ? { requiredPredicate } : {}) };
    };
    const result = {
      subscription: slot(entries.get('subscriptionId'), 1, 38, 38, 'quoted-uuid'),
      tenant: slot(entries.get('tenantId'), 1, 38, 38, 'quoted-uuid'),
      state: slot(entries.get('state'), 1, 9, 9, 'subscription-enabled'),
      atomObligations: [], extraObligations: [],
    };
    if (entries.size === 8) {
      for (const name of ['id', 'displayName', 'authorizationSource']) result.atomObligations.push(slot(entries.get(name), 1, 512));
      const policies = entries.get('subscriptionPolicies'), tenants = entries.get('managedByTenants');
      if (policies.type !== 'object' || policies.privateSlot !== undefined || policies.hasPrivateKeys || policies.entries.length !== 3 ||
          tenants.type !== 'array' || tenants.items.length !== 0) fail();
      const values = new Map(policies.entries.map(entry => [entry.key.value, entry.value]));
      for (const name of ['locationPlacementId', 'quotaId', 'spendingLimit']) result.atomObligations.push(slot(values.get(name), 1, 512));
    }
    if (privateEntries.length) {
      if (entries.size !== 8) fail();
      const entry = privateEntries[0];
      if (entry.value.type !== 'array' || entry.value.items.length !== 1) fail();
      result.extraObligations.push({ name: 'tenant-extra-v1', key: slot(entry.key, 1, 64), object: slot(entry.value.items[0], 6, 128) });
    }
    if (used.size !== parsed.slots.length) fail();
    return result;
  } catch { fail(); }
}
