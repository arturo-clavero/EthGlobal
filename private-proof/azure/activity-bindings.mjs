import { AZURE_ACTIVITY_PROFILES } from './browser-result.mjs';
import { claimsProofExpectations } from './claims-bindings.mjs';

const fail = () => { throw new Error('AZURE_PRIVATE_ACTIVITY_BINDINGS_INVALID'); };
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const digest = value => {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail();
  return Array.from({ length: 32 }, (_, i) => parseInt(value.slice(i * 2, i * 2 + 2), 16));
};
const field = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
const proof = (circuitId, hashes, suffix = []) => ({ circuitId,
  publicInputs: [...hashes.flatMap(digest), ...suffix].map(field) });

/** Source-derived header obligations; shared by client and server, including identity. */
export function headerProofExpectations(headers) {
  if (!Array.isArray(headers)) fail();
  for (const header of headers) {
    if (header?.circuitId !== 'header-v1' || !Number.isInteger(header.length) || header.length < 1 || header.length > 2048) fail();
  }
  const proofs = [], small = headers.filter(header => header.length <= 64);
  for (let start = 0; start < small.length; start += 16) {
    const batch = small.slice(start, start + 16);
    while (batch.length < 16) batch.push({ hash: '0'.repeat(64), length: 0 });
    proofs.push(proof('headers-small-v1', batch.map(header => header.hash), batch.map(header => header.length)));
  }
  for (const header of headers.filter(header => header.length > 64)) proofs.push(proof('header-v1', [header.hash], [header.length]));
  return proofs;
}

/** tenant/activity must be fresh inspectTenantReceipt/inspectActivityReceipt outputs from trusted
 * native receipts. Context is server-owned. Bindings are untrusted commitments, never identities.
 * This composes obligations only: identity acceptance and ARG coverage remain separate requirements.
 */
export function activityProofExpectations(tenant, activity, context, bindings, claim) {
  try {
    if (typeof claim !== 'string' || !Object.hasOwn(AZURE_ACTIVITY_PROFILES, claim)) fail();
    const profile = AZURE_ACTIVITY_PROFILES[claim];
    if (!exact(bindings, ['graphActorHash', 'identityBinding', 'selectedRow', 'claims']) ||
        !Number.isSafeInteger(context.cutoffMs) || context.cutoffMs < 0 || context.cutoffMs > 8640000000000000 ||
        !Array.isArray(activity.body.rows) || activity.body.rows.length < 1 || activity.body.rows.length > 8 ||
        !Number.isInteger(bindings.selectedRow) || bindings.selectedRow < 0 || bindings.selectedRow >= activity.body.rows.length ||
        !Array.isArray(bindings.claims) || bindings.claims.length !== activity.body.rows.length) fail();
    const proofs = [];
    for (const inspection of [tenant, activity]) {
      proofs.push(...headerProofExpectations(inspection.headerObligations));
      for (const link of inspection.requestUuidObligations) {
        if (link.predicate !== 'request-uuid') fail();
        proofs.push(proof('request-uuid-v1', [link.request.hash, link.reference.hash]));
      }
      const atoms = inspection.atomObligations ?? [];
      if (!Array.isArray(atoms) || atoms.some(atom => atom.circuitId !== 'atom-v1' || atom.kind !== 1 ||
          !Number.isInteger(atom.length) || atom.length < 2 || atom.length > 512)) fail();
      const small = atoms.filter(atom => atom.length <= 64);
      for (let start = 0; start < small.length; start += 8) {
        const batch = small.slice(start, start + 8);
        while (batch.length < 8) batch.push({ hash: '0'.repeat(64), length: 0, kind: 0 });
        proofs.push(proof('atoms-small-v1', batch.map(atom => atom.hash),
          [...batch.map(atom => atom.length), ...batch.map(atom => atom.kind)]));
      }
      for (const atom of atoms.filter(atom => atom.length > 64)) proofs.push(proof('atom-v1', [atom.hash], [atom.length, atom.kind]));
      for (const extra of inspection.extraObligations ?? []) {
        if (extra.name !== 'tenant-extra-v1' || inspection !== tenant ||
            !Number.isInteger(extra.key.length) || extra.key.length < 3 || extra.key.length > 64 ||
            !Number.isInteger(extra.object.length) || extra.object.length < 2 || extra.object.length > 128) fail();
        proofs.push(proof('tenant-extra-v1', [extra.key.hash, extra.object.hash], [extra.key.length, extra.object.length]));
      }
    }
    proofs.push(proof('subscription-state-v1', [tenant.body.state.hash]));
    proofs.push(proof('identity-link-v1', [bindings.graphActorHash, context.challenge, bindings.identityBinding]));
    const rows = activity.body.rows.map((row, index) => {
      const claim = bindings.claims[index];
      if (!exact(claim, ['stateHashes', 'identityHashes'])) fail();
      const claims = claimsProofExpectations(row.claims, claim.stateHashes, claim.identityHashes);
      proofs.push(...claims.proofs);
      const { actorHash, tenantHash } = claims.references;
      const hashes = [actorHash, tenantHash, row.subscription.hash, row.eventId.hash, row.operationId.hash,
        row.correlationId.hash, row.event.hash, row.operation.hash, row.status.hash, row.timestamp.hash, row.resource.hash];
      const lengths = ['event', 'operation', 'status', 'timestamp', 'resource'].map(key => row[key].length);
      if (!lengths.every(Number.isSafeInteger)) fail();
      return { hashes, lengths, actorHash, tenantHash };
    });
    const selected = rows[bindings.selectedRow], selectedSource = activity.body.rows[bindings.selectedRow];
    proofs.push(proof('scope-link-v1', [bindings.graphActorHash, selected.actorHash,
      tenant.body.tenant.hash, selected.tenantHash, tenant.body.subscription.hash, selectedSource.subscription.hash]));
    for (const row of rows) proofs.push(proof(profile.circuitId, [...selected.hashes, ...row.hashes],
      [...selected.lengths, ...row.lengths, context.cutoffMs, ...(profile.code === undefined ? [] : [profile.code])]));
    return { proofs, references: { identityBinding: bindings.identityBinding, selectedRow: bindings.selectedRow,
      resource: selectedSource.resource, correlationId: selectedSource.correlationId, cutoffMs: context.cutoffMs } };
  } catch { fail(); }
}
