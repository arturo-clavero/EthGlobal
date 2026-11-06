const fail = () => { throw new Error('AZURE_PRIVATE_CLAIMS_BINDINGS_INVALID'); };
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const digest = value => {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail();
  return Array.from({ length: 32 }, (_, i) => parseInt(value.slice(i * 2, i * 2 + 2), 16));
};
const field = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;

/** Descriptor ranges/hashes must come from authenticated native receipts and the Activity inspector.
 * Carries and identities are provisional commitments: verify every returned expectation with pinned
 * keys, then bind references to the identity/scope/Activity proofs. This function verifies no proof.
 */
export function claimsProofExpectations(claimsDescriptor, stateHashes, identityHashes) {
  if (!exact(claimsDescriptor, ['start', 'end', 'length', 'chunks'])) fail();
  const { start, end, length, chunks } = claimsDescriptor;
  if (![start, end, length].every(Number.isSafeInteger) || start < 0 || end > 16384 ||
      length < 2 || length > 2304 || end - start !== length ||
      !Array.isArray(chunks) || chunks.length !== Math.ceil(length / 512) ||
      !Array.isArray(stateHashes) || stateHashes.length !== chunks.length + 1 ||
      !Array.isArray(identityHashes) || identityHashes.length !== 2) fail();
  const states = [];
  for (const hash of stateHashes) states.push(digest(hash));
  const identities = [];
  for (const hash of identityHashes) identities.push(digest(hash));
  const proofs = [];
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i], offset = i * 512, chunkLength = Math.min(512, length - offset);
    if (!exact(chunk, ['start', 'end', 'kind', 'hash']) || chunk.kind !== 6 ||
        chunk.start !== start + offset || chunk.end !== start + offset + chunkLength) fail();
    const hashes = [digest(chunk.hash), states[i], states[i + 1], ...identities];
    proofs.push({ circuitId: 'claims-chunk-v1',
      publicInputs: [...hashes.flat(), chunkLength, offset, length].map(field) });
  }
  return { proofs, references: { actorHash: identityHashes[0], tenantHash: identityHashes[1] } };
}
