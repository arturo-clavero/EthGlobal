export type GcpPrivateCircuitId = 'header-v1' | 'atom-v1' | 'headers-small-v1' | 'atoms-small-v1' | 'timestamps-v1' | 'identity-scope-v1' | 'query-scope-v1';
export interface GcpPrivateProof {
  circuitId: GcpPrivateCircuitId;
  proof: string;
  publicInputs: string[];
}

const CIRCUIT_IDS: readonly GcpPrivateCircuitId[] = ['header-v1', 'atom-v1', 'headers-small-v1', 'atoms-small-v1', 'timestamps-v1', 'identity-scope-v1', 'query-scope-v1'];
function fail(): never { throw new Error('GCP_PRIVATE_PROOF_INVALID'); }
function exactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && actual.every(key => typeof key === 'string' && keys.includes(key));
}
export function proofBundle(value: unknown): GcpPrivateProof[] {
  if (!exactKeys(value, ['proofs'])) fail();
  const proofs = value.proofs;
  if (!Array.isArray(proofs) || !proofs.length || proofs.length > 128) fail();
  // Array.from visits holes, so sparse bundles cannot bypass element validation.
  return Array.from(proofs, item => {
    if (!exactKeys(item, ['circuitId', 'proof', 'publicInputs'])) fail();
    const { circuitId, proof, publicInputs: inputs } = item;
    if (typeof circuitId !== 'string' || !CIRCUIT_IDS.includes(circuitId as GcpPrivateCircuitId) ||
        typeof proof !== 'string' || !proof.length || proof.length > 32768 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(proof) ||
        !Array.isArray(inputs) || !inputs.length || inputs.length > 1024) fail();
    const publicInputs = Array.from(inputs, input => {
      if (typeof input !== 'string' || !/^(?:0x[0-9a-f]{1,64}|[0-9]{1,78})$/.test(input)) fail();
      return input;
    });
    // Verification keys stay in the verifier registry; this envelope accepts no supplied key.
    return { circuitId: circuitId as GcpPrivateCircuitId, proof, publicInputs };
  });
}

export function sanitizeGcpPrivateResult(value: unknown) {
  if (!exactKeys(value, ['kind', 'version', 'proofs', 'sessionIds']) || value.kind !== 'GCP_PRIVATE_RESULT' || value.version !== 1 ||
      !Array.isArray(value.sessionIds) || value.sessionIds.length !== 6) fail();
  const sessionIds = Array.from(value.sessionIds, id => {
    if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) fail();
    return id;
  });
  if (new Set(sessionIds.map(id => id.toLowerCase())).size !== 6) fail();
  const result = { kind: 'GCP_PRIVATE_RESULT' as const, version: 1 as const, proofs: proofBundle({ proofs: value.proofs }), sessionIds };
  if (JSON.stringify(result).length > 4 * 1024 * 1024) fail();
  return result;
}
