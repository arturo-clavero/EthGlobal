import { Barretenberg, BackendType, UltraHonkBackend, UltraHonkVerifierBackend } from '@aztec/bb.js';

const OPTIONS = Object.freeze({ verifierTarget: 'noir-recursive' });
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
export function proofRuntimeFactory({ ids, invalidCode, provingCode, keyForCircuit, threads }) {
  const IDS = new Set(ids);
  const fail = () => { throw new Error(invalidCode); };

  function fields(values, stringsOnly = false) {
    if (!Array.isArray(values) || !values.length || values.length > 1024) fail();
    return Array.from(values, value => {
      if (stringsOnly && typeof value !== 'string') fail();
      if (typeof value === 'number') { if (!Number.isSafeInteger(value)) fail(); }
      else if (typeof value === 'string') {
        if (!/^(?:0x[0-9a-f]{1,64}|0|[1-9][0-9]{0,19})$/.test(value)) fail();
      } else if (typeof value !== 'bigint') fail();
      const number = BigInt(value);
      // Every public field in these circuits is a byte, boolean, u32 or u64.
      if (number < 0n || number > 0xffffffffffffffffn) fail();
      return `0x${number.toString(16).padStart(64, '0')}`;
    });
  }

  function encode(bytes) { return btoa(String.fromCharCode(...bytes)); }
  function decode(value) {
    if (typeof value !== 'string' || !value.length || value.length > 32768 || !BASE64.test(value)) fail();
    const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
    if (encode(bytes) !== value) fail();
    return bytes;
  }

  /**
   * `artifacts` is the application-pinned registry, never request data or a caller's
   * verification key. Run inside one dedicated worker; terminate it on cancellation.
   * Operations are serial to bound memory. Prover witnesses never leave this worker.
   */
  return async function createProofRuntime(artifacts, pinnedKeys) {
    const registry = new Map(Object.entries(artifacts));
    if (!registry.size || [...registry].some(([id, artifact]) => !IDS.has(id) || !artifact?.bytecode || !artifact?.abi)) fail();
    const keys = new Map();
    if (pinnedKeys !== undefined)
      for (const id of registry.keys()) keys.set(id, keyForCircuit(pinnedKeys, id));
    const api = await Barretenberg.new({ backend: BackendType.Wasm, threads, memory: { maximum: 32768 } });
    const verifier = new UltraHonkVerifierBackend(api);
    const backends = new Map(), noirs = new Map();
    let busy = false, closed = false;
    const backend = id => {
      if (!registry.has(id)) fail();
      if (!backends.has(id)) backends.set(id, new UltraHonkBackend(registry.get(id).bytecode, api));
      return backends.get(id);
    };
    async function serial(operation) {
      if (closed || busy) fail();
      busy = true;
      try { return await operation(); }
      finally { busy = false; }
    }
    return {
      async prove(circuitId, inputs) {
        return serial(async () => {
          try {
            const prover = backend(circuitId);
            if (!noirs.has(circuitId)) {
              const { Noir } = await import('@noir-lang/noir_js');
              noirs.set(circuitId, new Noir(registry.get(circuitId)));
            }
            const { witness } = await noirs.get(circuitId).execute(inputs);
            try {
              const result = await prover.generateProof(witness, OPTIONS);
              const proof = encode(result.proof);
              if (proof.length > 32768) fail();
              return { circuitId, proof, publicInputs: fields(result.publicInputs, true) };
            } finally { witness.fill(0); }
          } catch { throw new Error(provingCode); }
        });
      },
      /** expectedFields must be independently derived from authenticated receipts and server policy. */
      async verify(entry, expectedFields) {
        return serial(async () => {
          try {
            if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
                Reflect.ownKeys(entry).length !== 3 || !['circuitId', 'proof', 'publicInputs'].every(key => Object.hasOwn(entry, key))) return false;
            if (!registry.has(entry.circuitId)) return false;
            const actual = fields(entry.publicInputs, true), expected = fields(expectedFields);
            if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) return false;
            const proof = decode(entry.proof);
            if (!keys.has(entry.circuitId)) keys.set(entry.circuitId, await backend(entry.circuitId).getVerificationKey(OPTIONS));
            return await verifier.verifyProof({ proof, publicInputs: expected, verificationKey: keys.get(entry.circuitId) }, OPTIONS);
          } catch { return false; }
        });
      },
      async close() {
        if (busy) fail();
        if (!closed) { closed = true; await api.destroy(); }
        backends.clear(); noirs.clear(); keys.clear(); registry.clear();
      },
    };
  };
}
