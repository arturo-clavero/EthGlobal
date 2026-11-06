import artifacts from './generated/artifacts.json' with { type: 'json' };
import manifest from './generated/verification-keys.json' with { type: 'json' };
import packageInfo from './package.json' with { type: 'json' };

const registries = new WeakMap();
const fail = () => { throw new Error('GCP_PRIVATE_VERIFICATION_KEY_INVALID'); };

/** Only packaged application keys can enter this registry; request data cannot replace its pins. */
export async function loadPinnedVerificationKeys(loadBytes) {
  if (manifest.backend !== packageInfo.dependencies['@aztec/bb.js'] ||
      manifest.compiler !== artifacts.compiler || manifest.verifierTarget !== 'noir-recursive' ||
      artifacts.verifierTarget !== manifest.verifierTarget ||
      Object.keys(manifest.circuits).sort().join(',') !== Object.keys(artifacts.circuits).sort().join(',')) fail();
  const keys = new Map();
  for (const [id, artifact] of Object.entries(artifacts.circuits)) {
    const pin = manifest.circuits[id];
    if (pin.artifactSha256 !== artifact.sha256 || !/^[a-f0-9]{64}$/.test(pin.sha256) ||
        pin.file !== `${id}-${pin.sha256}.vk` || !Number.isSafeInteger(pin.bytes) || pin.bytes < 1 || pin.bytes > 65536) fail();
    const bytes = await loadBytes(pin.file);
    if (!(bytes instanceof Uint8Array) || bytes.length !== pin.bytes) fail();
    // Own the bytes before hashing so a loader cannot change them after validation.
    const key = Uint8Array.from(bytes);
    const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', key))]
      .map(value => value.toString(16).padStart(2, '0')).join('');
    if (hash !== pin.sha256) fail();
    keys.set(id, key);
  }
  const registry = Object.freeze({});
  registries.set(registry, keys);
  return registry;
}

export function pinnedVerificationKey(registry, circuitId) {
  const key = registries.get(registry)?.get(circuitId);
  if (!key) fail();
  return key.slice();
}
