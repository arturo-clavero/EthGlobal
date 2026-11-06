import pins from './generated/pins.json' with { type: 'json' };
import packageInfo from '../gcp/package.json' with { type: 'json' };

const registries = new WeakMap();
const fail = () => { throw new Error('AWS_PRIVATE_ARTIFACT_INVALID'); };
const IDS = ['atom-v1', 'aws-escaped-atom-v1', 'aws-escaped-atoms-small-v1', 'aws-escaped-atom-small-v1', 'aws-event-link-v1',
  'aws-identity-link-v1', 'aws-xml-text-v1', 'atoms-small-v1', 'header-v1', 'headers-small-v1'].sort();
function metadata() {
  if (pins.compiler !== '1.0.0-beta.19+74d6be658e1ad252f87943292ba09bdd4da80bd4' ||
      pins.backend !== packageInfo.dependencies['@aztec/bb.js'] || pins.verifierTarget !== 'noir-recursive' ||
      Object.keys(pins.circuits).sort().join(',') !== IDS.join(',')) fail();
}
async function checked(loadBytes, file, digest, length, limit) {
  if (!/^[a-f0-9]{64}$/.test(digest) || !Number.isSafeInteger(length) || length < 1 || length > limit) fail();
  const source = await loadBytes(file);
  if (!(source instanceof Uint8Array) || source.length !== length) fail();
  const bytes = Uint8Array.from(source);
  const actual = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(n => n.toString(16).padStart(2, '0')).join('');
  if (actual !== digest) fail();
  return bytes;
}

/** Load only packaged files through application code; wire data cannot supply pins or paths. */
export async function loadAwsArtifacts(loadBytes) {
  metadata();
  const artifacts = {};
  for (const [id, pin] of Object.entries(pins.circuits)) {
    if (pin.file !== `${id}-${pin.sha256}.json`) fail();
    const bytes = await checked(loadBytes, pin.file, pin.sha256, pin.bytes, 10000000);
    const artifact = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (artifact.noir_version !== pins.compiler || !artifact.abi || !artifact.bytecode) fail();
    artifacts[id] = artifact;
  }
  return artifacts;
}

export async function loadAwsVerificationKeys(loadBytes) {
  metadata();
  const keys = new Map();
  for (const [id, pin] of Object.entries(pins.circuits)) {
    if (pin.keyFile !== `${id}-${pin.keySha256}.vk`) fail();
    keys.set(id, await checked(loadBytes, pin.keyFile, pin.keySha256, pin.keyBytes, 65536));
  }
  const registry = Object.freeze({}); registries.set(registry, keys); return registry;
}

export function pinnedAwsKey(registry, id) {
  const key = registries.get(registry)?.get(id);
  if (!key) fail();
  return key.slice();
}
