import manifest from './generated/artifacts.json' with { type: 'json' };

const fail = () => { throw new Error('AZURE_PRIVATE_ARTIFACT_INVALID'); };
const hex = bytes => Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
export const azureProofOptions = Object.freeze({ verifierTarget: 'noir-recursive' });

/** Pins come only from the compiled package, never worker messages or page data. */
export async function loadAzureCircuit(id, loadBytes) {
  if (manifest.compiler !== '1.0.0-beta.19+74d6be658e1ad252f87943292ba09bdd4da80bd4' ||
      manifest.verifierTarget !== azureProofOptions.verifierTarget || typeof id !== 'string' ||
      !Object.hasOwn(manifest.circuits, id) || typeof loadBytes !== 'function') fail();
  const pin = manifest.circuits[id];
  const checked = async (file, digest, extension, maximum) => {
    if (typeof digest !== 'string' || !/^[a-f0-9]{64}$/.test(digest) || file !== `${id}-${digest}.${extension}`) fail();
    const bytes = await loadBytes(file);
    if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > maximum ||
        hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))) !== digest) fail();
    return bytes;
  };
  const bytes = await checked(pin.artifactFile, pin.sha256, 'json', 10000000);
  const circuit = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (circuit.noir_version !== manifest.compiler || typeof circuit.bytecode !== 'string' || !circuit.bytecode || !circuit.abi) fail();
  const verificationKey = await checked(pin.keyFile, pin.keySha256, 'key', 65536);
  return { circuit, verificationKey };
}
