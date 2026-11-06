import manifest from './generated/artifacts.json' with { type: 'json' };

/** loadBytes reads packaged application files only; no request can supply a path or artifact. */
export async function loadPinnedArtifacts(loadBytes) {
  const registry = {};
  for (const [id, pin] of Object.entries(manifest.circuits)) {
    const bytes = await loadBytes(pin.file);
    if (!(bytes instanceof Uint8Array) || bytes.length !== pin.bytes || bytes.length > 10000000)
      throw new Error('GCP_PRIVATE_ARTIFACT_INVALID');
    const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
      .map(value => value.toString(16).padStart(2, '0')).join('');
    if (hash !== pin.sha256) throw new Error('GCP_PRIVATE_ARTIFACT_INVALID');
    const artifact = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (artifact.noir_version !== manifest.compiler || !artifact.abi || !artifact.bytecode)
      throw new Error('GCP_PRIVATE_ARTIFACT_INVALID');
    registry[id] = artifact;
  }
  return registry;
}
