import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const manifest = JSON.parse(readFileSync(new URL('./generated/artifacts.json', import.meta.url)));
export const proofOptions = Object.freeze({ verifierTarget: 'noir-recursive' });
assert.equal(manifest.verifierTarget, proofOptions.verifierTarget);

function readPinned(id, kind) {
  assert.ok(Object.hasOwn(manifest.circuits, id), 'Unknown pinned Azure circuit');
  const pin = manifest.circuits[id];
  const [file, digest, extension] = kind === 'key' ? [pin.keyFile, pin.keySha256, 'key'] : [pin.artifactFile, pin.sha256, 'json'];
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.equal(file, `${id}-${digest}.${extension}`);
  const bytes = readFileSync(new URL(`./dist/${file}`, import.meta.url));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), digest, 'Artifact pin mismatch');
  return bytes;
}

// The application ships these pins; proof submissions cannot select artifacts or keys.
export const verificationKey = id => new Uint8Array(readPinned(id, 'key'));
export const artifact = id => ({ circuit: JSON.parse(readPinned(id, 'circuit')), verificationKey: verificationKey(id) });
