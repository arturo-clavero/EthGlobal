import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { loadAzureCircuit } from './browser-artifacts.mjs';

globalThis.crypto ??= webcrypto;
const packaged = async file => new Uint8Array(await readFile(new URL(`./dist/${file}`, import.meta.url)));
test('browser artifact loader uses packaged circuit and independently pinned verification key', async () => {
  const loaded = await loadAzureCircuit('identity-link-v1', packaged);
  assert.equal(loaded.circuit.noir_version, '1.0.0-beta.19+74d6be658e1ad252f87943292ba09bdd4da80bd4');
  assert.ok(loaded.verificationKey.length > 0);
});
test('browser artifact loader rejects unknown IDs before consulting loader', async () => {
  let called = false;
  await assert.rejects(loadAzureCircuit('../../caller-key', async () => { called = true; return new Uint8Array(); }));
  assert.equal(called, false);
});
test('browser artifact loader rejects substituted packaged bytes', async () => {
  await assert.rejects(loadAzureCircuit('identity-link-v1', async file => {
    const bytes = await packaged(file); bytes[0] ^= 1; return bytes;
  }));
});
