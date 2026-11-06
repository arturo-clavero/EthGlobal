import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { createPublicClient } from '@arkiv-network/sdk';
import { localhost } from '@arkiv-network/sdk/chains';
import { custom } from 'viem';
import { findAttestations, findBundle, PART_BYTES } from './read.mjs';
import { publishAttestation, publishBundle } from './write.mjs';

// The real SDK read client over an in-memory transport: no network, but real query building and row decoding.
function arkiv(entities) {
  const queries = [];
  const transport = custom({ async request({ method, params }) {
    if (method !== 'arkiv_query') throw new Error(`unexpected ${method}`);
    queries.push(params[0]);
    const offset = Number(params[1].offset ?? '0x0'), limit = Number(params[1].limit);
    return { data: entities.slice(offset, offset + limit), blockNumber: '0x1' };
  } });
  return { client: createPublicClient({ chain: localhost, transport }), queries };
}
const hex = text => `0x${Buffer.from(text).toString('hex')}`;
const entity = (schema, attributes, index) => ({ key: `0x${String(index).padStart(64, '0')}`,
  attributes: [{ name: 'arkiv.schema', type: 'str', value: schema },
    ...Object.entries(attributes).map(([name, [type, value]]) => ({ name, type, value }))] });

const commitment = 'a'.repeat(64);
const signed = { v: 1, type: 'tlsn-attestation', commitment, provider: 'example', claim: 'example:example-claim',
  proofHash: 'b'.repeat(64), issuedAt: '2026-11-06T00:00:00.000Z', expiresAt: '2027-05-01T00:00:00.000Z',
  verifierKeyId: 'c'.repeat(32), sig: 's'.repeat(86) };
const attestationEntity = (value, index, attrs = {}) => entity('tlsn-attestation', { type: ['str', 'tlsn-attestation'],
  commitment: ['str', value.commitment], provider: ['str', value.provider], claim: ['str', value.claim],
  verifierKeyId: ['str', value.verifierKeyId], payload: ['bytes', hex(JSON.stringify(value))], ...attrs }, index);

test('publishAttestation writes the coarse attributes and the signed payload with a bounded lifetime', async () => {
  const calls = [];
  const walletClient = { createEntity: async (...args) => { calls.push(args); return { entityKey: '0x01', txHash: '0x02', expiresAt: 1n }; } };
  assert.deepEqual(await publishAttestation(signed, { walletClient }), { entityKey: '0x01', txHash: '0x02' });
  const [schema, values, options] = calls[0];
  assert.equal(schema.name, 'tlsn-attestation');
  assert.deepEqual(Object.keys(values).sort(), ['claim', 'commitment', 'payload', 'provider', 'type', 'verifierKeyId']);
  assert.deepEqual(JSON.parse(Buffer.from(values.payload)), signed);
  assert.ok(options.expiration);
  await assert.rejects(publishAttestation(signed, { walletClient, expiresInSeconds: 400 * 86400 }), /expiresInSeconds/);
  await assert.rejects(publishAttestation({ ...signed, commitment: 'x' }, { walletClient }), /signed attestation/);
  await assert.rejects(publishAttestation(signed, { privateKey: 'nope' }), /privateKey/);
});

test('findAttestations queries by type and commitment and skips entities whose attributes disagree', async () => {
  const forged = { ...signed, commitment: 'd'.repeat(64) };
  const { client, queries } = arkiv([attestationEntity(signed, 1), attestationEntity(forged, 2, { commitment: ['str', commitment] }),
    entity('tlsn-attestation', { type: ['str', 'tlsn-attestation'], payload: ['bytes', '0x00'] }, 3)]);
  assert.deepEqual(await findAttestations({ client, commitment }), [signed]);
  assert.match(queries[0], /arkiv\.schema = str\('tlsn-attestation'\) AND type = str\('tlsn-attestation'\) AND commitment = str\('a{64}'\)/);
  await assert.rejects(findAttestations({ client, commitment: 'not hex' }), /commitment/);
});

test('a bundle round-trips through parts and is only returned when its bytes match the proof hash', async () => {
  const bundleJson = JSON.stringify({ kind: 'EXAMPLE', version: 1, proofs: [{ proof: 'x'.repeat(PART_BYTES * 2 + 10) }] });
  const created = [];
  const walletClient = { createEntity: async (schema, values) => { created.push(values); return { entityKey: `0x0${created.length}`, txHash: '0x' }; } };
  const result = await publishBundle({ commitment, bundleJson }, { walletClient });
  const proofHash = createHash('sha256').update(bundleJson).digest('hex');
  assert.equal(result.proofHash, proofHash);
  assert.equal(created.length, 3);
  assert.ok(created.every(values => values.payload.length <= PART_BYTES && values.count === 3));
  const rows = created.map((values, index) => entity('tlsn-bundle-part', { type: ['str', values.type], commitment: ['str', commitment],
    proofHash: ['str', values.proofHash], index: ['i32', values.index], count: ['i32', values.count],
    payload: ['bytes', `0x${Buffer.from(values.payload).toString('hex')}`] }, index));
  // A junk duplicate of part 1 must not break reassembly; a set with a wrong hash is ignored.
  const junk = entity('tlsn-bundle-part', { type: ['str', 'tlsn-bundle-part'], commitment: ['str', commitment], proofHash: ['str', proofHash],
    index: ['i32', 1], count: ['i32', 3], payload: ['bytes', '0x00'] }, 9);
  const { client } = arkiv([rows[2], junk, rows[0], rows[1]]);
  assert.deepEqual(await findBundle({ client, commitment, proofHash }), { json: bundleJson, proofHash });
  assert.equal(await findBundle({ client: arkiv(rows.slice(0, 2)).client, commitment }), null);
  await assert.rejects(publishBundle({ commitment, bundleJson: '{' + 'x'.repeat(PART_BYTES * 17) }, { walletClient }), /too large/);
});
