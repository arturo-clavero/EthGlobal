// Read path: no keys, no viem/accounts. Safe to load in a browser through an import map.
import { createPublicClient } from '@arkiv-network/sdk';
import { rabdi } from '@arkiv-network/sdk/chains';
import { eq } from '@arkiv-network/sdk/query';
import { bytes, defineSchema, i32, str } from '@arkiv-network/sdk/schema';
import { http } from 'viem';

export const ATTESTATION_TYPE = 'tlsn-attestation';
export const BUNDLE_PART_TYPE = 'tlsn-bundle-part';
/** Arkiv caps one entity's bytes at 128 KiB; parts stay below it with room for the other attributes. */
export const PART_BYTES = 120 * 1024;
export const MAX_PARTS = 16;
const PAGE = 100, MAX_PAGES = 20;

// Every attribute is public. Only coarse, non-personal values may ever be stored here.
export const Attestations = defineSchema(ATTESTATION_TYPE, {
  type: str().indexed(),
  commitment: str().indexed(),
  provider: str().indexed(),
  claim: str().indexed(),
  verifierKeyId: str().indexed(),
  payload: bytes(),
});
export const BundleParts = defineSchema(BUNDLE_PART_TYPE, {
  type: str().indexed(),
  commitment: str().indexed(),
  proofHash: str().indexed(),
  index: i32().indexed(),
  count: i32(),
  payload: bytes(),
});

export const HEX64 = /^[0-9a-f]{64}$/;
const KEY_ID = /^[0-9a-f]{32}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
export const fail = reason => { throw new Error(`PIN_REGISTRY_INVALID: ${reason}`); };

/** The Arkiv testnet (Rabdi) unless `chain` is given; `rpcUrl` overrides the chain's default endpoint. */
export function arkivChain({ chain, accessKey = '' } = {}) {
  return chain ?? rabdi({ accessKey });
}

export function readClient({ client, rpcUrl, accessKey, chain } = {}) {
  return client ?? createPublicClient({ chain: arkivChain({ chain, accessKey }), transport: http(rpcUrl) });
}

const decoder = new TextDecoder('utf-8', { fatal: true });
export function hexToBytes(hex) {
  if (typeof hex !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(hex)) fail('bytes');
  return Uint8Array.from({ length: (hex.length - 2) / 2 }, (_, index) => parseInt(hex.slice(2 + index * 2, 4 + index * 2), 16));
}

export async function sha256Hex(bytes) {
  return Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes)),
    byte => byte.toString(16).padStart(2, '0')).join('');
}

async function fetchAll(builder) {
  const rows = [];
  for (let page = 0; page < MAX_PAGES; page++) {
    const { entities } = await builder.limit(PAGE).offset(page * PAGE).fetch();
    rows.push(...entities);
    if (entities.length < PAGE) break;
  }
  return rows;
}

function filtered(client, schema, selection, filters, owner) {
  if (owner !== undefined && !ADDRESS.test(owner)) fail('owner');
  let builder = client.select(selection).from(schema, { onMismatch: 'skip' }).where(...filters);
  if (owner) builder = builder.ownedBy(owner);
  return builder;
}

/**
 * Signed attestations, optionally narrowed by commitment, verifier key id or writer wallet. Read-only.
 * Results are untrusted until verifyAttestation succeeds against a known verifier key.
 */
export async function findAttestations({ commitment, verifierKeyId, owner, ...connection } = {}) {
  const filters = [eq('type', ATTESTATION_TYPE)];
  if (commitment !== undefined) {
    if (!HEX64.test(commitment)) fail('commitment');
    filters.push(eq('commitment', commitment));
  }
  if (verifierKeyId !== undefined) {
    if (!KEY_ID.test(verifierKeyId)) fail('verifierKeyId');
    filters.push(eq('verifierKeyId', verifierKeyId));
  }
  const rows = await fetchAll(filtered(readClient(connection), Attestations,
    { commitment: true, verifierKeyId: true, payload: true }, filters, owner));
  const found = [];
  for (const row of rows) {
    try {
      const signed = JSON.parse(decoder.decode(hexToBytes(row.payload.value)));
      // The indexed attributes must describe the payload they sit next to.
      if (signed?.commitment === row.commitment.value && signed?.verifierKeyId === row.verifierKeyId.value) found.push(signed);
    } catch { /* skip malformed entities: anyone can write */ }
  }
  return found;
}

/**
 * Reassembles the public bundle published for a commitment. Returns { json, proofHash } for the first complete set of
 * parts whose bytes hash to their proofHash (and to `proofHash` when given), or null. Read-only.
 */
export async function findBundle({ commitment, proofHash, owner, ...connection } = {}) {
  if (!HEX64.test(commitment ?? '')) fail('commitment');
  const filters = [eq('type', BUNDLE_PART_TYPE), eq('commitment', commitment)];
  if (proofHash !== undefined) {
    if (!HEX64.test(proofHash)) fail('proofHash');
    filters.push(eq('proofHash', proofHash));
  }
  const rows = await fetchAll(filtered(readClient(connection), BundleParts,
    { proofHash: true, index: true, count: true, payload: true }, filters, owner));
  const sets = new Map();
  for (const row of rows) {
    const hash = row.proofHash.value, index = row.index.value, count = row.count.value;
    if (!HEX64.test(hash) || !Number.isInteger(count) || count < 1 || count > MAX_PARTS || !Number.isInteger(index) ||
        index < 0 || index >= count) continue;
    const key = `${hash}:${count}`;
    if (!sets.has(key)) sets.set(key, { hash, count, parts: new Map() });
    const set = sets.get(key);
    if (!set.parts.has(index)) set.parts.set(index, []);
    set.parts.get(index).push(row.payload.value);
  }
  for (const { hash, count, parts } of sets.values()) {
    if (parts.size !== count) continue;
    // Duplicates at one index are possible (anyone can write); try each candidate and keep the one that hashes.
    let candidates = [[]];
    for (let index = 0; index < count && candidates.length <= 8; index++)
      candidates = candidates.flatMap(prefix => parts.get(index).map(value => [...prefix, value]));
    for (const candidate of candidates.slice(0, 8)) {
      try {
        const chunks = candidate.map(hexToBytes);
        const bytes = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
        chunks.reduce((offset, chunk) => { bytes.set(chunk, offset); return offset + chunk.length; }, 0);
        if (await sha256Hex(bytes) === hash) return { json: decoder.decode(bytes), proofHash: hash };
      } catch { /* try the next candidate */ }
    }
  }
  return null;
}
