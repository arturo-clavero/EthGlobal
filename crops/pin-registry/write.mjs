// Write path: needs a funded Arkiv wallet key, passed in by the caller (from an env var), never stored.
import { createWalletClient, ExpirationTime } from '@arkiv-network/sdk';
import { http } from 'viem';
import { arkivChain, ATTESTATION_TYPE, Attestations, BUNDLE_PART_TYPE, BundleParts, fail, HEX64, MAX_PARTS, PART_BYTES,
  sha256Hex } from './read.mjs';

const DAY = 86400;
/** Arkiv's MAX_LIFETIME is 7,884,000 blocks (about 182.5 days); stay inside it. */
const MAX_SECONDS = 182 * DAY;

async function writeClient({ walletClient, privateKey, rpcUrl, accessKey, chain }) {
  if (walletClient) return walletClient;
  if (typeof privateKey !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(privateKey)) fail('privateKey');
  const { privateKeyToAccount } = await import('viem/accounts');
  return createWalletClient({ chain: arkivChain({ chain, accessKey }), transport: http(rpcUrl),
    account: privateKeyToAccount(privateKey) });
}

function lifetime(seconds) {
  if (!Number.isSafeInteger(seconds) || seconds < 60 || seconds > MAX_SECONDS) fail('expiresInSeconds');
  return ExpirationTime.fromSeconds(seconds);
}

const STR = value => typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= 128;

/**
 * Publishes a signed attestation (from @tlsn-fork/proof-bundle signAttestation) as an entity owned by the writer wallet.
 * Attributes: type, commitment, provider, claim, verifierKeyId; payload: the signed attestation JSON.
 */
export async function publishAttestation(signed, { expiresInSeconds = 180 * DAY, ...connection } = {}) {
  if (!signed || typeof signed !== 'object' || signed.type !== ATTESTATION_TYPE || !HEX64.test(signed.commitment ?? '') ||
      !STR(signed.provider) || !STR(signed.claim) || !/^[0-9a-f]{32}$/.test(signed.verifierKeyId ?? '') ||
      typeof signed.sig !== 'string') fail('signed attestation');
  const client = await writeClient(connection);
  const { entityKey, txHash } = await client.createEntity(Attestations, {
    type: ATTESTATION_TYPE, commitment: signed.commitment, provider: signed.provider, claim: signed.claim,
    verifierKeyId: signed.verifierKeyId, payload: new TextEncoder().encode(JSON.stringify(signed)),
  }, { expiration: lifetime(expiresInSeconds) });
  return { entityKey, txHash };
}

/**
 * Publishes the public bundle (canonical JSON text of proofs and public inputs; no transcripts, no session ids) in
 * parts of at most PART_BYTES, linked by commitment and by proofHash = sha256 of the whole text.
 */
export async function publishBundle({ commitment, bundleJson }, { expiresInSeconds = 180 * DAY, ...connection } = {}) {
  if (!HEX64.test(commitment ?? '')) fail('commitment');
  if (typeof bundleJson !== 'string' || !bundleJson.startsWith('{')) fail('bundleJson');
  const bytes = new TextEncoder().encode(bundleJson);
  const count = Math.ceil(bytes.length / PART_BYTES);
  if (count > MAX_PARTS) fail('bundle too large');
  const proofHash = await sha256Hex(bytes), expiration = lifetime(expiresInSeconds);
  const client = await writeClient(connection);
  const entityKeys = [], txHashes = [];
  // One transaction per part keeps each under the node's size limits.
  for (let index = 0; index < count; index++) {
    const { entityKey, txHash } = await client.createEntity(BundleParts, {
      type: BUNDLE_PART_TYPE, commitment, proofHash, index, count,
      payload: bytes.slice(index * PART_BYTES, (index + 1) * PART_BYTES),
    }, { expiration });
    entityKeys.push(entityKey); txHashes.push(txHash);
  }
  return { proofHash, entityKeys, txHashes };
}
