# Arkiv

[`crops/pin-registry`](../crops/pin-registry) publishes signed attestations (and, optionally, public proof bundles)
to [Arkiv](https://docs.arkiv.network) and reads them back.

## Why Arkiv

- **Evidence survives without the operator.** Once written, an attestation is readable from any Arkiv RPC endpoint
  until it expires, whether or not the operator, its backend or its website is still running.
- **Anyone can check it.** Reading needs no account and no key. Attributes are indexed, so a third party can find
  an attestation by its commitment, verifier key or writer, and check it with the [verify page](verification.md).
- **No custom storage service.** Arkiv is a queryable store with expiry, which fits evidence that should not live
  forever.

## Entities

Each entity is owned by the wallet that wrote it. Every attribute and payload is public.

### `tlsn-attestation`

| Field | Type | Value |
| --- | --- | --- |
| `type` | `str`, indexed | `tlsn-attestation` |
| `commitment` | `str`, indexed | 64 hex characters, see [architecture.md](architecture.md#data-flow-of-a-cloud-private-proof) |
| `provider` | `str`, indexed | e.g. `gcp`, `aws` |
| `claim` | `str`, indexed | coarse claim, e.g. `gcp:observed:g1,g4` |
| `verifierKeyId` | `str`, indexed | 32 hex characters, see [verification.md](verification.md#publishing-a-verifier-key) |
| `payload` | `bytes` | the signed attestation, as JSON |
| owner | system | the writer wallet |
| expiry | system | at most about 182 days after the write; default 180 days |

The payload (signed attestation) looks like this:

```json
{
  "v": 1,
  "type": "tlsn-attestation",
  "commitment": "<64 hex>",
  "provider": "gcp",
  "claim": "gcp:observed:g1,g4",
  "window": 30,
  "proofHash": "<64 hex>",
  "vkHashes": { "timestamps-v1": "<64 hex>", "...": "..." },
  "issuedAt": "2026-11-06T00:00:00.000Z",
  "expiresAt": "2027-05-05T00:00:00.000Z",
  "humanCheck": { "credential": "proof_of_human", "scope": "per-job" },
  "verifierKeyId": "<32 hex>",
  "sig": "<base64url Ed25519 signature>"
}
```

`coreDigest`, `pluginSha256`, `window`, `vkHashes` and `humanCheck` are optional.

### `tlsn-bundle-part` (optional)

| Field | Type | Value |
| --- | --- | --- |
| `type` | `str`, indexed | `tlsn-bundle-part` |
| `commitment` | `str`, indexed | the attestation's commitment |
| `proofHash` | `str`, indexed | sha256 of the whole bundle text |
| `index` | `i32`, indexed | part number, from 0 |
| `count` | `i32` | number of parts (at most 16) |
| `payload` | `bytes` | up to 120 KiB of the canonical public bundle |

Arkiv caps an entity at 128 KiB, so a bundle is split. Readers reassemble the parts and keep the set whose bytes hash
to `proofHash`.

## Queries a third party can run

With the package (Node 22.10+, or a browser with an import map):

```js
import { findAttestations, findBundle } from '@tlsn-fork/pin-registry/read';
import { verifyAttestation } from '@tlsn-fork/proof-bundle';

const commitment = '<64 hex>';
// accessKey: '' uses the public, heavily rate-limited endpoint; get a free key at hub.arkiv.network.
const found = await findAttestations({ commitment, accessKey: '' });
for (const signed of found) {
  console.log(signed.claim, signed.verifierKeyId, await verifyAttestation(signed, publicKeyPem));
}
const bundle = await findBundle({ commitment, accessKey: '' });   // { json, proofHash } or null
```

`findAttestations` also takes `verifierKeyId` (all attestations by one verifier) and `owner` (all entities written
by one wallet).

With the raw SDK (`@arkiv-network/sdk` 1.0.1), no schema:

```js
import { createPublicClient } from '@arkiv-network/sdk';
import { rabdi } from '@arkiv-network/sdk/chains';
import { eq } from '@arkiv-network/sdk/query';
import { http } from 'viem';

const client = createPublicClient({ chain: rabdi({ accessKey: '' }), transport: http() });
const { entities } = await client
  .select({ $key: true, $owner: true, $expiresAt: true, claim: true, payload: true })
  .where(eq('type', 'tlsn-attestation'), eq('commitment', commitment))
  .limit(100)
  .fetch();
// payload.value is hex; decode it to the signed attestation JSON, then verify the signature.
```

Results are untrusted until the signature checks out against a key you accept: anyone can write an entity with
these attributes.

## What is kept off Arkiv

| Not published | Why |
| --- | --- |
| Transcripts, revealed or not | They contain account data; the claim is all a reader needs |
| Email addresses, account ids, project ids, even hashed | A hash of a guessable identifier can be confirmed by hashing guesses, and a stable one links entries across time; no reader needs them |
| World ID nullifiers | They prove uniqueness to one relying application for one job; publishing them would make that check linkable |
| Proof bundles, by default | Their public inputs include the lengths of hidden values (for example of an email address or project id) and the time cutoff. Publish only when that is acceptable |
| Session ids, receipts, the verifier's records | Operational data with no value to a reader |

Expiry removes an entity from queries. It does not erase it from chain history: the transaction that created it,
with its payload, stays in the blocks. Treat everything written to Arkiv as permanent public data.

## Network

| | |
| --- | --- |
| Network | Rabdi testnet |
| Chain id | `7794095` |
| RPC | `https://rpc.rabdi.db-chain.testnet.arkiv.network` (with an access key: `…/<accessKey>`) |
| Explorer | `https://rabdi.explorer.arkiv.network` |
| Gas token | tGLM (testnet), from the faucet at `hub.arkiv.network` |
| SDK | `@arkiv-network/sdk` 1.0.1, `viem` 2.57.6 |

`arkivChain({ chain })` and `rpcUrl` let a caller point the package at another Arkiv chain.

## Costs and limits

- **Reads** are free and need no wallet. The public endpoint is heavily rate limited; a free access key from
  `hub.arkiv.network` raises the limit.
- **Writes** are transactions paid in tGLM by the writer wallet. The key is passed in from the environment and
  never stored by the package. An attestation is one transaction; a bundle is one transaction per 120 KiB part.
- **Size.** 128 KiB per entity, 128 bytes per string attribute. Claims are limited to 128 characters for this
  reason.
- **Lifetime.** At most 7,884,000 blocks (about 182.5 days) from the write. The package caps it at 182 days and
  defaults to 180. Longer retention needs re-publishing or `extendEntity` before expiry.
- **Reading many.** The package reads at most 20 pages of 100 entities per query.

## Setup

Reading needs none of this. These steps are for the operator who publishes attestations.

### 1. Writer wallet

- **Create a new key used only for publishing.** Never use a personal wallet: the writer address is public on every
  entity, and `findAttestations({ owner })` lists everything it wrote.
- The package expects the key as `0x` followed by 64 hex characters (`writeClient` in
  [`write.mjs`](../crops/pin-registry/write.mjs)). One way to make one, from `crops/pin-registry` after `npm ci`:

  ```sh
  node --input-type=module -e "import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
  const key = generatePrivateKey(); console.log(key, privateKeyToAccount(key).address)"
  ```

- Keep the key in the publishing backend's environment or secret store and pass it as `privateKey`. The package never
  stores it.
- Fund the address with testnet tGLM from the faucet: <https://hub.arkiv.network/faucet>.

### 2. Access key (optional)

Without an access key (`accessKey: ''`, the default) calls use the public endpoint, which is heavily rate limited.
Create a free key at <https://hub.arkiv.network/access-keys> and pass it as `accessKey`. It is appended to the RPC
URL, so treat it as a secret on the backend; a key shipped in a public page can be copied.

### 3. Network

The package uses `rabdi()` from `@arkiv-network/sdk` 1.0.1 unless told otherwise (`arkivChain` in
[`read.mjs`](../crops/pin-registry/read.mjs)): chain id `7794095`, RPC
`https://rpc.rabdi.db-chain.testnet.arkiv.network`. SDK 1.0.1 defines only `rabdi` and `localhost`. Arkiv's docs also
mention a Tiramisu testnet (chain id `7738577`). Confirm the current testnet in Arkiv's docs
(<https://docs.arkiv.network>) before publishing. To use another chain, pass a viem chain as `chain`, and `rpcUrl` if
needed, to every read and write call.

### 4. Lifetime

`publishAttestation` and `publishBundle` take `expiresInSeconds`: default 180 days, at least 60 seconds, at most 182
days (`lifetime` in `write.mjs`). This is the entity's lifetime on Arkiv. The attestation's own `expiresAt` is a
separate, signed field: `verifyAttestation` returns `expired` after it. Set `expiresAt` no later than the entity
lifetime, so an attestation does not outlive what readers can find.

### 5. Publish

```js
import { canonicalize, publicBundle } from '@tlsn-fork/proof-bundle';
import { publishAttestation, publishBundle } from '@tlsn-fork/pin-registry';

const connection = { privateKey: process.env.ARKIV_WRITER_KEY, accessKey: process.env.ARKIV_ACCESS_KEY ?? '' };
const { entityKey, txHash } = await publishAttestation(signed, connection);

// Only if the lengths of hidden values may be public (see "What is kept off Arkiv").
await publishBundle({ commitment: signed.commitment, bundleJson: canonicalize(publicBundle(bundle)) }, connection);
```

The variable names are examples; the package reads no environment. `bundleJson` must be exactly
`canonicalize(publicBundle(bundle))`: its sha256 is the attestation's `proofHash`, which the verify page uses to find
the bundle.

### 6. Check what you published

Use the queries in [Queries a third party can run](#queries-a-third-party-can-run), or open
`verify/?commitment=<64 hex>` ([verification.md](verification.md)). To list everything the writer wallet published:

```js
const mine = await findAttestations({ owner: '0x…writer address', accessKey: '' });
```

### Failure behaviour

| Case | What happens |
| --- | --- |
| Bad key, malformed attestation, bundle over 16 parts, lifetime out of range | The call rejects before any transaction (`PIN_REGISTRY_INVALID: …`); tested in [`registry.test.mjs`](../crops/pin-registry/registry.test.mjs) |
| RPC or transaction error | The SDK error is passed on as a rejection. The package does not retry or queue |
| A bundle part fails part-way | Earlier parts stay on Arkiv. `findBundle` ignores a set with missing parts, so readers see no bundle; publishing again writes a complete set |
| Malformed or mismatched entities when reading | Skipped by `findAttestations` and `findBundle`; anyone can write |

Nothing in this repository calls the publish functions, so whether a failed write blocks the user is the caller's
choice. An attestation is valid without Arkiv: the verify page also checks a dropped file. A caller that should
never block the user can answer first, publish afterwards, and retry or log a failure.
