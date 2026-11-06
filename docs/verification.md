# Verifying an attestation

Anyone can check an attestation published on Arkiv. Nothing here needs an account, a key or the operator's servers.

## The verify page

Open `verify/?commitment=<64 hex>` on any static host of this repository, or paste the commitment into the form. A
JSON file can also be dropped on the page: a public bundle, a signed attestation, or `{ "attestation": …, "bundle":
… }`. A dropped attestation's commitment is recomputed from its fields rather than taken from its label.

The page:

1. loads [`verify/keys.json`](../verify/keys.json), the verifier keys it accepts;
2. finds attestations for the commitment on Arkiv ([arkiv.md](arkiv.md)), unless a file supplied one;
3. looks for the public bundle on Arkiv, by commitment and proof hash;
4. runs the checks below in the viewer's browser and shows the result.

All checks live in [`verify/verify.mjs`](../verify/verify.mjs) (no DOM, no network; tested in Node).

## What each check means

| Check | What it establishes |
| --- | --- |
| Signed by a listed verifier key, unexpired, and the commitment recomputes from its fields | A verifier you accept signed exactly this claim, proof hash and pins, and the attestation has not expired |
| Published proof bundle hashes to the signed proof hash | The bundle on Arkiv is the one the signer saw |
| Verification keys are the ones pinned in this repository | The proofs were made for these circuits, with these keys, and no others |
| Claim matches the proven public inputs | The claim is not just a label: for GCP the observed groups and window are recomputed from the public inputs; for AWS the required circuits are present |

Results:

| Status | Meaning |
| --- | --- |
| Verified | All checks passed |
| Signed by the verifier (public proof bundle not available) | The signature checks out; there is no public bundle to check the proof hash and claim against |
| Does not verify | An attestation was found but a check failed |
| No attestation found | Nothing on Arkiv for this commitment |

What the page **takes from the signature** and cannot check itself (it says so under Details):

- the proofs came from a real TLS session with the provider, as observed by the TLSNotary verifier;
- the public inputs match that authenticated session;
- the zero-knowledge proofs verify. The page does not re-run the ZK verifier until the verification keys are hosted
  with it.

## Publishing a verifier key

A verifier operator signs attestations with an Ed25519 key and publishes the public key.

```sh
openssl genpkey -algorithm ed25519 -out attest-key.pem      # PKCS#8 private key; keep it in the signer's env only
openssl pkey -in attest-key.pem -pubout -out attest-pub.pem
# verifierKeyId: the first 16 bytes (32 hex) of sha256 over the public key's SPKI DER encoding
openssl pkey -pubin -in attest-pub.pem -outform DER | sha256sum | cut -c1-32
```

The same id comes from `verifierKeyId(publicKeyPem)` in [`crops/proof-bundle`](../crops/proof-bundle). Add the key
to `verify/keys.json`:

```json
{
  "keys": [
    {
      "id": "<32 hex verifierKeyId>",
      "label": "Example verifier",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    }
  ]
}
```

`label` is optional and shown on the page. The page accepts an attestation only if its `verifierKeyId` matches an
`id` here and the signature verifies with that `publicKeyPem`. Anyone hosting the page decides which keys to trust
by editing this file.

## Hosting the page

The page is static, but it imports files from outside `verify/`, so serve the **repository root**:

- `verify/` (page, `keys.json`);
- `crops/proof-bundle/` and `crops/pin-registry/read.mjs`;
- `private-proof/gcp/policy.mjs`, `private-proof/gcp/generated/` and `private-proof/aws/generated/` (pinned keys and
  the GCP batch layout).

The Arkiv SDK and viem are loaded from esm.sh through the import map in `verify/index.html`, pinned to
`@arkiv-network/sdk@1.0.1` and `viem@2.57.6`. To avoid the CDN, vendor those modules and point the import map at
them.

Locally:

```sh
python3 -m http.server 8080
# http://localhost:8080/verify/?commitment=<hex>
```

On GitHub Pages: publish the repository root of the branch that contains `verify/` (Settings → Pages → Deploy from a
branch, folder `/`). The page is then at `https://<owner>.github.io/<repo>/verify/`. Any other static host works the
same way.

Who sees what: the static host and esm.sh see the viewer's IP address; the Arkiv RPC endpoint sees the viewer's IP
address and the commitment looked up. The page sends no referrer.
