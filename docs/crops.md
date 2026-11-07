# CROPS

CROPS is the Ethereum Foundation's mandate for the software it supports: **C**ensorship resistance, **O**pen source,
**P**rivacy and **S**ecurity. This page states, for each letter, what this fork does, what it does not, and what
every third party learns. Component details are in [architecture.md](architecture.md).

Each guarantee, the code that enforces it and the test that checks it are listed in
[crops-compliance.md](crops-compliance.md).

## Censorship resistance

What holds:

- Evidence does not depend on the operator staying online. A signed attestation and, optionally, the public proof
  bundle are written to Arkiv ([arkiv.md](arkiv.md)) and stay readable by anyone until they expire.
- Anyone can check that evidence with the static [`verify/`](../verify/) page, hosted anywhere
  ([verification.md](verification.md)).
- Anyone can run their own TLSNotary verifier ([`servers/verifier`](../servers/verifier)), sign with their own key
  and list it in their own `keys.json`.

Trade-offs:

- Arkiv entities expire after at most about 182 days (default 180). Keeping evidence longer means re-publishing or
  extending it.
- Arkiv is currently a testnet. A testnet can be reset or replaced; entities do not carry over.
- The verify page loads the Arkiv SDK from the esm.sh CDN. A host that wants no CDN dependency can vendor those
  modules and change the import map in `verify/index.html`.

## Open source

What holds:

- MIT or Apache-2.0, at your option ([`LICENSE-MIT`](../LICENSE-MIT), [`LICENSE-APACHE`](../LICENSE-APACHE)), like
  upstream. The build refuses unknown or copyleft licences in shipped code and writes `THIRD_PARTY_NOTICES.txt`.
- Everything builds from this repository: the TLSNotary core is pinned by commit and its patches by hash
  ([`core/VERSION`](../core/VERSION)); circuits, verification keys and the WASM prover are built by
  [`fork/build.sh`](../fork/build.sh).
- `crops/` and `verify/` are plain ES modules with no build step.

Build and run from the repository alone:

```sh
npm ci
npm run build:fork                 # -> fork/out/extension (load unpacked in Chrome)

(cd crops/pin-registry && npm ci && npm test)   # same for proof-bundle, personhood
(cd servers/verifier && cargo run --release)  # your own verifier, see VERIFIER.md

python3 -m http.server 8080        # serve the repository root, then open
                                   # http://localhost:8080/verify/?commitment=<hex>
```

The private-proof build needs the pinned Noir compiler (`GCP_NOIR_NARGO`, default `nargo` on `PATH`) and the Rust
toolchain pinned by `fork/wasm-build-pins.json`.

## Privacy

| Third party | What it learns |
| --- | --- |
| Provider (Google Cloud, AWS) | An ordinary session from the user's browser, as if the user browsed the console |
| TLSNotary verifier (Proxy mode) | The user's IP address, the hosts contacted, timing and traffic sizes, the revealed HTTP framing, and private values only as blinded commitments `sha256(value ‖ blinder)` |
| Relying application | The coarse claim, the proof bundle and the verifier's receipts (framing and commitments), never the private values |
| Arkiv and anyone reading it | The coarse claim, the commitment, the signed attestation, the writer wallet, and, only if published, the public bundle (proofs and public inputs: blinded hashes, lengths of hidden values, the time cutoff) |
| World ID (optional) | That a unique human acted for the relying application. The per-job nullifier goes to the relying application's backend and is never published |
| esm.sh and the Arkiv RPC endpoint (verify page) | The viewer's IP address and the commitment looked up |

What is never sent anywhere: transcripts, email addresses, account or project ids (not even hashed without a
blinder), API keys, blinders, World ID nullifiers.

Trade-offs:

- Proxy mode is a network intermediary, so the verifier sees metadata (IP, hosts, timing, sizes). Running your own
  verifier, or reaching it through a network you trust, limits who sees it.
- A public bundle leaks the lengths of hidden values. That is why bundles are not published by default.
- The claim itself is public once published. It is coarse by design (skill groups observed, a window in days), but
  it is linked to the writer wallet and the publication time.

## Security

What holds:

- Attestations are Ed25519 signatures over the canonical attestation, which includes the commitment. Signing keys
  live only in the signer's environment; public keys are listed in [`verify/keys.json`](../verify/keys.json).
- Every value read from Arkiv is treated as untrusted: anyone can write, so readers keep only entities whose
  indexed attributes match the payload, and accept only signatures by a listed key.
- The extension runs only plugin code it ships, checked by sha256; the page passes values, never code. The page API
  answers only on build-time origins, and `window.tlsn` is locked there.
- Witness data (transcript bytes and blinders) is owned by one object per run and erased when the run settles.
- The TLSNotary core and its patches, the circuits and their verification keys are pinned by hash.

Trade-offs, stated plainly:

- **Transcript authenticity rests on the TLSNotary verifier.** If the verifier lies about what the provider sent,
  the proofs prove the wrong thing. Anyone can run their own verifier and publish its key; a relying party chooses
  which keys it accepts.
- **Proxy vs MPC.** In Proxy mode the verifier opens the connection to the provider and observes its TLS records; in
  MPC-TLS mode it would also hold a share of the session keys. MPC-TLS gives the verifier less room to deviate but
  costs much more bandwidth and time. The private proofs here accept Proxy-mode receipts only.
- **The verify page checks signatures, not zero-knowledge proofs.** It checks the signature, recomputes the
  commitment and the proof hash, checks that the circuits match pinned verification keys, and checks the claim
  against the proven public inputs where the circuits expose it. It does not re-run the ZK verifier until the
  verification keys are hosted next to it, so proof validity currently rests on the signer having run
  `verifyBundle` before signing.
