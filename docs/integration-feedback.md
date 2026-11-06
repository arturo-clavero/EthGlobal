# Integration feedback: Arkiv and World ID

Notes from integrating `@arkiv-network/sdk` 1.0.1 ([`crops/pin-registry`](../crops/pin-registry),
[`verify/`](../verify/)) and `@worldcoin/idkit-core` 4.6.0 ([`crops/personhood`](../crops/personhood)), written to
share with both teams. Each item was checked against the installed package and the public docs in November 2026.
Format: what we tried → what happened → impact → suggestion.

## Arkiv

**1. Public RPC rate limits**
- Tried: reading attestations from a static page with no access key.
- Happened: `rabdi()` throws `MissingAccessKeyError` without `accessKey`; `accessKey: ''` works but logs that the
  public endpoint is heavily rate limited. Expected: a keyless read path usable by a public page.
- Impact: a public verify page either ships a key (which anyone can copy) or risks rate-limit failures for viewers.
- Suggestion: document the public endpoint's limits and a recommended pattern for keyless, read-only public pages.

**2. 128 KiB entity limit**
- Tried: publishing a public proof bundle as one entity.
- Happened: entities are capped at 128 KiB, so bundles are split into parts of at most 120 KiB, one transaction
  each. In our runs a GCP bundle was about 780 to 945 KB (7 to 8 parts) and an AWS bundle 2 to 3 parts.
- Impact: multi-transaction writes, partial-write handling, and reassembly code on every reader.
- Suggestion: a documented chunking pattern, or a batched create for linked parts.

**3. Lifetime cap**
- Tried: long-lived evidence.
- Happened: lifetime is capped at 7,884,000 blocks (about 182.5 days). SDK 1.0.1 refuses longer expiries before
  sending, which is helpful.
- Impact: no long-lived registry without re-publishing or calling `extendEntity` before expiry, which needs a
  funded writer to stay around.
- Suggestion: state the cap and the renewal pattern on the main docs page, not only in SDK comments.

**4. Expiry is not deletion**
- Tried: reasoning about privacy of published data.
- Happened: expiry removes an entity from queries; the creating transaction, with its payload, stays in chain
  history. The SDK README does not mention this.
- Impact: integrators may treat expiry as erasure and publish data they would not publish permanently.
- Suggestion: a prominent privacy note: everything written is public and permanent in history; expiry only hides
  it from queries.

**5. Testnet funds**
- Tried: a first write.
- Happened: writes need tGLM from the faucet at `hub.arkiv.network`.
- Impact: we have not run a real write in automated tests; the package's tests use the real SDK over an in-memory
  transport. The SDK ships a `localhost` chain, but we did not find a documented local node for tests.
- Suggestion: document a local node or devnet for CI, or a test-funds path for automated tests.

**6. Network and naming churn**
- Tried: following examples found by search.
- Happened: Braga was sunset (12 August) after Kaolin; Rabdi (chain id `7794095`) is current. Older material still
  ranks highly: hub "skills" pages pinned to Braga and SDK 0.6, and Python SDK docs using `btl` and
  `string_annotations`, where SDK 1.0 uses attributes and `expiration`.
- Impact: time lost on examples that no longer run.
- Suggestion: mark superseded pages with a banner naming the current network and SDK version.

**7. No browser bundle**
- Tried: using the SDK from a static page with no build step.
- Happened: the package ships ESM and CJS with bare imports of `viem`; the README lists Node and Bun only. We load
  it through esm.sh with an import map.
- Impact: a CDN dependency that sees viewers' IP addresses, or a bundler for a page that otherwise needs none.
- Suggestion: a self-contained browser ESM build of the read path, or a documented import map.

What worked well:

- Typed schemas with indexed columns and `onMismatch: 'skip'`, which suits a store anyone can write to.
- Reads need no wallet; `select()` with only the fields needed keeps responses small.
- Clear errors: `MissingAccessKeyError` names the fix and the URL; expiry beyond the cap fails before sending.
- The query builder works over a custom viem transport, so read paths are testable without a network.

## World ID

**1. IDKit 4 redesign**
- Tried: integrating from examples found by search.
- Happened: IDKit 4.x is a breaking redesign; `@worldcoin/idkit-standalone` is discontinued. Many examples still
  show 3.x calls (`verification_level`, `verifyCloudProof`).
- Impact: rework after starting from outdated examples.
- Suggestion: keep the migration banner on every legacy page.

**2. Backend-signed `rp_context` for every request**
- Tried: a minimal flow.
- Happened: every request needs an `rp_context` signed by the relying party's backend with the Developer Portal
  signing key.
- Impact: one more endpoint and secret per integration; not possible from a purely static page.
  The security reason is sound.
- Suggestion: a reference serverless function for the signing endpoint.

**3. Selfie Check availability**
- Tried: understanding which credentials were open to us.
- Happened: the credentials page says Selfie Check is available today through the legacy preset and to select
  partners, while the session-proofs page shows a `selfieCheck()` preset.
- Impact: unclear what an ordinary app can request. We did not use it as a gate.
- Suggestion: one availability table per credential and preset.

**4. "Agent Pass"**
- Tried: finding a product we had heard called Agent Pass.
- Happened: we found no page by that name; the closest are human-in-the-loop and AgentKit under Agents.
- Impact: unclear whether it exists, was renamed, or is not public.
- Suggestion: a redirect or glossary entry for older names.

**5. Composing credentials**
- Tried: "proof of human or passport" in one request.
- Happened: `any()` with `CredentialRequest` works, but composition and the rule that a user holds only one NFC
  credential (passport, eID, My Number Card are alternatives) are found in the NFC credential page and the agent
  guide rather than the credentials page.
- Impact: easy to compose constraints that no user can satisfy.
- Suggestion: a composition section on the credentials page.

**6. 4.0-only requests**
- Tried: accepting World ID 4 proofs only.
- Happened: the integration prompt recommends `allow_legacy_proofs: true`, and `proofOfHuman()` includes a legacy
  Orb fallback. We set `allow_legacy_proofs: false` and use `CredentialRequest` directly.
- Impact: unclear which settings give a 4.0-only request.
- Suggestion: document a 4.0-only configuration explicitly.

**7. Local testing**
- Tried: testing without real credentials.
- Happened: `staging` works with the simulator; Sandbox needs Developer Portal enrollment and a TestFlight or
  private Google Play build of the World ID app.
- Impact: real end-to-end tests need an app registration and enrolled devices.
- Suggestion: a sandbox path that does not need device enrollment, for automated tests.

What worked well:

- The verify API takes the IDKit result unchanged; no remapping.
- `signRequest` and `hashSignal` as subpath exports run in Node, so the backend checks are unit-testable.
- The `signal` binds a proof to a value the app chooses (the evidence commitment or an application record hash), and per-action nullifiers give per-job uniqueness without
  linking across jobs.
- Typed result shapes (`protocol_version`, `responses[].identifier`) make strict local checks easy.
