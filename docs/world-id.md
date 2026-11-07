# World ID (optional)

[`crops/personhood`](../crops/personhood) adds one check to a job application: **one unique human per application
per job**. It uses World ID 4 through IDKit (`@worldcoin/idkit-core` 4.6.0). It is optional and separate from the
CROPS properties of the evidence ([crops.md](crops.md)): an attestation is valid with or without it.

## The trust moment

An employer wants to know that each application to a job comes from a different person, so one person cannot submit
the same evidence under several names. It does not need to know who the person is. World ID answers exactly that:
"this human has not applied to this job before", without a name, document number or account id.

## Credentials

The request accepts either of two credentials, used for **uniqueness only**:

| Credential | Identifier | What it shows |
| --- | --- | --- |
| Proof of Human | `proof_of_human` | A unique human, verified once at an Orb |
| Passport (NFC) | `passport` | A unique government document, read by NFC; one World ID per document |

The relying application can ask for both (`any`, the default) or one of them (`preset: 'proof_of_human'` or
`'passport'`).

Why this is proportionate:

- **No attributes.** The passport credential is requested as proof of a unique document, never for its attributes.
  The request has no identity check and no constraints on nationality, age, country or document type. Asking for
  those in hiring would be disproportionate to the question and a discrimination risk. The package's tests fail if
  such fields appear in a request.
- **No Selfie Check as the gate.** Selfie Check is a camera-based credential of lower assurance and is not offered;
  the server rejects any credential other than the two above.
- **No legacy proofs.** `allow_legacy_proofs` is `false`, so only World ID 4 proofs are accepted.

## Request

| Field | Value |
| --- | --- |
| `action` | `apply:<jobId>`, where `jobId` is 1 to 64 characters of `A-Z a-z 0-9 _ -` |
| `signal` | 64 hex characters the app binds the proof to: the evidence commitment, or a hash of its own application record |
| `rp_context` | signed by the relying application's backend for this action (below) |
| `environment` | `production`, or `staging` for the simulator |

```mermaid
sequenceDiagram
  participant U as Applicant (World App)
  participant P as Relying page
  participant B as Relying backend
  participant W as World verify API
  P->>B: request rp_context for apply:<jobId>
  B->>B: signRpContext (signing key from env)
  B-->>P: rp_context
  P->>U: IDKit request (QR / link), signal = binding hash
  U-->>P: proof result
  P->>B: result, unchanged
  B->>B: check action, environment, signal hash, credential
  B->>W: POST /api/v4/verify/<rp_id> (result unchanged)
  W-->>B: success + nullifier
  B->>B: reject if nullifier already used for this job, else store it
```

## Backend responsibilities

- **Sign the request context.** `signRpContext({ rpId, action, signingKeyHex })` uses IDKit's `signRequest`. The
  signing key comes from an environment variable and never reaches the client.
- **Never trust a client result.** `verifyWorldIdResult(result, { rpId, action, signal })` checks locally that the
  result is protocol 4.0, for this action and environment, bound to this signal (signal hash), and only uses an
  allowed credential. It then forwards the result unchanged to World's verify API and accepts only a successful
  answer for the same environment. Local mismatches fail without calling out.
- **Enforce uniqueness.** The function returns the nullifier; the backend stores it privately for this job and
  rejects a second application with the same nullifier. The package does not store anything.

## Nullifier scoping

The nullifier is derived per relying application and per action. The action is per job, so the same person gets a
different nullifier for every job. Two employers, or two jobs, cannot link an applicant by comparing nullifiers. The
nullifier is never published, never written to Arkiv and never placed in the attestation; the attestation may carry
only `humanCheck: { credential, scope: "per-job" }`.

## When it does not succeed

| Path | What happens |
| --- | --- |
| Applicant cancels or denies in World App | IDKit's poll returns no proof. Nothing is sent to the backend; the application can continue without the check or retry, as the relying application decides |
| Request expired | `rp_context` carries `expires_at` (IDKit default: 300 seconds). The page asks the backend for a fresh one and starts again |
| Wrong job, environment or evidence | `action-mismatch`, `environment-mismatch` or `signal-mismatch`; no call to World |
| Credential not allowed | `credential-not-allowed` (for example a selfie credential); no call to World |
| World rejects the proof | The API's error code is returned as the reason (for example `all_verifications_failed`) |
| World unreachable | `unavailable`; the backend fails closed |
| Same human, same job | The backend finds the nullifier already stored and rejects the application |

## Setup

### 1. Register the relying app

Create an app in the World Developer Portal (`https://developer.world.org`) with World ID 4.0 enabled. Keep three
values:

| Value | Form the package accepts | Where it lives |
| --- | --- | --- |
| App id | `app_…` (`worldIdRequestConfig` in [`client.mjs`](../crops/personhood/client.mjs)) | Client. Public |
| RP id | `rp_…` (`signRpContext` and `verifyWorldIdResult` in [`server.mjs`](../crops/personhood/server.mjs)) | Client and backend. Public |
| Signing key | Hex string, passed as `signingKeyHex` | Backend only. The portal shows it once |

### 2. Create one action per job

- The action is `apply:<jobId>`. Build it with `jobAction(jobId)`; `jobId` is 1 to 64 characters of
  `A-Z a-z 0-9 _ -`. `worldIdRequestConfig` and `signRpContext` reject any other action.
- Create each action in the portal, in the environment you will use. An action that exists only in staging is not
  found in production.
- One action per job gives one nullifier per person per job ([Nullifier scoping](#nullifier-scoping)).

### 3. Choose the signal

The signal is 64 lowercase hex characters the relying app binds the proof to: the evidence commitment, or a sha256 of
its own application record. `worldIdRequestConfig` rejects anything else. Pass the same value as `signal` to
`verifyWorldIdResult`, which compares `hashSignal(signal)` with each response's `signal_hash`. If `signal` is
omitted, that check is skipped, so always pass it.

### 4. Choose the environment

| `environment` | Proofs come from | Use |
| --- | --- | --- |
| `production` (default) | The World App | Real users |
| `staging` | The World ID Simulator (`https://simulator.worldcoin.org`) only | Development and tests |

Use the same value in `worldIdRequestConfig`, in `verifyWorldIdResult` and for the portal action.
`verifyWorldIdResult` returns `environment-mismatch` if the result is for another environment, and `rejected` if the
verify API answers for another environment.

### 5. World ID 4.0 only

- The request sets `allow_legacy_proofs: false` (`worldIdRequestConfig`).
- `verifyWorldIdResult` returns `malformed` for any `protocol_version` other than `4.0`.
- Both are checked in [`personhood.test.mjs`](../crops/personhood/personhood.test.mjs).

### 6. Keep the signing key on the server

Read the signing key from an environment variable or secret store on the backend and pass it to `signRpContext`. It
must never be in the client bundle, a response body or logs. Anyone holding it can create requests in the relying
app's name. If it leaks, rotate it in the portal.

### 7. Store nullifiers

`verifyWorldIdResult` returns `{ ok: true, nullifier, credential }`, with the nullifier as lowercase hex. The package
stores nothing. The backend should:

- store `(action, nullifier)` in its own database with a unique constraint, and treat a conflict as "already applied
  to this job";
- insert before accepting the application, so two parallel submissions cannot both pass;
- keep the nullifier private: not in the attestation (`createAttestation` accepts only
  `humanCheck: { credential, scope: "per-job" }`), not on Arkiv, not in logs, not sent to the client.

### 8. End to end

Backend, issuing a request context:

```js
import { jobAction, signRpContext } from '@tlsn-fork/personhood';

const action = jobAction(jobId);
const rpContext = signRpContext({
  rpId: process.env.WORLD_ID_RP_ID,                // any variable names; the package reads no environment
  action,
  signingKeyHex: process.env.WORLD_ID_SIGNING_KEY,
});
// return { action, rpContext } to the page
```

Page:

```js
import { worldIdRequest } from '@tlsn-fork/personhood/client';

const request = await worldIdRequest({ appId: 'app_…', action, signal: commitment, rpContext,
  environment: 'production' });
showQrOrLink(request.connectorURI);
const completion = await request.pollUntilCompletion();
if (completion.success) await sendToBackend(completion.result);   // unchanged
```

Backend, verifying:

```js
import { verifyWorldIdResult } from '@tlsn-fork/personhood';

const outcome = await verifyWorldIdResult(result, { rpId: process.env.WORLD_ID_RP_ID, action, signal: commitment,
  environment: 'production' });
if (!outcome.ok) return reject(outcome.reason);
await saveNullifierOrReject(action, outcome.nullifier);           // unique (action, nullifier)
const humanCheck = { credential: outcome.credential, scope: 'per-job' };   // optional, for createAttestation
```

`rp_context` expires (IDKit default: 300 seconds; `signRpContext` takes an optional `ttl`). Ask the backend for a new
one for each attempt.
