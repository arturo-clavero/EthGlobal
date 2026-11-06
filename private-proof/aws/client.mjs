import { validateAwsAttempt } from './authenticated-transcript.mjs';
import { planAwsSession } from './client-plan.mjs';
import { inspectAwsIdentityDirections } from './identity-structure.mjs';
import { inspectAwsEventDirections } from './event-structure.mjs';
import { assembleAwsBundleExpectations, validateAwsBundleShape, awsProofFields } from './verify-bundle.mjs';
import { awsCircuitInputs, eraseAwsInputs } from './circuit-inputs.mjs';

const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const fail = () => { throw new Error('AWS_PRIVATE_CLIENT_INVALID'); };
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

function matchSelections(actual, expected) {
  if (!Array.isArray(actual) || actual.length !== expected.length) fail();
  for (let index = 0; index < expected.length; index++) {
    const value = actual[index], target = expected[index], hash = target.handler.action.kind === 'HASH';
    if (!exact(value, ['start', 'end', 'handler']) || value.start !== target.start || value.end !== target.end ||
        !exact(value.handler, ['type', 'part', 'action']) || value.handler.type !== target.handler.type || value.handler.part !== 'BODY' ||
        !exact(value.handler.action, hash ? ['kind', 'algorithm'] : ['kind']) || value.handler.action.kind !== target.handler.action.kind ||
        (hash && value.handler.action.algorithm !== 'SHA256')) fail();
  }
}

async function prepare(witness, planned, openings, buffers, crypto) {
  const directions = {}, claims = [];
  for (const direction of ['sent', 'recv']) {
    const slots = planned.privateSlots[direction], candidates = witness.openings[direction];
    if (candidates.length !== slots.length) fail();
    const bytes = new Uint8Array(witness[direction]); buffers.push(bytes);
    const authenticated = [], used = new Set();
    for (const slot of slots) {
      const matches = candidates.filter(value => value.start === slot.start && value.end === slot.end);
      if (matches.length !== 1 || used.has(matches[0])) fail();
      const value = matches[0]; used.add(value);
      const preimage = new Uint8Array(slot.end - slot.start + 16); buffers.push(preimage);
      preimage.set(bytes.subarray(slot.start, slot.end)); preimage.set(value.blinder, preimage.length - 16);
      const digest = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', preimage)));
      if (digest !== hex(value.hash) || openings.has(digest)) fail();
      openings.set(digest, preimage);
      const accepted = { ...slot, hash: digest };
      if (slot.layer === 'event') {
        const encoded = decoder.decode(bytes.subarray(slot.start, slot.end));
        const decoded = encoder.encode(JSON.parse(`"${encoded}"`)); buffers.push(decoded);
        if (decoded.length !== slot.decodedLength || JSON.stringify(decoder.decode(decoded)).slice(1, -1) !== encoded) fail();
        const derived = new Uint8Array(decoded.length + 16); buffers.push(derived);
        derived.set(decoded); crypto.getRandomValues(derived.subarray(decoded.length));
        accepted.decodedHash = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', derived)));
        if (openings.has(accepted.decodedHash)) fail();
        openings.set(accepted.decodedHash, derived);
      }
      if (slot.layer) claims.push({ ...accepted });
      authenticated.push(accepted); bytes.fill(0, slot.start, slot.end);
    }
    directions[direction] = { bytes, privateRanges: authenticated };
  }
  return witness.step === 'identity' ? inspectAwsIdentityDirections(directions, witness) : inspectAwsEventDirections(directions, witness, claims);
}

/** Offscreen-owned client. The worker adapter must terminate CPU work on abort and settle its promise. */
export function createAwsPrivateClient({ attempt, proveCircuit, crypto = globalThis.crypto, now = Date.now }) {
  let context;
  try {
    validateAwsAttempt(attempt, now());
    if (typeof proveCircuit !== 'function' || !crypto?.subtle || !crypto?.getRandomValues) fail();
    context = Object.freeze(Object.fromEntries(['proofId', 'nonceMac', 'pluginSha256', 'identityService', 'region', 'issuedAt', 'expiresAt']
      .map(key => [key, attempt[key]])));
    attempt = undefined;
  } catch { fail(); }
  let consumed = false;
  const clear = () => { consumed = true; context = undefined; };
  const check = meta => {
    validateAwsAttempt(context, now());
    if (!meta || !uuid(meta.sessionId) || meta.proofId !== context.proofId || meta.nonceMac !== context.nonceMac) fail();
  };
  return {
    clear,
    getRevealPlan(meta, transcripts) {
      try { if (consumed) fail(); check(meta); return planAwsSession(meta, transcripts).plan; }
      catch { fail(); }
    },
    async prove(witnesses, signal) {
      const buffers = [], openings = new Map(), prepared = [], ids = new Set();
      try {
        if (consumed || !signal || signal.aborted || !Array.isArray(witnesses) || witnesses.length !== 2) fail();
        consumed = true;
        // Snapshot both witnesses before the first asynchronous hash; caller mutations cannot alter the plan.
        for (const [index, step] of ['identity', 'E0'].entries()) {
          const value = witnesses[index]; check(value);
          if (value.step !== step || ids.has(value.sessionId) || !exact(value.selections, ['sent', 'recv']) ||
              !exact(value.openings, ['sent', 'recv'])) fail();
          ids.add(value.sessionId);
          const witness = { sessionId: value.sessionId, serverName: value.serverName, step, proofId: value.proofId,
            nonceMac: value.nonceMac, openings: {} };
          for (const direction of ['sent', 'recv']) {
            if (!(value[direction] instanceof Uint8Array) || !value[direction].length || value[direction].length > 16384 ||
                !Array.isArray(value.openings[direction]) || value.openings[direction].length > 256) fail();
            witness[direction] = new Uint8Array(value[direction]); buffers.push(witness[direction]);
            witness.openings[direction] = value.openings[direction].map(opening => {
              if (!exact(opening, ['start', 'end', 'hash', 'blinder']) || !Number.isSafeInteger(opening.start) ||
                  !Number.isSafeInteger(opening.end) || opening.start < 0 || opening.end <= opening.start || opening.end > witness[direction].length ||
                  !(opening.hash instanceof Uint8Array) || opening.hash.length !== 32 ||
                  !(opening.blinder instanceof Uint8Array) || opening.blinder.length !== 16) fail();
              const hash = new Uint8Array(opening.hash), blinder = new Uint8Array(opening.blinder); buffers.push(hash, blinder);
              return { start: opening.start, end: opening.end, hash, blinder };
            });
          }
          const planned = planAwsSession(witness, witness);
          for (const direction of ['sent', 'recv']) matchSelections(value.selections[direction], planned.plan[`${direction}RangesWithHandlers`]);
          prepared.push({ witness, planned });
        }
        const inspections = [];
        for (const item of prepared) {
          if (signal.aborted) fail(); check(item.witness);
          inspections.push(await prepare(item.witness, item.planned, openings, buffers, crypto));
        }
        const targets = assembleAwsBundleExpectations(inspections[0], inspections[1], context.issuedAt);
        if (!targets.length || targets.length > 128) fail();
        const proofs = [];
        for (const target of targets) {
          if (signal.aborted) fail(); check(prepared[0].witness);
          const inputs = awsCircuitInputs(target, openings);
          try {
            const entry = await proveCircuit(target.circuitId, inputs, signal);
            const fields = awsProofFields(entry);
            if (signal.aborted || entry.circuitId !== target.circuitId || fields.length !== target.publicInputs.length ||
                fields.some((value, i) => value !== BigInt(target.publicInputs[i]))) fail();
            proofs.push(entry);
          } finally { eraseAwsInputs(inputs); }
        }
        check(prepared[0].witness);
        const bundle = { kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: [...ids], proofs };
        validateAwsBundleShape(bundle); return bundle;
      } catch { fail(); }
      finally { buffers.forEach(bytes => bytes.fill(0)); openings.clear(); clear(); }
    },
  };
}
