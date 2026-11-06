import { parseHttpStructure } from '../gcp/http-structure.mjs';
import { parseJsonStructure } from '../gcp/json-structure.mjs';
import { inspectIdentityReceipt } from './identity-receipt.mjs';
import { inspectTenantReceipt, inspectActivityReceipt } from './source-receipt.mjs';
import { activityProofExpectations, headerProofExpectations } from './activity-bindings.mjs';
import { prepareClaimsChunks } from './claims-plan.mjs';
import { AZURE_ACTIVITY_PROFILES, validateAzureAttempt, sanitizeAzurePrivateResult, azureProofFields, eraseAzureInputs } from './browser-result.mjs';

const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const STEPS = ['identity', 'tenant', 'activity'];
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const actorKey = 'http://schemas.microsoft.com/identity/claims/objectidentifier';
const tenantKey = 'http://schemas.microsoft.com/identity/claims/tenantid';
const fail = () => { throw new Error('AZURE_PRIVATE_PLAN_INVALID'); };
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const digestBytes = value => Array.from({ length: 32 }, (_, i) => Number.parseInt(value.slice(i * 2, i * 2 + 2), 16));
const same = (a, b) => a.length === b.length && a.every((value, i) => value === b[i]);
const field = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
const expectation = (circuitId, hashes, suffix = []) => ({ circuitId,
  publicInputs: [...hashes.flatMap(digestBytes), ...suffix].map(field) });
const inspector = step => step === 'identity' ? inspectIdentityReceipt : step === 'tenant' ? inspectTenantReceipt : inspectActivityReceipt;

function context(meta, attempt) {
  const index = STEPS.indexOf(meta?.step);
  if (index < 0 || meta.proofId !== attempt.proofId || meta.nonceMac !== attempt.nonceMac ||
      typeof meta.sessionId !== 'string' || !UUID.test(meta.sessionId) ||
      meta.serverName !== (index ? 'management.azure.com' : 'graph.microsoft.com')) fail();
  return { ...attempt, sessionId: meta.sessionId, step: meta.step };
}

function localHttp(bytes, kind) {
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 16384) fail();
  // Only framing is read from the ASCII shadow. Every private opening uses original wire bytes.
  const shadow = Uint8Array.from(bytes, value => value > 127 ? 63 : value);
  let parsed;
  try {
    parsed = parseHttpStructure({ bytes: shadow, privateRanges: [] }, { kind });
    return { ...parsed, body: { ...parsed.body,
      bytes: Uint8Array.from(parsed.body.wireIndices, index => bytes[index]) } };
  } finally { shadow.fill(0); parsed?.body.bytes.fill(0); }
}

function localReceipt(meta, expected, transcripts, selections, hashes) {
  const config = {}, results = [], transcript = {};
  let index = 0;
  for (const direction of ['sent', 'recv']) {
    const bytes = transcripts[direction], shadow = Uint8Array.from(bytes);
    config[direction] = selections[direction];
    for (const range of selections[direction]) {
      const hidden = range.handler.action.kind === 'HASH';
      const value = hidden ? (hashes?.get(`${direction}:${range.start}:${range.end}`) ?? (++index).toString(16).padStart(64, '0'))
        : decoder.decode(bytes.subarray(range.start, range.end));
      results.push({ ...range.handler, value });
      if (hidden) shadow.fill(0, range.start, range.end);
    }
    transcript[direction] = decoder.decode(shadow); transcript[`${direction}_length`] = bytes.length;
    shadow.fill(0);
  }
  return { server_name: meta.serverName, session: { id: meta.sessionId, proofId: expected.proofId,
    pluginSha256: expected.pluginSha256, nonceMac: expected.nonceMac, step: meta.step,
    method: 'AZURE_WORK_PRIVATE', mode: 'Proxy' }, config, results, transcript };
}

/** Provisional local planning only. This synthetic receipt is never submitted as native evidence. */
export function planAzureSession(meta, transcripts, attempt) {
  return plan(meta, transcripts, attempt, true);
}

function plan(meta, transcripts, attempt, batchHeaders) {
  const expected = context(meta, attempt), privateSlots = { sent: [], recv: [] }, buffers = [];
  try {
    const sent = localHttp(transcripts.sent, 'request');
    buffers.push(sent.body.bytes);
    const recv = localHttp(transcripts.recv, 'response');
    buffers.push(recv.body.bytes);
    const hide = (direction, start, end, capacity = 2048) => {
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end <= start ||
          end > transcripts[direction].length) fail();
      for (let at = start; at < end; at += capacity) privateSlots[direction].push({ start: at, end: Math.min(at + capacity, end) });
    };
    // As in GCP: medium headers use existing 16-slot/64-byte batches.
    // Header grammar is bytewise, so adjacent independently opened chunks preserve it.
    const header = (direction, value) => {
      for (let index = value.start; index < value.end; index++) {
        const byte = transcripts[direction][index];
        if (!(byte === 9 || (byte >= 32 && byte <= 126))) fail();
      }
      hide(direction, value.start, value.end, batchHeaders && value.end - value.start <= 256 ? 64 : 2048);
    };
    for (const value of sent.headers) if (value.name === 'authorization') header('sent', value.value);
    if (meta.step === 'identity') {
      if (transcripts.recv.length > 1024) fail();
      hide('recv', 0, transcripts.recv.length, 1024);
    } else {
      const target = sent.startLine.target;
      for (const match of target.text.matchAll(/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}/gi)) {
        hide('sent', target.start + match.index, target.start + match.index + 36, 36);
      }
      if (recv.startLine.reason.text !== 'OK') header('recv', recv.startLine.reason);
      for (const value of recv.headers) {
        if (!['content-type', 'content-length', 'content-encoding', 'transfer-encoding'].includes(value.name)) {
          header('recv', value.value);
        }
      }
      const shadow = Uint8Array.from(recv.body.bytes, value => value > 127 ? 63 : value);
      buffers.push(shadow);
      const root = parseJsonStructure(shadow).root, wire = recv.body.wireIndices;
      const bodyRange = (node, chunks = false) => {
        if (node.end <= node.start || node.end - node.start > (chunks ? 2304 : 514)) fail();
        for (let i = node.start + 1; i < node.end; i++) if (wire[i] !== wire[i - 1] + 1) fail();
        hide('recv', wire[node.start], wire[node.end - 1] + 1, chunks ? 512 : node.end - node.start);
      };
      const walk = node => {
        if (node.type === 'object') for (const entry of node.entries) {
          if (meta.step === 'activity' && entry.key.value === 'claims') bodyRange(entry.value, true);
          else walk(entry.value);
        }
        else if (node.type === 'array') for (const item of node.items) walk(item);
        else bodyRange(node);
      };
      if (meta.step === 'tenant' && root.type === 'object') {
        const known = new Set(['id', 'subscriptionId', 'tenantId', 'state', 'displayName', 'authorizationSource', 'subscriptionPolicies', 'managedByTenants']);
        for (const entry of root.entries) {
          if (known.has(entry.key.value)) walk(entry.value);
          else {
            if (entry.key.end - entry.key.start > 64 || entry.value.type !== 'array' || entry.value.items.length !== 1 ||
                entry.value.items[0].type !== 'object' || entry.value.items[0].end - entry.value.items[0].start > 128) fail();
            bodyRange(entry.key); bodyRange(entry.value.items[0]);
          }
        }
      } else walk(root);
    }
    const selections = {};
    for (const direction of ['sent', 'recv']) {
      const ranges = [], slots = privateSlots[direction].sort((a, b) => a.start - b.start);
      let cursor = 0;
      const add = (start, end, hidden) => {
        if (start < end) ranges.push({ start, end, handler: { type: direction.toUpperCase(), part: 'BODY',
          action: hidden ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' } } });
      };
      for (const slot of slots) {
        if (slot.start < cursor) fail();
        add(cursor, slot.start, false); add(slot.start, slot.end, true); cursor = slot.end;
      }
      add(cursor, transcripts[direction].length, false);
      // Preserve supported transcripts when extra commitments exceed native range capacity.
      if (ranges.length > 256 && batchHeaders) return plan(meta, transcripts, attempt, false);
      if (!ranges.length || ranges.length > 256) fail(); selections[direction] = ranges;
    }
    const receipt = localReceipt(meta, expected, transcripts, selections);
    // Reject unknown headers/keys and unsupported coverage BEFORE native disclosure.
    const inspection = inspector(meta.step)(receipt, expected);
    return { plan: { sentRangesWithHandlers: selections.sent, recvRangesWithHandlers: selections.recv },
      selections, privateSlots, inspection };
  } catch { fail(); }
  finally { for (const bytes of buffers) bytes.fill(0); }
}

export function createAzurePrivatePlan({ attempt, proveCircuit, crypto = globalThis.crypto }) {
  validateAzureAttempt(attempt);
  if (typeof proveCircuit !== 'function' || !crypto?.subtle || !crypto?.getRandomValues) fail();
  attempt = Object.freeze({ ...attempt });
  let closed = false;
  const owned = [], claimsPlans = [];
  const keep = value => { owned.push(value); return value; };
  const clear = () => { closed = true; for (const plan of claimsPlans) plan.clear();
    for (const value of owned) eraseAzureInputs(value); owned.length = 0; claimsPlans.length = 0; };
  return {
    clear,
    getRevealPlan(meta, transcripts) { if (closed) fail(); validateAzureAttempt(attempt); return planAzureSession(meta, transcripts, attempt).plan; },
    async prove(witnesses, signal) {
      if (closed) fail(); closed = true;
      try {
        validateAzureAttempt(attempt);
        if (!signal || signal.aborted || !Array.isArray(witnesses) || witnesses.length !== 3) fail();
        const entries = new Map(), sessions = [], seenIds = new Set();
        const remember = (hash, bytes, blinder) => { if (entries.has(hash)) fail(); entries.set(hash, { bytes, blinder }); };
        for (const [i, witness] of witnesses.entries()) {
          if (witness.step !== STEPS[i] || seenIds.has(witness.sessionId.toLowerCase())) fail();
          seenIds.add(witness.sessionId.toLowerCase());
          const expected = context(witness, attempt), planned = planAzureSession(witness, witness, attempt), hashes = new Map();
          for (const direction of ['sent', 'recv']) {
            if (JSON.stringify(witness.selections?.[direction]) !== JSON.stringify(planned.selections[direction])) fail();
            const openings = witness.openings?.[direction], slots = planned.privateSlots[direction];
            if (!Array.isArray(openings) || openings.length !== slots.length) fail();
            for (const slot of slots) {
              const matching = openings.filter(value => value.start === slot.start && value.end === slot.end);
              if (matching.length !== 1) fail();
              const opening = matching[0];
              if (!(opening.hash instanceof Uint8Array) || opening.hash.length !== 32 ||
                  !(opening.blinder instanceof Uint8Array) || opening.blinder.length !== 16) fail();
              const bytes = witness[direction].subarray(slot.start, slot.end), preimage = new Uint8Array(bytes.length + 16);
              preimage.set(bytes); preimage.set(opening.blinder, bytes.length);
              let actual;
              try { actual = new Uint8Array(await crypto.subtle.digest('SHA-256', preimage)); }
              finally { preimage.fill(0); }
              if (!same(actual, opening.hash)) fail();
              const hash = hex(actual); hashes.set(`${direction}:${slot.start}:${slot.end}`, hash);
              remember(hash, bytes, opening.blinder);
            }
          }
          const receipt = localReceipt(witness, expected, witness, planned.selections, hashes);
          sessions.push({ witness, expected, inspection: inspector(witness.step)(receipt, expected) });
        }
        const opening = (hash, capacity) => {
          const value = entries.get(hash);
          if (!value || value.bytes.length > capacity) fail();
          const result = keep(Array(capacity + 16).fill(0));
          result.splice(0, value.bytes.length, ...value.bytes); result.splice(value.bytes.length, 16, ...value.blinder);
          return result;
        };
        const seal = async bytes => {
          const blinder = keep(crypto.getRandomValues(new Uint8Array(16))), input = keep(new Uint8Array(bytes.length + 16));
          input.set(bytes); input.set(blinder, bytes.length);
          const hash = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', input)));
          remember(hash, bytes, blinder); return hash;
        };
        const graphHttp = localHttp(witnesses[0].recv, 'response'); owned.push(graphHttp.body.bytes);
        const graphActor = JSON.parse(decoder.decode(graphHttp.body.bytes)).id;
        if (typeof graphActor !== 'string' || !UUID.test(graphActor) || graphActor !== graphActor.toLowerCase()) fail();
        const graphActorHash = await seal(keep(encoder.encode(JSON.stringify(graphActor))));
        const salt = keep(Array.from(crypto.getRandomValues(new Uint8Array(32))));
        const bindingBytes = keep(Uint8Array.from([...encoder.encode('azure-identity-v1'), ...digestBytes(attempt.challenge), ...salt, ...encoder.encode(graphActor)]));
        const identityBinding = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bindingBytes)));
        const activity = sessions[2].inspection, tenant = sessions[1].inspection;
        const claimBindings = [], claimJobs = new Map();
        for (const row of activity.body.rows) {
          const chunks = row.claims.chunks.map(ref => witnesses[2].openings.recv.find(value => value.start === ref.start && value.end === ref.end));
          const plan = await prepareClaimsChunks(witnesses[2].recv.subarray(row.claims.start, row.claims.end), chunks, { start: row.claims.start, crypto });
          claimsPlans.push(plan);
          for (const identity of plan.identities) remember(hex(identity.hash), keep(Uint8Array.from(identity.preimage.slice(0, 38))), keep(Uint8Array.from(identity.preimage.slice(38, 54))));
          for (const chunk of plan.chunks) claimJobs.set(chunk.publicInputs.join(','), chunk.inputs);
          claimBindings.push({ stateHashes: [hex(plan.chunks[0].inputs.hashes[1]), ...plan.chunks.map(value => hex(value.inputs.hashes[2]))],
            identityHashes: plan.identities.map(value => hex(value.hash)) });
        }
        const text = ref => JSON.parse(decoder.decode(witnesses[2].recv.subarray(ref.start, ref.end)));
        const tenantId = JSON.parse(decoder.decode(witnesses[1].recv.subarray(tenant.body.tenant.start, tenant.body.tenant.end))).toLowerCase();
        const subscriptionId = JSON.parse(decoder.decode(witnesses[1].recv.subarray(tenant.body.subscription.start, tenant.body.subscription.end))).toLowerCase();
        let selectedRow = -1, claim;
        // Preserve the rule profile preference when one correlation contains both supported types.
        for (const [candidateClaim, profile] of Object.entries(AZURE_ACTIVITY_PROFILES)) {
          selectedRow = activity.body.rows.findIndex((row, index) => {
            const claims = JSON.parse(decoder.decode(witnesses[2].recv.subarray(row.claims.start, row.claims.end)));
            const operation = text(row.operation), time = Date.parse(text(row.timestamp));
            return text(row.event) === 'EndRequest' && text(row.status) === 'Succeeded' &&
              profile.operations.some(expected => operation === expected || (profile.code !== undefined &&
                /^[\x20-\x7e]+$/.test(operation) && operation.toLowerCase() === expected.toLowerCase())) &&
              typeof claims[actorKey] === 'string' && claims[actorKey].toLowerCase() === graphActor &&
              typeof claims[tenantKey] === 'string' && claims[tenantKey].toLowerCase() === tenantId &&
              text(row.subscription).toLowerCase() === subscriptionId && time <= attempt.cutoffMs && time >= attempt.cutoffMs - 14 * 86400000 &&
              index < claimBindings.length;
          });
          if (selectedRow >= 0) { claim = candidateClaim; break; }
        }
        if (selectedRow < 0) fail();
        const bindings = { graphActorHash, identityBinding, selectedRow, claims: claimBindings };
        const identity = sessions[0].inspection;
        const expected = [expectation('identity-v1', [identity.responseHash], [identity.responseLength, ...digestBytes(attempt.challenge), ...digestBytes(identityBinding)]),
          ...headerProofExpectations(identity.headerObligations),
          ...activityProofExpectations(tenant, activity, attempt, bindings, claim).proofs];
        if (expected.length > 128) fail();
        const proofs = [];
        for (const required of expected) {
          if (signal.aborted) fail(); validateAzureAttempt(attempt);
          const values = required.publicInputs.map(value => Number(BigInt(value)));
          const hash = offset => hex(values.slice(offset, offset + 32));
          let inputs;
          if (required.circuitId === 'identity-v1') inputs = { response_hash: values.slice(0, 32), response_length: values[32],
            challenge: values.slice(33, 65), identity_binding: values.slice(65, 97), response_preimage: opening(hash(0), 1024), salt };
          else if (required.circuitId === 'header-v1' || required.circuitId === 'atom-v1') inputs = {
            commitment: values.slice(0, 32), length: values[32], preimage: opening(hash(0), required.circuitId === 'header-v1' ? 2048 : 512) };
          else if (required.circuitId === 'request-uuid-v1') inputs = { hashes: [values.slice(0, 32), values.slice(32, 64)],
            request_preimage: opening(hash(0), 36), reference_preimage: opening(hash(32), 38) };
          else if (required.circuitId === 'tenant-extra-v1') inputs = { hashes: [values.slice(0, 32), values.slice(32, 64)],
            lengths: values.slice(64, 66), key_preimage: opening(hash(0), 64), object_preimage: opening(hash(32), 128) };
          else if (required.circuitId === 'atoms-small-v1') inputs = {
            hashes: Array.from({ length: 8 }, (_, i) => values.slice(i * 32, i * 32 + 32)),
            lengths: values.slice(256, 264), kinds: values.slice(264, 272),
            preimages: Array.from({ length: 8 }, (_, i) => values[256 + i] ? opening(hash(i * 32), 64) : keep(Array(80).fill(0))) };
          else if (required.circuitId === 'headers-small-v1') inputs = {
            hashes: Array.from({ length: 16 }, (_, i) => values.slice(i * 32, i * 32 + 32)), lengths: values.slice(512, 528),
            preimages: Array.from({ length: 16 }, (_, i) => values[512 + i] ? opening(hash(i * 32), 64) : keep(Array(80).fill(0))) };
          else if (required.circuitId === 'subscription-state-v1') inputs = { hash: values, preimage: opening(hash(0), 9) };
          else if (required.circuitId === 'identity-link-v1') inputs = { actor_hash: values.slice(0, 32), challenge: values.slice(32, 64),
            identity_binding: values.slice(64, 96), actor_preimage: opening(hash(0), 38), salt };
          else if (required.circuitId === 'claims-chunk-v1') inputs = claimJobs.get(required.publicInputs.join(','));
          else if (required.circuitId === 'scope-link-v1') inputs = { hashes: Array.from({ length: 6 }, (_, i) => values.slice(i * 32, i * 32 + 32)),
            preimages: Array.from({ length: 6 }, (_, i) => opening(hash(i * 32), 38)) };
          else if (required.circuitId === AZURE_ACTIVITY_PROFILES[claim].circuitId) {
            const rows = [0, 1].map(row => Array.from({ length: 11 }, (_, i) => values.slice((row * 11 + i) * 32, (row * 11 + i + 1) * 32)));
            inputs = { hashes: rows, lengths: [values.slice(704, 709), values.slice(709, 714)], cutoff_ms: values[714],
              ...(required.circuitId === 'catalog-activity-atoms-v1' ? { profile_code: values[715] } : {}),
              ids: rows.map(row => row.slice(0, 6).map(value => opening(hex(value), 38))) };
            for (const [i, key, cap] of [[6, 'event', 32], [7, 'operation', 96], [8, 'status', 32], [9, 'timestamp', 32], [10, 'resource', 514]]) {
              inputs[key] = rows.map(row => opening(hex(row[i]), cap));
            }
          } else fail();
          if (!inputs) fail();
          const entry = await proveCircuit(required.circuitId, inputs, signal, expected.length);
          if (entry?.circuitId !== required.circuitId || !same(azureProofFields(entry), required.publicInputs.map(BigInt))) fail();
          proofs.push(entry);
        }
        return sanitizeAzurePrivateResult({ kind: 'AZURE_PRIVATE_RESULT', version: 1, claim,
          sessionIds: witnesses.map(value => value.sessionId), bindings, proofs });
      } catch { fail(); }
      finally { clear(); }
    },
  };
}
