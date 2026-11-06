import { authenticatedAwsTranscript } from './authenticated-transcript.mjs';
import { inspectAwsIdentitySession } from './identity-structure.mjs';
import { inspectAwsEventSession } from './event-structure.mjs';

const COUNTS = Object.freeze({ 'header-v1': 33, 'atom-v1': 34, 'aws-xml-text-v1': 33,
  'aws-escaped-atom-v1': 67, 'aws-identity-link-v1': 264, 'aws-event-link-v1': 199,
  'headers-small-v1': 528, 'atoms-small-v1': 272, 'aws-escaped-atoms-small-v1': 536, 'aws-escaped-atom-small-v1': 67 });
const BATCHES = [['header-v1', 'headers-small-v1', 16], ['atom-v1', 'atoms-small-v1', 8],
  ['aws-escaped-atom-v1', 'aws-escaped-atoms-small-v1', 8]];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const fail = () => { throw new Error('AWS_PRIVATE_BUNDLE_INVALID'); };
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const bytes = hash => {
  if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) fail();
  return Array.from({ length: 32 }, (_, index) => parseInt(hash.slice(index * 2, index * 2 + 2), 16));
};
function fields(proof) {
  if (!exact(proof, ['circuitId', 'proof', 'publicInputs']) || !Object.hasOwn(COUNTS, proof.circuitId) ||
      typeof proof.proof !== 'string' || !proof.proof.length || proof.proof.length > 32768 || !BASE64.test(proof.proof) ||
      !Array.isArray(proof.publicInputs) || proof.publicInputs.length !== COUNTS[proof.circuitId]) fail();
  return Array.from(proof.publicInputs, value => {
    if (typeof value !== 'string' || !/^(?:0x[0-9a-f]{1,64}|0|[1-9][0-9]{0,19})$/.test(value)) fail();
    const number = BigInt(value);
    if (number > 0xffffffffffffffffn) fail();
    return number;
  });
}

export { fields as awsProofFields };

/** Wire preflight only; native delivery, ownership and replay gates remain caller duties. */
export function validateAwsBundleShape(bundle) {
  if (!exact(bundle, ['kind', 'version', 'sessionIds', 'proofs']) || bundle.kind !== 'AWS_PRIVATE_RESULT' || bundle.version !== 1 ||
      !Array.isArray(bundle.sessionIds) || bundle.sessionIds.length !== 2 ||
      Array.from(bundle.sessionIds).some(id => typeof id !== 'string' || !UUID.test(id)) ||
      new Set(bundle.sessionIds.map(id => id.toLowerCase())).size !== 2 ||
      !Array.isArray(bundle.proofs) || bundle.proofs.length < 2 || bundle.proofs.length > 128) fail();
  let size = JSON.stringify({ kind: bundle.kind, version: bundle.version, sessionIds: bundle.sessionIds, proofs: [] }).length;
  for (const proof of bundle.proofs) {
    fields(proof);
    size += JSON.stringify(proof).length + 1;
    if (size > 4 * 1024 * 1024) fail();
  }
}

/** Copy the closed public envelope before passing it across an extension boundary. */
export function sanitizeAwsPrivateResult(bundle) {
  validateAwsBundleShape(bundle);
  return { kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: [...bundle.sessionIds],
    proofs: bundle.proofs.map(({ circuitId, proof, publicInputs }) => ({ circuitId, proof, publicInputs: [...publicInputs] })) };
}

function relation(circuitId, slots, extra = []) {
  return { circuitId, publicInputs: [...slots.flatMap(slot => bytes(slot.hash)),
    ...slots.map(slot => slot.end - slot.start), ...extra] };
}

/** Shared with the local planner: every field comes from authenticated structure. */
export function assembleAwsBundleExpectations(identity, event, cutoffMs) {
  const i = identity.bindings, e = event.bindings;
  const result = [
    relation('aws-identity-link-v1', [i.UserId, i.Arn, i.Path, i.UserName, e.actorId, e.actorArn, e.actorAccount, e.recipientAccount]),
    relation('aws-event-link-v1', [e.requestEventId, e.outerEventId, e.eventId, e.outerTime, e.eventTime, e.roleName], [cutoffMs]),
  ];
  const obligations = [...identity.obligations, ...event.obligations], batched = new Set();
  // Identity-link authenticates these exact raw spans and proves stricter XML-safe grammars.
  const identityText = new Set([i.UserId.hash, i.Arn.hash, i.Path.hash, i.UserName.hash]);
  for (const [single, circuitId, count] of BATCHES) {
    const eligible = obligations.filter(slot => slot.circuitId === single && slot.length <= 64 &&
      (single !== 'aws-escaped-atom-v1' || slot.decodedLength <= 64));
    for (let start = 0; start < eligible.length; start += count) {
      const slots = eligible.slice(start, start + count);
      for (const slot of slots) batched.add(slot);
      if (single === 'aws-escaped-atom-v1' && slots.length < count) {
        for (const slot of slots) result.push({ circuitId: 'aws-escaped-atom-small-v1',
          publicInputs: [...bytes(slot.hash), slot.length, ...bytes(slot.decodedHash), slot.decodedLength, slot.kind] });
        continue;
      }
      while (slots.length < count) slots.push({ hash: '0'.repeat(64), length: 0, decodedHash: '0'.repeat(64), decodedLength: 0, kind: 0 });
      const publicInputs = [...slots.flatMap(slot => bytes(slot.hash)), ...slots.map(slot => slot.length)];
      if (single === 'aws-escaped-atom-v1') publicInputs.push(...slots.flatMap(slot => bytes(slot.decodedHash)), ...slots.map(slot => slot.decodedLength));
      if (single !== 'header-v1') publicInputs.push(...slots.map(slot => slot.kind));
      result.push({ circuitId, publicInputs });
    }
  }
  for (const slot of obligations) {
    if (batched.has(slot)) continue;
    if (slot.circuitId === 'aws-xml-text-v1' && identityText.has(slot.hash)) continue;
    const publicInputs = [...bytes(slot.hash), slot.length];
    if (slot.circuitId === 'atom-v1') publicInputs.push(slot.kind);
    if (slot.circuitId === 'aws-escaped-atom-v1') publicInputs.push(...bytes(slot.decodedHash), slot.decodedLength, slot.kind);
    if (publicInputs.length !== COUNTS[slot.circuitId]) fail();
    result.push({ circuitId: slot.circuitId, publicInputs });
  }
  return result;
}

/** Only a trusted pinned-key runtime may verify; sessions must come from the authenticated attempt ledger. */
export async function verifyAwsBundle({ sessions, bundle, runtime, now = Date.now() }) {
  try {
    validateAwsBundleShape(bundle);
    if (!Array.isArray(sessions) || sessions.length !== 2 || typeof runtime?.verify !== 'function') fail();
    const first = sessions[0]?.expected, native = new Map();
    for (const [index, step] of ['identity', 'E0'].entries()) {
      const session = sessions[index], expected = session?.expected;
      if (!expected || expected.step !== step || expected.sessionId !== bundle.sessionIds[index]) fail();
      for (const name of ['proofId', 'nonceMac', 'pluginSha256', 'issuedAt', 'expiresAt', 'identityService', 'region']) {
        if (expected[name] !== first[name]) fail();
      }
      const transcript = authenticatedAwsTranscript(session.receipt, expected, now);
      for (const [direction, value] of Object.entries(transcript)) {
        for (const range of value.privateRanges) {
          if (native.has(range.hash)) fail();
          native.set(range.hash, { ...range, direction: direction.toUpperCase(), index });
        }
      }
    }
    const claims = [], claimed = new Set();
    for (const entry of bundle.proofs) {
      const values = fields(entry);
      if (!['atom-v1', 'aws-escaped-atom-v1', 'atoms-small-v1', 'aws-escaped-atoms-small-v1', 'aws-escaped-atom-small-v1'].includes(entry.circuitId)) continue;
      const bridge = entry.circuitId.startsWith('aws-escaped-'), batch = ['atoms-small-v1', 'aws-escaped-atoms-small-v1'].includes(entry.circuitId);
      const limit = entry.circuitId.includes('-small-') ? 64n : 512n;
      const fieldHash = start => values.slice(start, start + 32).map(value => {
        if (value > 255n) fail();
        return value.toString(16).padStart(2, '0');
      }).join('');
      for (let index = 0; index < (batch ? 8 : 1); index++) {
        const length = values[batch ? 256 + index : 32];
        if (batch && length === 0n) continue;
        const hash = fieldHash(batch ? index * 32 : 0), slot = native.get(hash);
        const kind = values[batch ? (bridge ? 528 : 264) + index : bridge ? 66 : 33];
        const decodedLength = bridge ? values[batch ? 520 + index : 65] : 0n;
        if (!slot || slot.index !== 1 || BigInt(slot.end - slot.start) !== length || claimed.has(hash) ||
            length > limit || kind < 1n || kind > 5n) fail();
        if (bridge && (decodedLength < 1n || decodedLength > limit)) fail();
        claimed.add(hash);
        claims.push({ direction: slot.direction, start: slot.start, end: slot.end, hash,
          layer: bridge ? 'event' : 'outer', kind: Number(kind),
          ...(bridge ? { decodedHash: fieldHash(batch ? 264 + index * 32 : 33), decodedLength: Number(decodedLength) } : {}) });
      }
    }
    const identity = inspectAwsIdentitySession(sessions[0].receipt, first, now);
    const event = inspectAwsEventSession(sessions[1].receipt, sessions[1].expected, claims, now);
    const expected = assembleAwsBundleExpectations(identity, event, first.issuedAt);
    if (expected.length !== bundle.proofs.length) fail();
    for (let index = 0; index < expected.length; index++) {
      const proof = bundle.proofs[index], target = expected[index];
      const actual = fields(proof);
      if (proof.circuitId !== target.circuitId || actual.some((value, i) => value !== BigInt(target.publicInputs[i])) ||
          await runtime.verify(proof, target.publicInputs) !== true) fail();
    }
    return { taskType: 'iam-role-trust-update', attribution: 'iam-user', windowDays: 90 };
  } catch { throw new Error('AWS_PRIVATE_BUNDLE_INVALID'); }
}
