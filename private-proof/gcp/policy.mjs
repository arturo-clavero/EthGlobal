import catalog from './generated/catalog.json' with { type: 'json' };

export const CATALOG_DIGEST = catalog.digest;
export const BATCHES = Object.freeze(catalog.batches.map(batch => Object.freeze({
  step: batch.step, groupIds: Object.freeze([...batch.groupIds]),
})));
const literals = new Map(catalog.literals.map(literal => [literal.name, literal.utf8]));
const fail = () => { throw new Error('GCP_PRIVATE_POLICY_INVALID'); };

export function validatePolicy(policy) {
  if (!policy || !Number.isSafeInteger(policy.cutoff) || policy.cutoff < 0 || policy.cutoff > 253402300799999 ||
      ![7, 30, 90].includes(policy.windowDays)) fail();
  return { cutoff: policy.cutoff, windowDays: policy.windowDays };
}

/** Constant authenticated bytes and private insertion roles in exact request order. */
export function batchPattern(step, policy) {
  validatePolicy(policy);
  const batch = BATCHES.find(batch => batch.step === step);
  if (!batch) fail();
  const start = new Date(policy.cutoff - policy.windowDays * 86400000).toISOString();
  const cutoff = new Date(policy.cutoff).toISOString();
  if (start.length !== 24 || cutoff.length !== 24) fail();
  const segments = [];
  for (const id of batch.groupIds) {
    const group = catalog.groups.find(group => group.id === id);
    segments.push(literals.get(group.multipartPrefix));
    const insertions = [{ field: 'project' }, { field: 'project' }, { field: 'email' }, start, cutoff];
    for (let index = 0; index < group.jsonChunks.length; index++) {
      segments.push(literals.get(group.jsonChunks[index]));
      if (index < insertions.length) segments.push(insertions[index]);
    }
    segments.push(literals.get(group.multipartSuffix));
  }
  segments.push(literals.get(catalog.batchSuffix));
  return segments;
}

/** Local-only construction. The returned text contains secrets and must never be sent to the verifier or the page. */
export function localBatchBody(step, policy, project, email) {
  if (typeof project !== 'string' || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(project) ||
      typeof email !== 'string' || email.length > 254 ||
      !/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(email) ||
      email.toLowerCase().endsWith('.gserviceaccount.com')) fail();
  let text = '';
  const privateRanges = [];
  for (const segment of batchPattern(step, policy)) {
    if (typeof segment === 'string') text += segment;
    else {
      const start = text.length;
      text += segment.field === 'project' ? project : email;
      privateRanges.push({ start, end: text.length, field: segment.field });
    }
  }
  return { text, privateRanges };
}

/** The body and slots must come from authenticatedTranscript + parseHttpStructure. */
export function matchBatchBody(body, step, policy) {
  if (!(body?.bytes instanceof Uint8Array) || !Array.isArray(body.privateRanges)) fail();
  const output = { project: [], email: [] };
  let cursor = 0, slotIndex = 0;
  for (const segment of batchPattern(step, policy)) {
    if (typeof segment === 'string') {
      for (let index = 0; index < segment.length; index++) {
        if (body.bytes[cursor++] !== segment.charCodeAt(index)) fail();
      }
    } else {
      const slot = body.privateRanges[slotIndex++];
      const min = segment.field === 'project' ? 6 : 1;
      const max = segment.field === 'project' ? 30 : 254;
      if (!slot || slot.start !== cursor || !Number.isSafeInteger(slot.end) ||
          slot.end - slot.start < min || slot.end - slot.start > max || slot.end > body.bytes.length ||
          typeof slot.hash !== 'string' || !/^[0-9a-f]{64}$/.test(slot.hash)) fail();
      while (cursor < slot.end) if (body.bytes[cursor++] !== 0) fail();
      output[segment.field].push({ ...slot });
    }
  }
  if (cursor !== body.bytes.length || slotIndex !== body.privateRanges.length) fail();
  return output;
}
