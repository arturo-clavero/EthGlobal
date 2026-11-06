import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { BATCHES, localBatchBody, matchBatchBody, validatePolicy } from './policy.mjs';

const policy = { cutoff: 1704067200000, windowDays: 30 };
assert.deepEqual(BATCHES.map(batch => batch.groupIds.length), [4, 5, 5, 6, 3]);
assert.equal(new Set(BATCHES.flatMap(batch => batch.groupIds)).size, 23);
for (const batch of BATCHES) {
  const local = localBatchBody(batch.step, policy, 'sample-project', 'person@example.invalid');
  const body = { bytes: new TextEncoder().encode(local.text), privateRanges: [] };
  for (const range of local.privateRanges) {
    const { start, end } = range;
    body.privateRanges.push({ start, end, hash: createHash('sha256').update(body.bytes.subarray(start, end)).digest('hex') });
    body.bytes.fill(0, start, end);
  }
  const result = matchBatchBody(body, batch.step, policy);
  assert.equal(result.project.length, batch.groupIds.length * 2);
  assert.equal(result.email.length, batch.groupIds.length);
  assert(!new TextDecoder().decode(body.bytes).includes('sample-project'));
  assert(!new TextDecoder().decode(body.bytes).includes('person@example.invalid'));
  assert.throws(() => matchBatchBody(body, batch.step, { ...policy, windowDays: 7 }));
  const altered = structuredClone(body); altered.bytes[0] ^= 1;
  assert.throws(() => matchBatchBody(altered, batch.step, policy));
  const omitted = structuredClone(body); omitted.privateRanges.pop();
  assert.throws(() => matchBatchBody(omitted, batch.step, policy));
  const wrong = structuredClone(body); wrong.privateRanges[0].start++;
  assert.throws(() => matchBatchBody(wrong, batch.step, policy));
  const extra = structuredClone(body); extra.privateRanges.push(extra.privateRanges[0]);
  assert.throws(() => matchBatchBody(extra, batch.step, policy));
  const disclosed = structuredClone(body); disclosed.bytes[disclosed.privateRanges[0].start] = 65;
  assert.throws(() => matchBatchBody(disclosed, batch.step, policy));
}
for (const invalid of [null, {}, { ...policy, cutoff: NaN }, { ...policy, cutoff: 253402300800000 },
  { ...policy, cutoff: -1 }, { ...policy, windowDays: 14 }]) assert.throws(() => validatePolicy(invalid));
for (const [project, email] of [['short', 'a@b.invalid'], ['valid-project', 'service@p.iam.gserviceaccount.com'],
  ['valid-project', 'a"@b.invalid'], ['project\n', 'a@b.invalid']]) {
  assert.throws(() => localBatchBody('groups:0', policy, project, email));
}
assert.throws(() => localBatchBody('groups:5', policy, 'valid-project', 'a@b.invalid'));
console.log('Policy: all five fixed batches accepted; altered queries, policy, privacy slots and scope rejected.');
