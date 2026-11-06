import assert from 'node:assert/strict';
import test from 'node:test';
import { awsCredentialScanView } from './credential-scan-view.mjs';
import { identityFixture } from './identity-fixture.mjs';
import { eventFixture, fixtureNow } from './event-fixture.mjs';

function revealHeader(receipt, name, partial) {
  const offset = receipt.transcript.sent.indexOf(`${name}: `) + name.length + 2;
  const range = receipt.config.sent.find(range => range.start === offset);
  assert.equal(range?.handler.action.kind, 'HASH');
  const result = receipt.results.filter(result => result.type === 'SENT')[receipt.config.sent.indexOf(range)];
  const end = partial ? range.start + 1 : range.end;
  const reveal = { type: 'SENT', part: 'BODY', action: { kind: 'REVEAL' } };
  const ranges = [{ start: range.start, end, handler: reveal }];
  const results = [{ ...reveal, value: 'x'.repeat(end - range.start) }];
  if (partial) {
    ranges.push({ ...range, start: end });
    results.push(result);
  }
  receipt.config.sent.splice(receipt.config.sent.indexOf(range), 1, ...ranges);
  receipt.results.splice(receipt.results.indexOf(result), 1, ...results);
  receipt.transcript.sent = receipt.transcript.sent.slice(0, offset) + results[0].value + receipt.transcript.sent.slice(end);
}

for (const fixture of [identityFixture, eventFixture]) {
  test(`${fixture.name}: masks only fully hidden credential names without changing the native receipt`, () => {
    const { receipt, expected } = fixture(), before = structuredClone(receipt);
    const view = awsCredentialScanView(receipt, expected, fixtureNow);
    assert.deepEqual(receipt, before);
    assert.equal(view.transcript.recv, receipt.transcript.recv);
    assert.equal(view.transcript.sent, receipt.transcript.sent.replace(/authorization|x-amz-security-token/g, name => '\0'.repeat(name.length)));
    assert.deepEqual(view.results.filter(result => result.action.kind === 'HASH'), receipt.results.filter(result => result.action.kind === 'HASH'));
    for (const result of view.results.filter(result => result.action.kind === 'REVEAL')) {
      assert.doesNotMatch(result.value, /(?:authorization|x-amz-security-token):/);
    }
  });

  for (const name of ['authorization', 'x-amz-security-token']) {
    for (const partial of [false, true]) test(`${fixture.name}: preserves ${partial ? 'partly' : 'fully'} exposed ${name} for rejection`, () => {
      const { receipt, expected } = fixture();
      revealHeader(receipt, name, partial);
      const view = awsCredentialScanView(receipt, expected, fixtureNow);
      assert.ok(view.transcript.sent.includes(`${name}: x`));
      assert.ok(view.results.some(result => result.action.kind === 'REVEAL' && result.value.includes(`${name}: `)));
    });
  }

  test(`${fixture.name}: rejects stale and foreign receipts before masking`, () => {
    const { receipt, expected } = fixture();
    assert.throws(() => awsCredentialScanView(receipt, expected, expected.expiresAt), { message: 'AWS_PRIVATE_TRANSCRIPT_INVALID' });
    receipt.session.method = 'GCP_WORK';
    assert.throws(() => awsCredentialScanView(receipt, expected, fixtureNow), { message: 'AWS_PRIVATE_TRANSCRIPT_INVALID' });
  });
}
