import assert from 'node:assert/strict';
import test from 'node:test';
import { identityFixture } from './identity-fixture.mjs';
import { eventFixture, syntheticWitness } from './event-fixture.mjs';
import { planAwsSession } from './client-plan.mjs';

const rejected = value => assert.throws(() => planAwsSession(value, value), { message: 'AWS_PRIVATE_CLIENT_INVALID' });

test('selects the exact native-shaped identity/event ranges without returning private values', () => {
  for (const fixture of [identityFixture(), eventFixture(), eventFixture({ chunked: true })]) {
    const witness = syntheticWitness(fixture), before = structuredClone(witness);
    const planned = planAwsSession(witness, witness);
    assert.deepEqual(planned.plan, { sentRangesWithHandlers: fixture.receipt.config.sent, recvRangesWithHandlers: fixture.receipt.config.recv });
    assert.deepEqual(witness, before, 'planning must not consume the native caller buffers');
    assert.doesNotMatch(JSON.stringify(planned), /AWS_PRIVATE_[A-Z_]+_SENTINEL|111122223333|AIDAEXAMPLESYNTHETIC01|SYNTHETIC_PRIVATE/);
  }
});

test('preserves byte offsets for UTF-8 and escaped nested values', () => {
  const fixture = eventFixture({ mutateEvent: event => { event.userAgent = '漢字 "quote" \\ slash /'; } });
  const witness = syntheticWitness(fixture), planned = planAwsSession(witness, witness);
  assert.deepEqual(planned.plan.recvRangesWithHandlers, fixture.receipt.config.recv);
  assert.ok(planned.privateSlots.recv.some(slot => slot.layer === 'event' && slot.decodedLength < slot.end - slot.start));
});

test('rejects unsupported semantics, actor/error shapes and XML before revealing any ranges', () => {
  for (const fixture of [
    eventFixture({ mutateEvent: event => { event.errorCode = 'PRIVATE_ERROR_SENTINEL'; } }),
    eventFixture({ mutateEvent: event => { event.userIdentity.type = 'AssumedRole'; } }),
    eventFixture({ mutateEvent: event => { event.requestParameters.dryRun = true; } }),
    eventFixture({ mutateEvent: event => { event.eventName = 'DeleteRole'; } }),
    identityFixture({ requestBody: 'Action=GetUser&UserName=other&Version=2010-05-08' }),
    identityFixture({ mutateUser: user => user + '<Tags><Tag>PRIVATE_TAG_SENTINEL</Tag></Tags>' }),
  ]) rejected(syntheticWitness(fixture));
});

test('rejects wrong hosts, methods, nonce, body limits and atoms crossing chunk framing', () => {
  for (const mutate of [w => { w.serverName = 'other.amazonaws.com'; }, w => { w.nonceMac = 'X'.repeat(43); },
    w => { w.step = 'other'; }, w => { w.sent[0] = 71; }, w => { w.recv = new Uint8Array(16385); }]) {
    const witness = syntheticWitness(eventFixture()); mutate(witness); rejected(witness);
  }
  const fixture = eventFixture(), split = syntheticWitness(fixture), raw = Buffer.from(split.recv);
  const bodyStart = raw.indexOf('\r\n\r\n') + 4, body = raw.subarray(bodyStart);
  const at = fixture.claims.find(slot => slot.direction === 'RECV').start - bodyStart + 1;
  const head = raw.subarray(0, bodyStart).toString().replace(/content-length: [0-9]+\r\n/, 'transfer-encoding: chunked\r\n');
  split.recv = Uint8Array.from(Buffer.concat([Buffer.from(head + at.toString(16) + '\r\n'), body.subarray(0, at),
    Buffer.from('\r\n' + (body.length - at).toString(16) + '\r\n'), body.subarray(at), Buffer.from('\r\n0\r\n\r\n')]));
  rejected(split);
  rejected(syntheticWitness(eventFixture({ mutateEvent: event => { event.userAgent = 'X'.repeat(513); } })));
});

test('handles formatted IAM XML without hiding container whitespace', () => {
  const fixture = identityFixture({ mutateXml: xml => xml.replace('<GetUserResult>', '\n<GetUserResult>\n').replace('</User>', '</User>\n') });
  const witness = syntheticWitness(fixture);
  assert.deepEqual(planAwsSession(witness, witness).plan.recvRangesWithHandlers, fixture.receipt.config.recv);
});

test('rejects duplicate decoded keys and noncanonical outer escape aliases', () => {
  for (const transform of [
    body => body.replace('"EventId":', '"EventId":"duplicate","EventId":'),
    body => {
      const outer = JSON.parse(body);
      outer.Events[0].CloudTrailEvent = outer.Events[0].CloudTrailEvent.replace('"eventID":', '"eventID":"duplicate","\\u0065ventID":');
      return JSON.stringify(outer);
    },
    body => body.replace('CloudTrailEvent":"{', 'CloudTrailEvent":"\\u007b'),
  ]) {
    const witness = syntheticWitness(eventFixture()), raw = Buffer.from(witness.recv), start = raw.indexOf('\r\n\r\n') + 4;
    const body = Buffer.from(transform(raw.subarray(start).toString()));
    const head = raw.subarray(0, start).toString().replace(/content-length: [0-9]+\r\n/, `content-length: ${body.length}\r\n`);
    witness.recv = Uint8Array.from(Buffer.concat([Buffer.from(head), body])); rejected(witness);
  }
});
