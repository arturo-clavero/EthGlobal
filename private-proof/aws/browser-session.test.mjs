import test from 'node:test';
import assert from 'node:assert/strict';
import { awsPrivateCredentials, signAwsPrivateRequest, readAwsPrivateResponse, createAwsLocalSession } from './browser-session.mjs';
import { identityFixture } from './identity-fixture.mjs';
import { eventFixture, syntheticWitness } from './event-fixture.mjs';

const now = Date.UTC(2026, 9, 29, 8, 0, 0);
const credentials = () => ({ accessKeyId: 'ASIA' + 'A'.repeat(16), secretAccessKey: 's'.repeat(40),
  sessionToken: 't'.repeat(100), expiration: new Date(now + 3600000).toISOString() });
const attempt = () => ({ proofId: '22222222-2222-4222-8222-222222222222', pluginSha256: 'a'.repeat(64),
  nonceMac: 'n'.repeat(43), identityService: 'iam', region: 'us-east-1', issuedAt: now, expiresAt: now + 300000 });
const capture = () => ({ credentials: credentials(), accountId: '111122223333' });
const body = fixture => new TextDecoder().decode(syntheticWitness(fixture).recv).split('\r\n\r\n')[1];
const identity = () => body(identityFixture({ fields: { Path: '/', UserName: 'synthetic', Arn: 'arn:aws:iam::111122223333:user/synthetic' } }));
const event = options => body(eventFixture(options));
const failed = operation => assert.rejects(operation, { message: 'AWS_PRIVATE_COLLECTION_FAILED' });
const collector = fetchAws => createAwsLocalSession({ attempt: attempt(), fetchAws, now: () => now });

test('WebCrypto signatures match offline botocore IAM and CloudTrail vectors', async () => {
  // botocore SigV4Auth, frozen 2026-10-29T08:00:00Z, explicit synthetic credentials; no network.
  for (const [options, signature] of [
    [{ kind: 'identity' }, 'e1a7c3ecfa1375632f1436e5ef1a1ef060608970bd8773b5773407ca88d34deb'],
    [{ kind: 'event', eventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }, '4897e6c48f10b296a0859e959406f9b18905d51c3c4f9d1f9639eda88abad2ae'],
  ]) {
    const request = await signAwsPrivateRequest(options, credentials(), { nonceMac: 'n'.repeat(43), now });
    assert.ok(request.headers.authorization.endsWith(`Signature=${signature}`));
    assert.equal(request.headers['x-amz-date'], '20261029T080000Z');
    assert.equal(request.headers['x-16signals-nonce'], 'n'.repeat(43));
    assert.equal(request.headers['accept-encoding'], 'identity');
  }
});

test('fixed signer refuses arbitrary requests, permanent credentials, stale credentials and mutable inputs', async () => {
  for (const options of [{ kind: 'identity', url: 'https://sentinel.invalid/' }, { kind: 'identity', identityService: 'sts' },
    { kind: 'write' }, { kind: 'event', eventId: '../secret' }, { kind: 'discovery', start: 0, end: now / 1000 }]) {
    await assert.rejects(signAwsPrivateRequest(options, credentials(), { nonceMac: 'n'.repeat(43), now }));
  }
  for (const edit of [{ accessKeyId: 'AKIA' + 'A'.repeat(16) }, { expiration: new Date(now).toISOString() },
    { sessionToken: 'private\r\ninjected: value' }, { sessionToken: 1234567890123456 }, { secretAccessKey: '' }]) {
    assert.throws(() => awsPrivateCredentials({ ...credentials(), ...edit }, now));
  }
  const value = credentials();
  const pending = signAwsPrivateRequest({ kind: 'identity' }, value, { nonceMac: 'n'.repeat(43), now });
  value.secretAccessKey = 'x'.repeat(40); value.accessKeyId = 'ASIA' + 'B'.repeat(16);
  assert.ok((await pending).headers.authorization.endsWith('Signature=e1a7c3ecfa1375632f1436e5ef1a1ef060608970bd8773b5773407ca88d34deb'));
});

test('response reader bounds bytes, erases owned chunks and returns only fixed failures', async () => {
  for (const [status, count, succeeds] of [[200, 20, true], [200, 16385, false], [403, 20, false]]) {
    const chunk = new Uint8Array(count).fill(65);
    const fetchAws = async (_url, options) => {
      assert.equal(options.redirect, 'error'); assert.equal(options.cache, 'no-store');
      return new Response(new ReadableStream({ start(controller) { controller.enqueue(chunk); controller.close(); } }), { status });
    };
    const pending = readAwsPrivateResponse('https://iam.amazonaws.com/', {}, { fetchAws });
    if (succeeds) assert.equal(await pending, 'A'.repeat(count)); else await failed(pending);
    if (status === 200) assert.ok(chunk.every(value => value === 0));
  }
  await failed(readAwsPrivateResponse('https://iam.amazonaws.com/', {}, { fetchAws: async () => { throw new Error('PRIVATE_ERROR_SENTINEL'); } }));
});

test('local discovery emits only two signed native requests and consumes its session once', async () => {
  const calls = [];
  const local = collector(async (url, options) => {
    calls.push({ url, options });
    assert.equal(options.credentials, 'omit');
    return new Response(calls.length === 1 ? identity() : event());
  });
  const supplied = capture(), snapshot = structuredClone(supplied);
  const requests = await local.prepare(supplied);
  assert.deepEqual(supplied, snapshot, 'capture caller owns its source credentials');
  assert.deepEqual(requests.map(row => row.url), ['https://iam.amazonaws.com/', 'https://cloudtrail.us-east-1.amazonaws.com/']);
  assert.equal(JSON.parse(requests[1].body).LookupAttributes[0].AttributeKey, 'EventId');
  const query = JSON.parse(calls[1].options.body);
  assert.equal(query.MaxResults, 1);
  assert.deepEqual(query.LookupAttributes, [{ AttributeKey: 'EventName', AttributeValue: 'UpdateAssumeRolePolicy' }]);
  assert.doesNotMatch(JSON.stringify(requests), /AWS_PRIVATE_\w+_SENTINEL|AIDAEXAMPLESYNTHETIC01|111122223333|secretAccessKey|expiration/);
  await failed(local.prepare(capture())); assert.equal(calls.length, 2);
});

test('wrong account, wrong actor, denied events and dry runs never select evidence', async () => {
  for (const mutateEvent of [e => { e.userIdentity.principalId = 'OTHER'; }, e => { e.recipientAccountId = '999999999999'; },
    e => { e.errorCode = 'PRIVATE_ERROR_SENTINEL'; }, e => { e.requestParameters.dryRun = true; }]) {
    let calls = 0;
    const local = collector(async () => new Response(++calls === 1 ? identity() : event({ mutateEvent })));
    await failed(local.prepare(capture())); assert.equal(calls, 2);
  }
  let calls = 0;
  const local = collector(async () => { calls++; return new Response(identity()); });
  await failed(local.prepare({ ...capture(), accountId: '999999999999' })); assert.equal(calls, 1);
});

test('duplicate keys and looping pagination reject without a completed selection', async () => {
  for (const page of ['{"Events":[],"Events":[]}', '{"Events":[],"NextToken":"loop"}']) {
    let calls = 0;
    const local = collector(async () => new Response(++calls === 1 ? identity() : page));
    await failed(local.prepare(capture())); assert.ok(calls <= 3);
  }
});

test('account binding is snapshotted before asynchronous identity fetch', async () => {
  const supplied = { ...capture(), accountId: '999999999999' };
  const local = collector(async () => { supplied.accountId = '111122223333'; return new Response(identity()); });
  await failed(local.prepare(supplied));
});

test('cancellation and expiry settle a pending response without follow-up requests', async () => {
  for (const expired of [false, true]) {
    let clock = now, resume, started;
    const ready = new Promise(resolve => { started = resolve; });
    const local = createAwsLocalSession({ attempt: attempt(), now: () => clock, fetchAws: async () => {
      started(); return new Promise(resolve => { resume = resolve; });
    } });
    const pending = local.prepare(capture()); await ready;
    if (expired) clock += 300001; else local.clear();
    resume(new Response(identity())); await failed(pending);
  }
});
