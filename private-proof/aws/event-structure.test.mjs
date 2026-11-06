import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectAwsEventSession } from './event-structure.mjs';
import { eventFixture, activityEventFixture, fixtureNow } from './event-fixture.mjs';

const inspect = fixture => inspectAwsEventSession(fixture.receipt, fixture.expected, fixture.claims, fixtureNow);
const rejects = fixture => assert.throws(() => inspect(fixture), { message: 'AWS_PRIVATE_EVENT_INVALID' });

test('maps every native range to one proof obligation and retains private joins', () => {
  const fixture = eventFixture(), result = inspect(fixture);
  const hashes = fixture.receipt.results.filter(row => row.action.kind === 'HASH').map(row => row.value);
  assert.equal(result.obligations.length, hashes.length);
  assert.deepEqual(new Set(result.obligations.map(slot => slot.hash)), new Set(hashes));
  assert.equal(result.obligations.filter(slot => slot.circuitId === 'header-v1').length, 5);
  assert.ok(result.obligations.some(slot => slot.circuitId === 'atom-v1'));
  assert.ok(result.obligations.some(slot => slot.circuitId === 'aws-escaped-atom-v1'));
  assert.equal(Object.keys(result.bindings).length, 10);
  assert.equal(result.accepted, undefined);
  for (const sentinel of ['AWS_PRIVATE', 'SYNTHETIC_PRIVATE', '111122223333', 'AIDAEXAMPLE', 'aaaaaaaa-aaaa']) {
    assert.ok(!JSON.stringify(result).includes(sentinel));
    assert.ok(!JSON.stringify(fixture.receipt).includes(sentinel));
  }
});

test('maps intact atom ranges through chunk framing and rejects split atoms', () => {
  const result = inspect(eventFixture({ chunked: true }));
  assert.equal(Object.keys(result.bindings).length, 10);
  rejects(eventFixture({ crossChunk: true }));
});

test('requires exact read-only lookup request shape and private event selection', () => {
  for (const mutateRequest of [request => { request.MaxResults = 2; }, request => { request.NextToken = 'page'; },
    request => { request.LookupAttributes[0].AttributeKey = 'EventSource'; },
    request => { request.LookupAttributes.push(request.LookupAttributes[0]); }]) rejects(eventFixture({ mutateRequest }));
  for (const startLine of ['GET / HTTP/1.1', 'POST /other HTTP/1.1']) rejects(eventFixture({ startLine }));
});

test('requires the authenticated HTTP request to carry the intended host, operation and nonce', () => {
  for (const [name, value] of [['host', 'attacker.invalid'], ['x-16signals-nonce', 'X'.repeat(43)],
    ['x-amz-target', 'DifferentOperation'], ['accept-encoding', 'gzip']]) {
    rejects(eventFixture({ mutateHeaders: headers => { headers.find(row => row[0] === name)[1] = value; } }));
  }
});

test('rejects visible, empty or missing credentials and duplicate request headers', () => {
  for (const mutateHeaders of [headers => { headers.find(row => row[0] === 'authorization')[2] = false; },
    headers => { headers.find(row => row[0] === 'authorization')[1] = ''; },
    headers => { headers.splice(headers.findIndex(row => row[0] === 'x-amz-security-token'), 1); },
    headers => { headers.push([...headers[0]]); }]) rejects(eventFixture({ mutateHeaders }));
});

test('hides each unknown response header, including duplicate private metadata', () => {
  assert.ok(inspect(eventFixture({ mutateHeaders: (_, headers) => { headers.push(['x-private', 'FIRST', true], ['x-private', 'SECOND', true]); } })));
  rejects(eventFixture({ mutateHeaders: (_, headers) => { headers.push(['x-private', 'EMPLOYER_PRIVATE', false]); } }));
  rejects(eventFixture({ mutateHeaders: (_, headers) => { headers.push(['content-type', 'application/x-amz-json-1.1']); } }));
});

test('a successful lookup cannot hide recorded errors, dry runs or addenda', () => {
  for (const mutateEvent of [event => { event.errorCode = 'AccessDenied'; }, event => { event.errorMessage = 'private'; },
    event => { event.errorCode = null; }, event => { event.addendum = {}; },
    event => { event.requestParameters.dryRun = true; }, event => { event.responseElements = {}; }]) rejects(eventFixture({ mutateEvent }));
  rejects(eventFixture({ statusLine: 'HTTP/1.1 403 Forbidden' }));
});

test('rejects wrong event semantics, absent required fields and mismatched outer metadata', () => {
  for (const mutateEvent of [event => { event.eventName = 'AttachRolePolicy'; }, event => { event.eventSource = 'ec2.amazonaws.com'; },
    event => { event.readOnly = true; }, event => { event.managementEvent = false; }, event => { event.awsRegion = 'us-west-2'; },
    event => { delete event.eventID; }, event => { delete event.responseElements; }, event => { event.eventVersion = '2.00'; },
    event => { event.eventVersion = 1.11; },
    event => { event.requestParameters.policyDocument = ''; }, event => { event.requestParameters.roleName = ''; }]) rejects(eventFixture({ mutateEvent }));
  rejects(eventFixture({ mutateRow: row => { row.EventName = 'AttachRolePolicy'; } }));
  rejects(eventFixture({ mutateRow: row => { row.ReadOnly = 'true'; } }));
});

test('rejects unsupported actor classes and delegation fields', () => {
  for (const mutateEvent of [event => { event.userIdentity.type = 'AssumedRole'; }, event => { event.userIdentity.type = 'Root'; },
    event => { event.userIdentity.invokedBy = 'service.amazonaws.com'; }, event => { event.userIdentity.onBehalfOf = {}; },
    event => { delete event.userIdentity.principalId; }]) rejects(eventFixture({ mutateEvent }));
});

test('does not release private actor, account, time or resource values as public literals', () => {
  for (const path of ['userIdentity.principalId', 'userIdentity.arn', 'recipientAccountId', 'eventTime', 'requestParameters.roleName']) {
    rejects(eventFixture({ publicEvent: [path] }));
  }
});

test('binds provisional atom claims to exact native direction, range, digest and consumption', () => {
  for (const mutate of [fixture => { fixture.claims[0].start++; }, fixture => { fixture.claims[0].hash = 'ef'.repeat(32); },
    fixture => { fixture.claims[0].direction = 'RECV'; }, fixture => { fixture.claims.pop(); },
    fixture => { fixture.claims.push({ ...fixture.claims[0] }); }, fixture => { fixture.claims[0].extra = 'private'; }]) {
    const fixture = eventFixture(); mutate(fixture); rejects(fixture);
  }
});

test('keeps wrong private actor/account values provisional until equality proofs verify', () => {
  const result = inspect(eventFixture({ mutateEvent: event => { event.userIdentity.accountId = '999988887777'; } }));
  assert.notEqual(result.bindings.actorAccount.hash, result.bindings.recipientAccount.hash);
  assert.equal(result.accepted, undefined);
});

test('additional activity predicates keep all private fields behind proof obligations', () => {
  for (const [activity, id] of [['lambda', 'lambda-configuration-update'], ['network', 'security-group-ingress']]) {
    const fixture = activityEventFixture(activity), result = inspect(fixture);
    assert.equal(result.activity, id);
    assert.equal(result.obligations.length, fixture.receipt.results.filter(row => row.action.kind === 'HASH').length);
    for (const sentinel of ['AWS_PRIVATE', 'sg-0123456789abcdef0', '192.0.2.0/24', '111122223333']) {
      assert.ok(!JSON.stringify(fixture.receipt).includes(sentinel));
      assert.ok(!JSON.stringify(result).includes(sentinel));
    }
  }
});

test('additional families reject failures, other actors, unknown fields and leaked configuration', () => {
  for (const activity of ['lambda', 'network']) for (const mutate of [
    event => { event.errorCode = 'AccessDenied'; }, event => { event.errorMessage = 'failed'; },
    event => { event.requestParameters.dryRun = true; }, event => { event.userIdentity.type = 'AssumedRole'; },
    event => { event.requestParameters.unreviewedField = 'private'; }, event => { event.readOnly = true; },
    event => { event.eventSource = 'iam.amazonaws.com'; },
  ]) rejects(activityEventFixture(activity, { mutateEvent: mutate }));
  rejects(activityEventFixture('network', { mutateEvent: event => { event.responseElements._return = false; } }));
  rejects(activityEventFixture('network', { mutateEvent: event => { event.requestParameters.ipPermissions.items = []; } }));
  rejects(activityEventFixture('lambda', { mutateEvent: event => { delete event.requestParameters.timeout; } }));
  rejects(activityEventFixture('lambda', { mutateEvent: event => { event.requestParameters.environment = { SECRET: 'private' }; } }));
  for (const path of ['requestParameters.functionName', 'requestParameters.timeout']) {
    rejects(activityEventFixture('lambda', { publicEvent: [path] }));
  }
  for (const path of ['requestParameters.groupId', 'requestParameters.ipPermissions.items.0.ipRanges.items.0.cidrIp',
    'responseElements.securityGroupRuleSet.items.0.cidrIpv4']) {
    rejects(activityEventFixture('network', { publicEvent: [path] }));
  }
});
