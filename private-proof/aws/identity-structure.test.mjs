import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectAwsIdentitySession } from './identity-structure.mjs';
import { fixtureNow } from './event-fixture.mjs';

import { identityFixture as fixture } from './identity-fixture.mjs';

const inspect = value => inspectAwsIdentitySession(value.receipt, value.expected, fixtureNow);
const reject = value => assert.throws(() => inspect(value), { message: 'AWS_PRIVATE_IDENTITY_INVALID' });

test('extracts only private IAM identity bindings and accounts for every native interval', () => {
  const input = fixture(), output = inspect(input);
  assert.deepEqual(Object.keys(output.bindings).sort(), ['Arn', 'CreateDate', 'Path', 'UserId', 'UserName']);
  assert.equal(output.obligations.filter(slot => slot.circuitId === 'header-v1').length, 3);
  assert.equal(output.obligations.filter(slot => slot.circuitId === 'aws-xml-text-v1').length, 6);
  assert.equal(output.obligations.length, input.receipt.results.filter(row => row.action.kind === 'HASH').length);
  assert.ok(!JSON.stringify(output).includes('AWS_PRIVATE') && !JSON.stringify(input.receipt).includes('111122223333'));
  assert.equal(output.accepted, undefined);
});

test('accepts reordered fields, XML declaration, reviewed content type and optional last-used date', () => {
  const input = fixture({ fields: { PasswordLastUsed: '2026-10-29T07:00:00Z' }, contentType: 'text/xml; charset=utf-8',
    mutateUser: user => user.split('\n').reverse().join('\n'), mutateXml: xml => '<?xml version="1.0" encoding="UTF-8"?>\n' + xml });
  assert.equal(inspect(input).bindings.PasswordLastUsed.length, 20);
});

test('only implicit self-GetUser can establish credential ownership', () => {
  for (const requestBody of ['Action=GetUser&UserName=someone&Version=2010-05-08', 'Action=GetCallerIdentity&Version=2011-06-15',
    'Action=GetUser&Version=2010-05-08&Action=GetUser', 'Action=GetUser&Version=2010-05-08 ']) reject(fixture({ requestBody }));
});

test('rejects visible identity values, missing fields and duplicate user fields', () => {
  for (const name of ['UserId', 'Path', 'UserName', 'Arn', 'CreateDate']) {
    reject(fixture({ visible: name })); reject(fixture({ fields: { [name]: undefined } }));
  }
  reject(fixture({ mutateUser: (user, hide) => user + `<UserId>${hide('AIDAOTHERIDENTITY0001')}</UserId>` }));
});

test('rejects nested unreviewed structures, attributes and element lookalikes', () => {
  reject(fixture({ mutateUser: user => user + '<Tags><member/></Tags>' }));
  reject(fixture({ mutateUser: user => user + '<PermissionsBoundary/>' }));
  reject(fixture({ mutateUser: user => user.replace('<UserId>', '<UserId ignored="x">') }));
  reject(fixture({ mutateUser: user => user.replaceAll('UserId', 'x:UserId') }));
});

test('rejects entities, declarations, comments, mixed content and trailing documents', () => {
  for (const mutateXml of [xml => '<!DOCTYPE User SYSTEM "file:///private">' + xml, xml => xml + '<other/>',
    xml => xml.replace('<User>', '<User>&amp;'), xml => xml.replace('<User>', '<User><!-- hidden -->'),
    xml => xml.replace('<User>', '<User>visible-text'), xml => xml.replace('https://iam.amazonaws.com/', 'https://attacker.invalid/')]) {
    reject(fixture({ mutateXml }));
  }
});

test('requires each complete private text to be one native interval', () => {
  reject(fixture({ mutateUser: (user, hide) => user.replace(/<UserId>.*?<\/UserId>/, `<UserId>${hide('AIDAEXAMPLE')}${hide('SYNTHETIC01')}</UserId>`) }));
  reject(fixture({ mutateXml: (xml, hide) => xml.replace('<User>', `<User>${hide(' ')}`) }));
});

test('rejects identity bounds before constructing circuit obligations', () => {
  for (const fields of [{ UserId: 'short' }, { UserId: 'x'.repeat(129) }, { UserName: 'x'.repeat(65) },
    { Arn: 'short' }, { Arn: 'x'.repeat(513) }, { Path: '' }]) reject(fixture({ fields }));
});

test('keeps hidden XML injection provisional until its lexical proof is checked', () => {
  const result = inspect(fixture({ fields: { Path: '/x</Path><UserId>attacker</UserId><Path>/' } }));
  assert.equal(result.obligations.find(slot => slot.hash === result.bindings.Path.hash).circuitId, 'aws-xml-text-v1');
  assert.equal(result.accepted, undefined);
});
