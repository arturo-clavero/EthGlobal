import { createHash } from 'node:crypto';
import { fixtureExpected } from './event-fixture.mjs';

// Synthetic native-shaped receipt; placeholders become distinct private commitments.
export function identityFixture(options = {}) {
  const expected = { ...fixtureExpected, step: 'identity' };
  const values = [], openings = new Map();
  const hide = value => `\x01${values.push(value) - 1}\x02`;
  const fields = { UserId: 'AIDAEXAMPLESYNTHETIC01', Path: '/engineering/', UserName: 'AWS_PRIVATE_USER_SENTINEL',
    Arn: 'arn:aws:iam::111122223333:user/engineering/AWS_PRIVATE_USER_SENTINEL', CreateDate: '2023-01-01T00:00:00Z' };
  Object.assign(fields, options.fields);
  let user = Object.entries(fields).filter(([, value]) => value !== undefined)
    .map(([name, value]) => `<${name}>${name === options.visible ? value : hide(value)}</${name}>`).join('\n');
  user = options.mutateUser?.(user, hide) ?? user;
  let xml = `<GetUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetUserResult><User>${user}</User></GetUserResult>` +
    `<ResponseMetadata><RequestId>${hide('synthetic-request-id')}</RequestId></ResponseMetadata></GetUserResponse>`;
  xml = options.mutateXml?.(xml, hide) ?? xml;
  const expand = value => value.replace(/\x01(\d+)\x02/g, (_, id) => values[Number(id)]);
  const requestBody = options.requestBody ?? 'Action=GetUser&Version=2010-05-08';
  const request = `POST / HTTP/1.1\r\nhost: iam.amazonaws.com\r\nconnection: close\r\naccept-encoding: identity\r\n` +
    `content-type: application/x-www-form-urlencoded\r\nx-16signals-nonce: ${expected.nonceMac}\r\n` +
    `authorization: ${hide('SYNTHETIC_PRIVATE_AUTH')}\r\nx-amz-date: ${hide('20261029T080000Z')}\r\n` +
    `x-amz-security-token: ${hide('SYNTHETIC_PRIVATE_TOKEN')}\r\ncontent-length: ${Buffer.byteLength(expand(requestBody))}\r\n\r\n${requestBody}`;
  const response = `HTTP/1.1 200 OK\r\ncontent-type: ${options.contentType ?? 'text/xml'}\r\nconnection: close\r\n` +
    `content-length: ${Buffer.byteLength(expand(xml))}\r\n\r\n${xml}`;
  const receipt = { server_name: 'iam.amazonaws.com', session: { id: expected.sessionId, proofId: expected.proofId,
    pluginSha256: expected.pluginSha256, nonceMac: expected.nonceMac, step: 'identity', method: 'AWS_ACCOUNT', mode: 'Proxy' },
    config: {}, results: [], transcript: {} };
  let salt = 0;
  for (const [direction, template] of [['sent', request], ['recv', response]]) {
    const ranges = [], parts = [];
    let cursor = 0, position = 0;
    const append = (bytes, hidden = false) => {
      if (!bytes.length) return;
      const handler = { type: direction.toUpperCase(), part: 'BODY', action: hidden ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' } };
      ranges.push({ start: position, end: position + bytes.length, handler });
      const preimage = hidden ? Buffer.concat([bytes, Buffer.alloc(16, ++salt)]) : undefined;
      const value = hidden ? createHash('sha256').update(preimage).digest('hex') : bytes.toString();
      if (hidden) openings.set(value, preimage);
      receipt.results.push({ ...handler, value });
      parts.push(hidden ? Buffer.alloc(bytes.length) : bytes); position += bytes.length;
    };
    for (const marker of template.matchAll(/\x01(\d+)\x02/g)) {
      append(Buffer.from(template.slice(cursor, marker.index)));
      append(Buffer.from(values[Number(marker[1])]), true); cursor = marker.index + marker[0].length;
    }
    append(Buffer.from(template.slice(cursor)));
    receipt.config[direction] = ranges;
    receipt.transcript[direction] = Buffer.concat(parts).toString();
    receipt.transcript[`${direction}_length`] = position;
  }
  return { receipt, expected, openings };
}
