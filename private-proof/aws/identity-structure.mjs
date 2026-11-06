import { inspectAwsHttpSession, inspectAwsHttpDirections } from './http-session.mjs';

const decoder = new TextDecoder('utf-8', { fatal: true });
const fail = () => { throw new Error('AWS_PRIVATE_IDENTITY_INVALID'); };
const key = slot => `${slot.direction}:${slot.start}:${slot.end}:${slot.hash}`;

/** Fixed IAM self-GetUser XML profile, with every text leaf private.
 * XML lexical proofs and the identity/actor predicates remain required. Tags,
 * PermissionsBoundary, entities, attributes on fields and mixed content fail closed. */
export function inspectAwsIdentitySession(receipt, expected, now = Date.now()) {
  try { return inspectIdentity(inspectAwsHttpSession(receipt, expected, now), expected); }
  catch { fail(); }
}

/** Local grammar checks only; never substitute these for authenticated receipt ingestion. */
export function inspectAwsIdentityDirections(directions, expected) {
  try { return inspectIdentity(inspectAwsHttpDirections(directions, expected), expected); }
  catch { fail(); }
}

function inspectIdentity(http, expected) {
  try {
    if (expected?.step !== 'identity') fail();
    const { sent, recv, native, obligations } = http;
    if (sent.body.privateRanges.length || decoder.decode(sent.body.bytes) !== 'Action=GetUser&Version=2010-05-08') fail();
    const body = decoder.decode(recv.body.bytes);
    const document = /^[\t\r\n ]*(?:<\?xml version="1\.0" encoding="UTF-8"\?>[\t\r\n ]*)?<GetUserResponse xmlns="https:\/\/iam.amazonaws.com\/doc\/2010-05-08\/">[\t\r\n ]*<GetUserResult>[\t\r\n ]*<User>([\s\S]*?)<\/User>[\t\r\n ]*<\/GetUserResult>[\t\r\n ]*<ResponseMetadata>[\t\r\n ]*<RequestId>(\x00+)<\/RequestId>[\t\r\n ]*<\/ResponseMetadata>[\t\r\n ]*<\/GetUserResponse>[\t\r\n ]*$/d.exec(body);
    if (!document) fail();
    const used = new Set();
    const scalar = (start, end) => {
      const range = recv.body.privateRanges.find(range => range.start === start && range.end === end);
      if (!range || used.has(range.sourceIndex) || end - start > 512) fail();
      used.add(range.sourceIndex);
      const slot = native.get(key({ direction: 'RECV', start: range.wireStart, end: range.wireEnd, hash: range.hash }));
      if (!slot) fail();
      obligations.push({ circuitId: 'aws-xml-text-v1', ...slot });
      return slot;
    };
    const fields = {}, user = document[1], userStart = document.indices[1][0];
    const field = /<(Arn|UserId|Path|UserName|CreateDate|PasswordLastUsed)>(\x00+)<\/\1>/dgy;
    let position = 0;
    while (position < user.length) {
      position += /^[\t\r\n ]*/.exec(user.slice(position))[0].length;
      if (position === user.length) break;
      field.lastIndex = position;
      const match = field.exec(user);
      if (!match || Object.hasOwn(fields, match[1])) fail();
      fields[match[1]] = scalar(userStart + match.indices[2][0], userStart + match.indices[2][1]);
      position = field.lastIndex;
    }
    if (['Arn', 'UserId', 'Path', 'UserName', 'CreateDate'].some(name => !Object.hasOwn(fields, name))) fail();
    scalar(...document.indices[2]);
    if (fields.UserId.length < 16 || fields.UserId.length > 128 || fields.UserName.length > 64 ||
        fields.Arn.length < 32 || used.size !== recv.body.privateRanges.length ||
        obligations.length !== native.size || new Set(obligations.map(key)).size !== native.size) fail();
    return { obligations, bindings: fields };
  } catch { throw new Error('AWS_PRIVATE_IDENTITY_INVALID'); }
}
