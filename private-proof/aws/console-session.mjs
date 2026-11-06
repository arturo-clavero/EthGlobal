export const AWS_CONSOLE_URL = 'https://ap-southeast-2.console.aws.amazon.com/cloudtrailv2/home?region=ap-southeast-2#/events';

// Accept only the read-only CloudTrail credential request from the managed extension window.
export function awsConsoleSession(request, now = Date.now()) {
  const match = /^https:\/\/(?:(\d{12})-([a-z0-9]{8})\.)?ap-southeast-2\.console\.aws\.amazon\.com\/cloudtrailv2\/tb\/creds$/.exec(request?.url ?? '');
  if (!match || request.method !== 'POST' || !Number.isFinite(request.timestamp) ||
      now - request.timestamp > 120000 || request.timestamp > now + 5000 || !Array.isArray(request.requestHeaders)) {
    throw new Error('AWS_CONSOLE_SESSION_INVALID');
  }
  const headers = {};
  for (const row of request.requestHeaders) {
    const name = String(row.name).toLowerCase();
    if (!['cookie', 'x-csrf-token', 'origin'].includes(name)) continue;
    if (Object.hasOwn(headers, name) || typeof row.value !== 'string' || !row.value ||
        row.value.length > (name === 'cookie' ? 16000 : 4096) || /[\r\n\0]/.test(row.value)) throw new Error('AWS_CONSOLE_SESSION_INVALID');
    headers[name] = row.value;
  }
  if (!headers.cookie || !headers['x-csrf-token'] || headers.origin !== request.url.slice(0, -'/cloudtrailv2/tb/creds'.length)) {
    throw new Error('AWS_CONSOLE_SESSION_INVALID');
  }
  return { url: request.url, headers, accountId: match[1] };
}

export function awsIdentityRequest(identityService = 'sts') {
  if (!['sts', 'iam'].includes(identityService)) throw new Error('AWS_IDENTITY_INVALID');
  return { url: identityService === 'iam' ? 'https://iam.amazonaws.com/' : 'https://sts.ap-southeast-2.amazonaws.com/',
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: identityService === 'iam' ? 'Action=GetUser&Version=2010-05-08' : 'Action=GetCallerIdentity&Version=2011-06-15',
    responseFormat: 'text' };
}

export function parseAwsIdentity(body, identityService = 'sts') {
  if (!['sts', 'iam'].includes(identityService) || typeof body !== 'string' || body.length > 16384 ||
      /<!|&|[^\t\r\n\x20-\x7e]/.test(body)) throw new Error('AWS_IDENTITY_INVALID');
  if (identityService === 'iam') {
    const result = /^\s*(?:<\?xml version="1\.0" encoding="UTF-8"\?>\s*)?<GetUserResponse xmlns="https:\/\/iam.amazonaws.com\/doc\/2010-05-08\/">\s*<GetUserResult>\s*<User>([\s\S]*?)<\/User>\s*<\/GetUserResult>\s*<ResponseMetadata>\s*<RequestId>[a-zA-Z0-9-]+<\/RequestId>\s*<\/ResponseMetadata>\s*<\/GetUserResponse>\s*$/.exec(body);
    if (!result) throw new Error('AWS_IDENTITY_INVALID');
    const fields = {};
    // shortcut: reject nested Tags/PermissionsBoundary; add schema-bound parsing when those users are supported.
    const residue = result[1].replace(/<(Arn|UserId|Path|UserName|CreateDate|PasswordLastUsed)>([^<>]+)<\/\1>/g, (_, key, value) => {
      if (Object.hasOwn(fields, key)) throw new Error('AWS_IDENTITY_INVALID');
      fields[key] = value; return '';
    });
    const account = /^arn:aws:iam::(\d{12}):user\//.exec(fields.Arn ?? '');
    if (residue.trim() || !account || !/^\w{16,128}$/.test(fields.UserId ?? '') ||
        !/^[\w+=,.@-]{1,64}$/.test(fields.UserName ?? '') || !/^\/(?:[\x21-\x7e]+\/)?$/.test(fields.Path ?? '') ||
        fields.Path.length > 512 || fields.Arn !== `arn:aws:iam::${account[1]}:user${fields.Path}${fields.UserName}` ||
        [fields.CreateDate, ...(fields.PasswordLastUsed ? [fields.PasswordLastUsed] : [])].some(value =>
          typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value) || !Number.isFinite(Date.parse(value)))) {
      throw new Error('AWS_IDENTITY_INVALID');
    }
    return { accountId: account[1], arn: fields.Arn, principalId: fields.UserId };
  }
  const result = /^\s*(?:<\?xml version="1\.0" encoding="UTF-8"\?>\s*)?<GetCallerIdentityResponse xmlns="https:\/\/sts.amazonaws.com\/doc\/2011-06-15\/">\s*<GetCallerIdentityResult>([\s\S]*?)<\/GetCallerIdentityResult>\s*<ResponseMetadata>\s*<RequestId>[a-zA-Z0-9-]+<\/RequestId>\s*<\/ResponseMetadata>\s*<\/GetCallerIdentityResponse>\s*$/.exec(body);
  if (!result) throw new Error('AWS_IDENTITY_INVALID');
  const fields = {};
  const residue = result[1].replace(/<(Arn|UserId|Account)>([^<>]+)<\/\1>/g, (_, key, value) => {
    if (Object.hasOwn(fields, key)) throw new Error('AWS_IDENTITY_INVALID');
    fields[key] = value; return '';
  });
  if (residue.trim() || Object.keys(fields).length !== 3 || !/^\d{12}$/.test(fields.Account) ||
      !new RegExp(`^arn:aws:(?:iam|sts)::${fields.Account}:[A-Za-z0-9+=,.@_:/-]+$`).test(fields.Arn) ||
      !/^[A-Za-z0-9+=,.@_:/-]{1,256}$/.test(fields.UserId)) throw new Error('AWS_IDENTITY_INVALID');
  return { accountId: fields.Account, arn: fields.Arn, principalId: fields.UserId };
}
