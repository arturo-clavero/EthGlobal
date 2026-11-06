import { buildAwsRequest, AWS_EVENT_ID, AWS_LIMITS } from './request.mjs';
import { parseAwsIdentity } from './console-session.mjs';
import { validateAwsAttempt } from './authenticated-transcript.mjs';
import { parseJsonStructure } from '../gcp/json-structure.mjs';
import { planAwsSession } from './client-plan.mjs';

const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const fail = () => { throw new Error('AWS_PRIVATE_COLLECTION_FAILED'); };
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const hex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
const hash = async value => hex(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
const json = text => {
  const bytes = encoder.encode(text);
  try { parseJsonStructure(bytes); return JSON.parse(text); }
  finally { bytes.fill(0); }
};

/** Only temporary Console credentials, copied into a closed in-memory shape. */
export function awsPrivateCredentials(value, now = Date.now()) {
  const expiresAt = Date.parse(value?.expiration);
  if (!Number.isSafeInteger(now) || ['accessKeyId', 'secretAccessKey', 'sessionToken', 'expiration'].some(key => typeof value?.[key] !== 'string') ||
      !/^ASIA[A-Z0-9]{16}$/.test(value?.accessKeyId ?? '') ||
      !/^[A-Za-z0-9/+=]{40}$/.test(value?.secretAccessKey ?? '') ||
      !/^[A-Za-z0-9/+=]{16,8192}$/.test(value?.sessionToken ?? '') ||
      !Number.isSafeInteger(expiresAt) || expiresAt <= now + 60000 || expiresAt > now + 43200000) fail();
  return { accessKeyId: value.accessKeyId, secretAccessKey: value.secretAccessKey,
    sessionToken: value.sessionToken, expiration: value.expiration };
}

/** Fixed SigV4 read-request grammar, signed with the browser's WebCrypto. */
export async function signAwsPrivateRequest(options, credentials, { nonceMac, now = Date.now() }) {
  const keys = options?.kind === 'identity' ? ['kind'] : options?.kind === 'event' ? ['kind', 'eventId'] :
    ['kind', 'start', 'end', ...(options?.nextToken === undefined ? [] : ['nextToken'])];
  if (!exact(options, keys) || !['identity', 'event', 'discovery'].includes(options.kind) ||
      !/^[A-Za-z0-9_-]{43}$/.test(nonceMac ?? '')) fail();
  const copy = awsPrivateCredentials(credentials, now);
  const request = buildAwsRequest({ ...options, identityService: 'iam', source: 'iam.amazonaws.com' });
  // shortcut: one event per discovery page fits the existing 16 KiB private parser; widen only with a reviewed profile.
  if (options.kind === 'discovery') request.body = JSON.stringify({ ...JSON.parse(request.body), MaxResults: 1,
    LookupAttributes: [{ AttributeKey: 'EventName', AttributeValue: 'UpdateAssumeRolePolicy' }] });
  const service = options.kind === 'identity' ? 'iam' : 'cloudtrail';
  const date = new Date(now).toISOString().replace(/[:-]|\.\d{3}/g, '');
  const headers = { ...request.headers, host: new URL(request.url).hostname, 'x-amz-date': date,
    'x-amz-security-token': copy.sessionToken, 'x-16signals-nonce': nonceMac };
  const names = Object.keys(headers).sort(), signedHeaders = names.join(';');
  const scope = `${date.slice(0, 8)}/us-east-1/${service}/aws4_request`;
  let key = encoder.encode(`AWS4${copy.secretAccessKey}`);
  const hmac = async text => {
    const imported = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', imported, encoder.encode(text)));
  };
  try {
    const canonical = ['POST', '/', '', names.map(name => `${name}:${headers[name]}\n`).join(''), signedHeaders, await hash(request.body)].join('\n');
    for (const part of [date.slice(0, 8), 'us-east-1', service, 'aws4_request']) {
      const next = await hmac(part); key.fill(0); key = next;
    }
    const signature = await hmac(`AWS4-HMAC-SHA256\n${date}\n${scope}\n${await hash(canonical)}`);
    try { headers.authorization = `AWS4-HMAC-SHA256 Credential=${copy.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${hex(signature)}`; }
    finally { signature.fill(0); }
    return { ...request, headers: { ...headers, 'accept-encoding': 'identity', connection: 'close' } };
  } finally { key.fill(0); for (const name of Object.keys(copy)) copy[name] = ''; }
}

/** Bounded, cancellable browser fetch. No error body, redirect or cookie leaves this caller. */
export async function readAwsPrivateResponse(url, options, { fetchAws = fetch, signal, limit = 16384 } = {}) {
  let reader;
  const chunks = [];
  try {
    const response = await fetchAws(url, { ...options, redirect: 'error', cache: 'no-store',
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000) });
    if (!response.body) fail();
    reader = response.body.getReader();
    if (response.status !== 200 || response.redirected) fail();
    let length = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value); length += value.byteLength;
      if (length > limit) fail();
    }
    if (signal?.aborted) fail();
    const bytes = new Uint8Array(length);
    try {
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return decoder.decode(bytes);
    } finally { bytes.fill(0); }
  } catch { fail(); }
  finally { await reader?.cancel().catch(() => {}); reader?.releaseLock(); for (const chunk of chunks) chunk.fill(0); }
}

/** Local selection is provisional: only the two native transcripts and their ZK bundle establish a claim. */
export function createAwsLocalSession({ attempt, fetchAws = fetch, now = Date.now }) {
  validateAwsAttempt(attempt, now());
  attempt = { ...attempt };
  const controller = new AbortController();
  let credentials, used = false, closed = false;
  const clear = () => {
    closed = true; controller.abort(); clearTimeout(timer);
    if (credentials) for (const key of Object.keys(credentials)) credentials[key] = '';
    credentials = undefined;
  };
  const timer = setTimeout(clear, attempt.expiresAt - now());
  const check = () => { if (closed || controller.signal.aborted) fail(); validateAwsAttempt(attempt, now()); };
  const sign = async options => {
    check(); const signed = await signAwsPrivateRequest(options, credentials, { nonceMac: attempt.nonceMac, now: now() });
    check(); return signed;
  };
  return {
    clear,
    async prepare(capture) {
      try {
        check(); if (used) fail(); used = true;
        const accountId = capture?.accountId;
        credentials = awsPrivateCredentials(capture?.credentials, now());
        if (Date.parse(credentials.expiration) <= attempt.expiresAt ||
            (accountId !== undefined && !/^\d{12}$/.test(accountId))) fail();
        let calls = 0;
        const read = async options => {
          if (calls++ >= AWS_LIMITS.attempts) fail();
          if (calls > 1) await new Promise((resolve, reject) => {
            const abort = () => { clearTimeout(pause); reject(new Error('AWS_PRIVATE_COLLECTION_FAILED')); };
            const pause = setTimeout(() => { controller.signal.removeEventListener('abort', abort); resolve(); }, AWS_LIMITS.intervalMs);
            controller.signal.addEventListener('abort', abort, { once: true });
            if (controller.signal.aborted) abort();
          });
          const request = await sign(options);
          const body = await readAwsPrivateResponse(request.url, { method: request.method, headers: request.headers, body: request.body, credentials: 'omit' },
            { fetchAws, signal: controller.signal });
          check(); return body;
        };
        const identity = parseAwsIdentity(await read({ kind: 'identity' }), 'iam');
        if (accountId !== undefined && accountId !== identity.accountId) fail();
        const tokens = new Set(), end = Math.floor(attempt.issuedAt / 1000), start = end - 90 * 86400;
        let nextToken, selected;
        do {
          const page = json(await read({ kind: 'discovery', start, end, ...(nextToken ? { nextToken } : {}) }));
          if (!exact(page, ['Events', ...(page.NextToken === undefined ? [] : ['NextToken'])]) ||
              !Array.isArray(page.Events) || page.Events.length > 1) fail();
          for (const row of page.Events) {
            if (!row || typeof row.CloudTrailEvent !== 'string') fail();
            const event = json(row.CloudTrailEvent), actor = event.userIdentity;
            if (event.eventName !== 'UpdateAssumeRolePolicy' || event.eventSource !== 'iam.amazonaws.com' ||
                actor?.type !== 'IAMUser' || actor.principalId !== identity.principalId || actor.arn !== identity.arn ||
                actor.accountId !== identity.accountId || event.recipientAccountId !== identity.accountId) continue;
            const time = Date.parse(event.eventTime);
            if (!AWS_EVENT_ID.test(row.EventId ?? '') || row.EventId !== event.eventID ||
                !Number.isFinite(time) || time < attempt.issuedAt - 90 * 86400000 || time > attempt.issuedAt ||
                typeof row.EventTime !== 'number' || Math.abs(row.EventTime * 1000 - time) > 1) continue;
            const request = await sign({ kind: 'event', eventId: row.EventId });
            const body = JSON.stringify({ Events: [row] });
            const sent = encoder.encode(`POST / HTTP/1.1\r\n${Object.entries(request.headers).map(([key, value]) => `${key}: ${value}\r\n`).join('')}content-length: ${encoder.encode(request.body).length}\r\n\r\n${request.body}`);
            const recv = encoder.encode(`HTTP/1.1 200 OK\r\ncontent-type: application/x-amz-json-1.1\r\ncontent-length: ${encoder.encode(body).length}\r\n\r\n${body}`);
            try { planAwsSession({ step: 'E0', serverName: 'cloudtrail.us-east-1.amazonaws.com', nonceMac: attempt.nonceMac }, { sent, recv }); selected = row.EventId; }
            catch { /* Unsupported or failed events remain unavailable. */ }
            finally { sent.fill(0); recv.fill(0); }
          }
          nextToken = page.NextToken;
          if (nextToken !== undefined && (typeof nextToken !== 'string' || !nextToken || nextToken.length > 8192 || tokens.has(nextToken))) fail();
          if (nextToken) tokens.add(nextToken);
        } while (!selected && nextToken);
        if (!selected) fail();
        const requests = [await sign({ kind: 'identity' }), await sign({ kind: 'event', eventId: selected })];
        check(); return requests;
      } catch { fail(); }
      finally { clear(); }
    },
  };
}
