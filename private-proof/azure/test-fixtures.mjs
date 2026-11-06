import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { parseJsonStructure } from '../gcp/json-structure.mjs';

const uuid = digit => `${digit.repeat(8)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(12)}`;
export const expected = step => ({ sessionId: uuid('1'), proofId: uuid('2'), pluginSha256: 'a'.repeat(64),
  nonceMac: 'b'.repeat(43), step, cutoffMs: Date.parse('2026-10-31T00:00:00Z') });
const subscription = uuid('a'), correlation = uuid('b');
const projection = 'claims,eventDataId,eventName,eventTimestamp,operationId,operationName,status,correlationId,resourceId,subscriptionId';
export const tenant = () => ({ subscriptionId: subscription, tenantId: uuid('c'), state: 'Enabled' });
export const activity = () => ({ value: [{ claims: { privateEmployerKey: 'private-value', padding: 'x'.repeat(550) },
  eventDataId: uuid('d'), eventName: { value: 'EndRequest' }, eventTimestamp: '2026-10-29T12:00:00Z',
  operationId: uuid('e'), operationName: { value: 'Microsoft.Network/networkSecurityGroups/securityRules/write' },
  status: { value: 'Succeeded' }, correlationId: correlation,
  resourceId: `/subscriptions/${subscription}/resourceGroups/private/providers/Microsoft.Network/networkSecurityGroups/private/securityRules/private`,
  subscriptionId: subscription }] });

export function fixture(step, options = {}) {
  const context = options.context ?? expected(step), value = options.value ?? (step === 'tenant' ? tenant() : activity());
  const body = Buffer.from(JSON.stringify(value)), parsed = parseJsonStructure(body), holes = [];
  const hide = (node, chunks = false) => {
    const size = chunks ? 512 : node.end - node.start;
    for (let start = node.start; start < node.end; start += size) holes.push({ start, end: Math.min(start + size, node.end) });
  };
  const descend = node => {
    if (node.type === 'object') for (const entry of node.entries) descend(entry.value);
    else if (node.type === 'array') for (const item of node.items) descend(item);
    else hide(node);
  };
  if (step === 'tenant') for (const { key, value } of parsed.root.entries) {
    if (options.privateTenantExtra && key.value === options.privateTenantExtra) {
      hide(key);
      if (value.type === 'array') for (const node of value.items) hide(node);
      else hide(value);
    } else descend(value);
  }
  else {
    const rows = parsed.root.entries.find(entry => entry.key.value === 'value').value.items;
    for (const row of rows) for (const { key, value } of row.entries) {
      if (key.value === 'claims') hide(value, true); else descend(value);
    }
  }
  const url = new URL(`/subscriptions/${subscription}${step === 'tenant' ? '' : '/providers/Microsoft.Insights/eventtypes/management/values'}`, 'https://management.azure.com');
  url.searchParams.set('api-version', step === 'tenant' ? '2022-12-01' : '2015-04-01');
  if (step === 'activity') {
    url.searchParams.set('$filter', `eventTimestamp ge '${new Date(context.cutoffMs - 14 * 86400000).toISOString()}' and eventTimestamp le '${new Date(context.cutoffMs).toISOString()}' and correlationId eq '${correlation}'`);
    url.searchParams.set('$select', projection);
  }
  options.url?.(url);
  const target = url.pathname + url.search, secret = 'Bearer PRIVATE_CREDENTIAL';
  const sent = `GET ${target} HTTP/1.1\r\nHost: management.azure.com\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nx-azure-proof-nonce: ${context.nonceMac}\r\nx-azure-proof-step: ${step}\r\nAuthorization: ${secret}\r\n${options.requestExtra ?? ''}\r\n`;
  const sentHoles = [subscription, ...(step === 'activity' ? [correlation] : []), secret].map(value => {
    const start = sent.indexOf(value); assert.ok(start >= 0); return { start, end: start + value.length };
  });
  const reason = options.reason ?? 'OK', date = 'Sat, 31 Oct 2026 00:00:00 GMT';
  const additionalHeaders = Object.entries(options.responseHeaders ?? {}).map(([name, value]) => `${name}: ${value}\r\n`).join('');
  const prefix = `HTTP/1.1 200 ${reason}\r\nContent-Type: application/json; charset=utf-8\r\n${options.chunked ? 'Transfer-Encoding: chunked' : `Content-Length: ${body.length}`}\r\n${options.date ? `Date: ${date}\r\n` : ''}${additionalHeaders}${options.responseExtra ?? ''}\r\n`;
  const splitAt = options.splitAt?.(holes), split = Number.isInteger(splitAt);
  const chunkPrefix = options.chunked ? `${(split ? splitAt : body.length).toString(16)}\r\n` : '';
  const gap = split ? `\r\n${(body.length - splitAt).toString(16)}\r\n` : '';
  const wireBody = split ? body.subarray(0, splitAt) + gap + body.subarray(splitAt) : body;
  const recv = prefix + chunkPrefix + wireBody + (options.chunked ? '\r\n0\r\n\r\n' : '');
  const bodyStart = prefix.length + chunkPrefix.length;
  const recvHoles = holes.map(({ start, end }) => ({ start: start + bodyStart + (split && start >= splitAt ? gap.length : 0),
    end: end + bodyStart + (split && end > splitAt ? gap.length : 0) }));
  if (options.date) { const start = prefix.indexOf(date); recvHoles.push({ start, end: start + date.length }); }
  if (options.reason) recvHoles.push({ start: 13, end: 13 + reason.length });
  for (const [name, value] of Object.entries(options.responseHeaders ?? {})) {
    const start = prefix.indexOf(`${name}: ${value}\r\n`) + name.length + 2;
    recvHoles.push({ start, end: start + value.length });
  }
  const config = { sent: [], recv: [] }, results = [], transcript = {};
  for (const [direction, text, ranges] of [['sent', sent, sentHoles], ['recv', recv, recvHoles]]) {
    const bytes = Buffer.from(text), redacted = Buffer.from(bytes);
    let cursor = 0;
    const add = (start, end, hidden) => {
      if (start === end) return;
      const action = hidden ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' };
      const handler = { type: direction.toUpperCase(), part: 'BODY', action };
      config[direction].push({ start, end, handler });
      results.push({ ...handler, value: hidden ? createHash('sha256').update(bytes.subarray(start, end))
        .update(Buffer.alloc(16, results.length)).digest('hex') : bytes.subarray(start, end).toString() });
      if (hidden) redacted.fill(0, start, end);
    };
    for (const { start, end } of ranges.sort((a, b) => a.start - b.start)) { add(cursor, start, false); add(start, end, true); cursor = end; }
    add(cursor, bytes.length, false);
    transcript[direction] = redacted.toString(); transcript[`${direction}_length`] = bytes.length;
  }
  return { receipt: { server_name: 'management.azure.com', session: { id: context.sessionId, proofId: context.proofId,
    pluginSha256: context.pluginSha256, nonceMac: context.nonceMac, step, method: 'AZURE_WORK_PRIVATE', mode: 'Proxy' },
    config, results, transcript }, context, bodyStart, holes };
}
