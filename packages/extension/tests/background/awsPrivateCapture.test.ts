import { describe, it, expect, vi } from 'vitest';
import { readAwsPrivateCapture } from '../../src/background/awsPrivateCapture';
import { readConsoleCredentials } from '../../src/entries/Content/awsPrivateCredentials';
import type { GcpPrivateRoute } from '../../src/background/gcpPrivateCompletion';

const origin = 'https://111122223333-abcdefgh.ap-southeast-2.console.aws.amazon.com';
const credentials = () => ({ accessKeyId: 'ASIA' + 'A'.repeat(16), secretAccessKey: 's'.repeat(40),
  sessionToken: 't'.repeat(100), expiration: new Date(Date.now() + 3600000).toISOString() });
function fixture() {
  const route: GcpPrivateRoute = { tabId: 1, windowId: 7, createdAt: Date.now(), awsPrivate: true, pageProgress: true };
  const routes = new Map([['run', route]]);
  const header = { id: 'capture', url: origin + '/cloudtrailv2/tb/creds', method: 'POST', timestamp: Date.now(),
    requestHeaders: [{ name: 'Cookie', value: 'PRIVATE_COOKIE_SENTINEL' }, { name: 'Origin', value: origin }, { name: 'x-csrf-token', value: 'PRIVATE_CSRF_SENTINEL' }] };
  const window = { tabId: 9, headers: [header] };
  const sender = { id: 'extension', url: 'chrome-extension://extension/offscreen.html' };
  const message = { type: 'AWS_PRIVATE_CREDENTIALS', requestId: 'run', windowId: 7, captureId: 'capture' };
  const deps = { extensionId: sender.id, offscreenUrl: sender.url, now: Date.now,
    window: vi.fn((id: number) => id === 7 ? window : undefined),
    tab: vi.fn(async () => ({ url: origin + '/cloudtrailv2/home', windowId: 7 })),
    send: vi.fn(async (_tab: number, _message: unknown): Promise<unknown> => credentials()) };
  return { route, routes, header, window, sender, message, deps };
}
const error = { message: 'AWS_PRIVATE_COLLECTION_FAILED' };

describe('AWS managed-window credential route', () => {
  it('uses the captured top-level tab once and erases the intermediate credential response', async () => {
    const f = fixture(), value = credentials(); f.deps.send.mockResolvedValue(value);
    const result = await readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps);
    expect(result.accountId).toBe('111122223333'); expect(result.credentials.accessKeyId).toMatch(/^ASIA/);
    expect(Object.values(value).every(value => value === '')).toBe(true);
    expect(f.deps.send).toHaveBeenCalledWith(9, { type: 'AWS_PRIVATE_CONSOLE_CREDENTIALS', url: f.header.url, csrfToken: 'PRIVATE_CSRF_SENTINEL' });
    expect(JSON.stringify(result)).not.toContain('PRIVATE_COOKIE_SENTINEL');
    await expect(readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps)).rejects.toMatchObject(error);
    expect(f.deps.send).toHaveBeenCalledTimes(1);
  });
  it('refuses foreign senders, page callers, other providers, other windows and stale captures before fetch', async () => {
    const changes = [
      (f: ReturnType<typeof fixture>) => { f.sender.url = origin; },
      (f: ReturnType<typeof fixture>) => { Object.assign(f.sender, { tab: { id: 1 } }); },
      (f: ReturnType<typeof fixture>) => { f.route.gcpPrivate = true; },
      (f: ReturnType<typeof fixture>) => { f.message.windowId = 8; },
      (f: ReturnType<typeof fixture>) => { f.header.timestamp -= 120001; },
      (f: ReturnType<typeof fixture>) => { f.route.createdAt -= 13 * 60 * 1000; },
      (f: ReturnType<typeof fixture>) => { f.deps.tab.mockResolvedValue({ url: 'https://sentinel.invalid/', windowId: 7 }); },
    ];
    for (const change of changes) {
      const f = fixture(); change(f);
      await expect(readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps)).rejects.toMatchObject(error);
      expect(f.deps.send).not.toHaveBeenCalled();
    }
  });
  it('discards credentials when cancellation, account switching or window replacement races the response', async () => {
    for (const change of ['cancel', 'switch', 'window']) {
      const f = fixture(), value = credentials();
      f.deps.send.mockImplementation(async () => {
        if (change === 'cancel') f.routes.delete('run');
        if (change === 'switch') f.window.headers.push({ ...f.header, id: 'changed', requestHeaders: f.header.requestHeaders.map(row =>
          row.name === 'Cookie' ? { ...row, value: 'OTHER_SESSION' } : row) });
        if (change === 'window') f.deps.window.mockReturnValue({ ...f.window });
        return value;
      });
      await expect(readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps)).rejects.toMatchObject(error);
      expect(Object.values(value).every(value => value === '')).toBe(true);
    }
  });
});

describe('AWS isolated content credential fetch', () => {
  const sender = { id: 'extension', url: 'chrome-extension://extension/background.bundle.js' };
  const message = { type: 'AWS_PRIVATE_CONSOLE_CREDENTIALS', url: origin + '/cloudtrailv2/tb/creds', csrfToken: 'csrf' };
  const deps = () => ({ extensionId: sender.id, backgroundUrl: sender.url, origin, top: true,
    fetchAws: vi.fn(async () => new Response(JSON.stringify(credentials()))) as unknown as typeof fetch });
  it('uses same-origin cookies with a fixed endpoint and returns a closed credential shape', async () => {
    const d = deps(), result = await readConsoleCredentials(message, sender, d);
    expect(result.accessKeyId).toMatch(/^ASIA/);
    expect(d.fetchAws).toHaveBeenCalledWith(message.url, expect.objectContaining({ method: 'POST', credentials: 'include', mode: 'same-origin', redirect: 'error', cache: 'no-store', headers: { 'x-csrf-token': 'csrf' } }));
    expect(Object.keys(result).sort()).toEqual(['accessKeyId', 'expiration', 'secretAccessKey', 'sessionToken']);
  });
  it('refuses page/foreign senders, subframes, origin/path substitutions and header injection', async () => {
    for (const [m, s, overrides] of [
      [message, { ...sender, id: 'other' }, {}], [message, { ...sender, tab: {} }, {}],
      [message, sender, { top: false }], [message, sender, { origin: 'https://sentinel.invalid' }],
      [{ ...message, url: message.url + '?url=https://sentinel.invalid' }, sender, {}],
      [{ ...message, csrfToken: 'csrf\r\ninjected: value' }, sender, {}],
    ] as const) {
      const d = { ...deps(), ...overrides };
      await expect(readConsoleCredentials(m, s, d)).rejects.toMatchObject(error);
      expect(d.fetchAws).not.toHaveBeenCalled();
    }
  });
});
