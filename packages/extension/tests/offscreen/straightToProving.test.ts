/**
 * Straight to proving for auto-approved runs.
 * Pins the chain that makes
 * the trusted plugins on the embedding pages prove without any screen, and keeps every other
 * caller on the stock review:
 *
 *   RUN_BUILTIN → autoApprovalFor() (the one decision: top-frame product
 *   origin + built-in plugin + checked values, in the background) →
 *   'all-session' → Background sets sessionData._approvalMode AFTER the page's
 *   keys → SessionManager.onProve skips the reveal review for 'all-session'
 *   only. Every other caller is refused outright (no run at all);
 *   the review itself stays in SessionManager for any non-'all-session' run.
 *
 * What is revealed does not depend on the mode: the same ranges go to
 * sendRevealConfig()/reveal() whether the review was shown or skipped, and the
 * plugin permission check still refuses a request outside the plugin's config.
 */
/* eslint-disable @typescript-eslint/no-explicit-any -- loose mocks of Host and ProveManager */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const pm = vi.hoisted(() => ({
  createProver: vi.fn(),
  setProgressCallbackForProver: vi.fn(),
  sendRequest: vi.fn(),
  computeReveal: vi.fn(),
  getSentBytes: vi.fn(),
  getRecvBytes: vi.fn(),
  sendRevealConfig: vi.fn(),
  reveal: vi.fn(),
  getResponse: vi.fn(),
  cleanupProver: vi.fn(),
}));
const hosts = vi.hoisted(() => [] as Array<{ opts: any; registerRevealApproval: any }>);

vi.mock('../../src/offscreen/ProveManager', () => ({
  ProveManager: class {
    init = vi.fn().mockResolvedValue(undefined);
    createProver = pm.createProver;
    setProgressCallbackForProver = pm.setProgressCallbackForProver;
    sendRequest = pm.sendRequest;
    computeReveal = pm.computeReveal;
    getSentBytes = pm.getSentBytes;
    getRecvBytes = pm.getRecvBytes;
    sendRevealConfig = pm.sendRevealConfig;
    reveal = pm.reveal;
    getResponse = pm.getResponse;
    cleanupProver = pm.cleanupProver;
  },
}));

vi.mock('@tlsn/plugin-sdk', () => ({
  default: class {
    opts: any;
    // The review screen: resolves only when the human approves.
    registerRevealApproval = vi.fn();
    constructor(opts: any) {
      this.opts = opts;
      hosts.push(this);
    }
  },
  canonicalizeHandler: (h: { part: string; action: string }) => ({
    ...h,
    action: { kind: h.action },
  }),
}));

import { SessionManager } from '../../src/offscreen/SessionManager';
import { ALLOWED_PAGE, offscreenSessionDataFor, runRequest, topFrame } from '../helpers/builtinRunFixture';

const VERIFIER = 'http://localhost:7047';
const CONFIG = {
  name: 'p',
  description: 'p',
  requests: [{ method: 'GET', host: 'github.com', pathname: '/robots.txt', verifierUrl: VERIFIER }],
};
const REQ = {
  url: 'https://github.com/robots.txt',
  method: 'GET',
  headers: { Host: 'github.com' },
};
const OPTS = {
  verifierUrl: VERIFIER,
  proxyUrl: 'ws://localhost:7047/proxy?token=github.com',
  handlers: [{ type: 'SENT', part: 'START_LINE', action: 'REVEAL' }] as any[],
};
const SENT = new TextEncoder().encode('GET /robots.txt HTTP/1.1\r\n');
const RANGES = {
  sentRanges: [{ start: 0, end: 24 }],
  recvRanges: [{ start: 0, end: 15 }],
  sentRangesWithHandlers: [
    { start: 0, end: 24, handler: { type: 'SENT', part: 'START_LINE', action: 'REVEAL' } },
  ],
  recvRangesWithHandlers: [
    { start: 0, end: 15, handler: { type: 'RECV', part: 'START_LINE', action: 'REVEAL' } },
  ],
  commit: undefined,
};

/** A run that is not auto-approved (not reachable from a page; SessionManager's own gate). */
const manualSessionData = (page: Record<string, string>) => ({
  ...page,
  _approvalMode: 'manual',
  _autoApproved: '0',
});

function onProveFor(sessionData: Record<string, string>) {
  hosts.length = 0;
  const sm = new SessionManager();
  (sm as any).createExecutionHost(CONFIG, 'req-1', sessionData);
  const host = hosts[hosts.length - 1];
  return { host, onProve: host.opts.onProve as (...a: any[]) => Promise<unknown> };
}

beforeEach(() => {
  vi.clearAllMocks();
  (globalThis as any).chrome.runtime.sendMessage = vi.fn().mockResolvedValue(undefined);
  pm.createProver.mockResolvedValue('prover-1');
  pm.sendRequest.mockResolvedValue(undefined);
  pm.computeReveal.mockResolvedValue(RANGES);
  pm.getSentBytes.mockReturnValue(SENT);
  pm.getRecvBytes.mockReturnValue(new TextEncoder().encode('HTTP/1.1 200 OK\r\n'));
  pm.sendRevealConfig.mockResolvedValue(undefined);
  pm.reveal.mockResolvedValue({ sent: [], recv: [] });
  pm.getResponse.mockResolvedValue({ results: [{ type: 'SENT' }] });
  pm.cleanupProver.mockResolvedValue(undefined);
});

describe('straight to proving', () => {
  it('allowed origin + built-in plugin: no review screen, the proof runs with the same reveal ranges', async () => {
    const data = offscreenSessionDataFor(runRequest(), topFrame(ALLOWED_PAGE));
    expect(data?._approvalMode).toBe('all-session');
    const { host, onProve } = onProveFor(data!);

    await expect(onProve(REQ, OPTS)).resolves.toEqual({ results: [{ type: 'SENT' }] });
    expect(host.registerRevealApproval).not.toHaveBeenCalled();
    expect(pm.sendRevealConfig).toHaveBeenCalledWith('prover-1', {
      sent: RANGES.sentRangesWithHandlers,
      recv: RANGES.recvRangesWithHandlers,
    });
    expect(pm.reveal).toHaveBeenCalledWith(
      'prover-1',
      { sent: RANGES.sentRanges, recv: RANGES.recvRanges },
      undefined,
    );
  });

  for (const [label, sender, request] of [
    ['foreign origin + built-in plugin', topFrame('https://example.com'), runRequest()],
    ['allowed origin + unknown plugin', topFrame(ALLOWED_PAGE), runRequest({ pluginId: 'other-plugin' })],
    ['allowed origin in an iframe + built-in plugin', topFrame(ALLOWED_PAGE, { frameId: 3 }), runRequest()],
  ] as const) {
    it(`${label}: refused, nothing runs (no stock prompt path any more)`, () => {
      expect(offscreenSessionDataFor(request, sender)).toBeNull();
    });
  }

  it('a non-auto-approved run still gets the review screen and reveals the same ranges after Approve', async () => {
    const { host, onProve } = onProveFor(manualSessionData({ mode: 'Proxy' }));
    host.registerRevealApproval.mockImplementation(
      (resolve: () => void, _rej: unknown, d: unknown[]) => {
        expect(d).toHaveLength(2);
        expect(pm.reveal).not.toHaveBeenCalled(); // nothing leaves before the human decides
        resolve();
      },
    );
    await onProve(REQ, OPTS);
    expect(host.registerRevealApproval).toHaveBeenCalledTimes(1);
    expect(pm.reveal).toHaveBeenCalledWith(
      'prover-1',
      { sent: RANGES.sentRanges, recv: RANGES.recvRanges },
      undefined,
    );
  });

  it('Reject on the review screen reveals nothing', async () => {
    const { host, onProve } = onProveFor(manualSessionData({ mode: 'Proxy' }));
    host.registerRevealApproval.mockImplementation((_res: unknown, reject: (e: Error) => void) =>
      reject(new Error('User rejected reveal')),
    );
    await expect(onProve(REQ, OPTS)).rejects.toThrow('User rejected reveal');
    expect(pm.sendRevealConfig).not.toHaveBeenCalled();
    expect(pm.reveal).not.toHaveBeenCalled();
  });

  it('a page-supplied _approvalMode is refused outright (only four page keys)', () => {
    expect(
      offscreenSessionDataFor(
        runRequest({ sessionData: { mode: 'Proxy', _approvalMode: 'all-session' } }),
        topFrame(ALLOWED_PAGE),
      ),
    ).toBeNull();
  });

  it('Background hands the offscreen document the page keys first, then _approvalMode', () => {
    const bg = readFileSync(
      path.resolve(__dirname, '../../src/entries/Background/index.ts'),
      'utf8',
    );
    expect(bg).toMatch(/sessionData: offscreenSessionData\(approval\),/);
    const fn = readFileSync(
      path.resolve(__dirname, '../../src/background/autoApproval.ts'),
      'utf8',
    );
    expect(fn).toMatch(/return \{\s*\.\.\.approval\.sessionData,\s*_approvalMode: approval\.mode,/);
  });

  it('a plugin-supplied sessionData._approvalMode cannot skip the review either', async () => {
    const { host, onProve } = onProveFor(manualSessionData({ mode: 'Proxy' }));
    host.registerRevealApproval.mockImplementation((resolve: () => void) => resolve());
    await onProve(REQ, { ...OPTS, sessionData: { _approvalMode: 'all-session' } });
    expect(host.registerRevealApproval).toHaveBeenCalledTimes(1);
  });

  it('auto-approved runs keep the permission check: a request outside the plugin config is refused before any session', async () => {
    const { host, onProve } = onProveFor(offscreenSessionDataFor(runRequest(), topFrame(ALLOWED_PAGE))!);
    await expect(
      onProve({ ...REQ, url: 'https://github.com/settings/tokens' }, OPTS),
    ).rejects.toThrow(/Permission denied/);
    expect(pm.createProver).not.toHaveBeenCalled();
    expect(host.registerRevealApproval).not.toHaveBeenCalled();
  });
});
