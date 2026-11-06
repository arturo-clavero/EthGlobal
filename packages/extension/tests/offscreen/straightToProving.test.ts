/**
 * Straight to proving for auto-approved runs.
 * Pins the chain that makes
 * the trusted plugins on the embedding pages prove without any screen, and keeps every other
 * caller on the stock review:
 *
 *   EXEC_CODE → autoApprovalFor() (the one decision: top-frame allowed origin
 *   + allowlisted plugin hash, in the background) → 'all-session' →
 *   Background sets sessionData._approvalMode AFTER the page's sessionData →
 *   SessionManager.onProve skips the reveal review for 'all-session' only.
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
import { autoApprovalFor } from '../../src/background/autoApproval';
import type { AllowedPlugin } from '../../src/constants/pluginAllowlist';

const EXT_ID = 'test-extension-id';
const ALLOWED_PAGE = 'http://localhost:5175';
const CODE = 'export default { main: () => null, config: {} };';
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

async function sha256Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function allowlist(): Promise<AllowedPlugin[]> {
  return [{ id: 'ours', sha256: await sha256Hex(CODE), layout: [CODE.length] }];
}

const topFrame = (origin: string) => ({
  id: EXT_ID,
  origin,
  url: `${origin}/apply`,
  frameId: 0,
  tab: { id: 1 },
});

/** What Background EXEC_CODE does: stock prompt answer unless auto-approved. */
async function approvalMode(
  code: string,
  sender: ReturnType<typeof topFrame>,
  promptAnswer: 'manual' | 'all-session' | 'rejected',
) {
  const auto = await autoApprovalFor(code, sender, EXT_ID, [ALLOWED_PAGE], await allowlist());
  return { auto, mode: auto ? auto.mode : promptAnswer };
}

/** Background's sessionData for EXEC_CODE_OFFSCREEN (page data first, then the background's keys). */
const offscreenSessionData = (page: Record<string, string>, mode: string) => ({
  ...page,
  _approvalMode: mode,
  _pluginHash: 'h',
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
  it('allowed origin + allowlisted plugin: no review screen, the proof runs with the same reveal ranges', async () => {
    const { auto, mode } = await approvalMode(CODE, topFrame(ALLOWED_PAGE), 'manual');
    expect(auto?.mode).toBe('all-session');
    const { host, onProve } = onProveFor(offscreenSessionData({ mode: 'Proxy' }, mode));

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

  for (const [label, sender, code] of [
    ['foreign origin + allowlisted plugin', topFrame('https://example.com'), CODE],
    ['allowed origin + unlisted plugin', topFrame(ALLOWED_PAGE), CODE + ' '],
    ['allowed origin in an iframe + allowlisted plugin', { ...topFrame(ALLOWED_PAGE), frameId: 3 }, CODE],
  ] as const) {
    it(`${label}: stock prompt, then the review screen is unchanged and reveals the same ranges after Approve`, async () => {
      const { auto, mode } = await approvalMode(code, sender, 'manual');
      expect(auto).toBeNull();
      const { host, onProve } = onProveFor(offscreenSessionData({ mode: 'Proxy' }, mode));
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
  }

  it('foreign origin: Reject on the review screen reveals nothing', async () => {
    const { mode } = await approvalMode(CODE, topFrame('https://example.com'), 'manual');
    const { host, onProve } = onProveFor(offscreenSessionData({ mode: 'Proxy' }, mode));
    host.registerRevealApproval.mockImplementation((_res: unknown, reject: (e: Error) => void) =>
      reject(new Error('User rejected reveal')),
    );
    await expect(onProve(REQ, OPTS)).rejects.toThrow('User rejected reveal');
    expect(pm.sendRevealConfig).not.toHaveBeenCalled();
    expect(pm.reveal).not.toHaveBeenCalled();
  });

  it('a page-supplied _approvalMode cannot skip the review (the background value wins)', async () => {
    const { mode } = await approvalMode(CODE, topFrame('https://example.com'), 'manual');
    const data = offscreenSessionData({ mode: 'Proxy', _approvalMode: 'all-session' }, mode);
    expect(data._approvalMode).toBe('manual');
    const { host, onProve } = onProveFor(data);
    host.registerRevealApproval.mockImplementation((resolve: () => void) => resolve());
    await onProve(REQ, OPTS);
    expect(host.registerRevealApproval).toHaveBeenCalledTimes(1);
  });

  it('Background EXEC_CODE writes _approvalMode after the page sessionData (so the page cannot set it)', () => {
    const src = readFileSync(
      path.resolve(__dirname, '../../src/entries/Background/index.ts'),
      'utf8',
    );
    const block = /sessionData: \{\s*\.\.\.request\.sessionData,\s*_approvalMode: mode,/;
    expect(src).toMatch(block);
  });

  it('a plugin-supplied sessionData._approvalMode cannot skip the review either', async () => {
    const { host, onProve } = onProveFor(offscreenSessionData({ mode: 'Proxy' }, 'manual'));
    host.registerRevealApproval.mockImplementation((resolve: () => void) => resolve());
    await onProve(REQ, { ...OPTS, sessionData: { _approvalMode: 'all-session' } });
    expect(host.registerRevealApproval).toHaveBeenCalledTimes(1);
  });

  it('auto-approved runs keep the permission check: a request outside the plugin config is refused before any session', async () => {
    const { mode } = await approvalMode(CODE, topFrame(ALLOWED_PAGE), 'manual');
    const { host, onProve } = onProveFor(offscreenSessionData({ mode: 'Proxy' }, mode));
    await expect(
      onProve({ ...REQ, url: 'https://github.com/settings/tokens' }, OPTS),
    ).rejects.toThrow(/Permission denied/);
    expect(pm.createProver).not.toHaveBeenCalled();
    expect(host.registerRevealApproval).not.toHaveBeenCalled();
  });
});
