/**
 * Progress of a trusted plugin for the embedding page, and nothing
 * for anyone else. Pins the chain:
 *
 *   EXEC_CODE → autoApprovalFor() (top-frame allowed origin + allowlisted plugin
 *   hash, in the background) → Background writes sessionData._autoApproved AFTER
 *   the page's sessionData and marks the run's progress route → SessionManager
 *   adds `reportProgress` only for _autoApproved '1' with a requestId (and
 *   keeps only the checked fields, constants/pageProgress.ts) → the background
 *   forwards PLUGIN_PROGRESS only on a marked route → the content script checks
 *   the fields again and posts them only on an allowed origin.
 */
/* eslint-disable @typescript-eslint/no-explicit-any -- loose mocks of Host and ProveManager */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const hosts = vi.hoisted(
  () => [] as Array<{ capabilities: Map<string, (...a: any[]) => unknown> }>,
);

vi.mock('../../src/offscreen/ProveManager', () => ({
  ProveManager: class {
    init = vi.fn().mockResolvedValue(undefined);
  },
}));

vi.mock('@tlsn/plugin-sdk', () => ({
  default: class {
    capabilities = new Map<string, (...a: any[]) => unknown>();
    constructor() {
      hosts.push(this);
    }
    addCapability(name: string, handler: (...a: any[]) => unknown) {
      this.capabilities.set(name, handler);
    }
  },
  canonicalizeHandler: (h: unknown) => h,
}));

import { SessionManager } from '../../src/offscreen/SessionManager';
import { autoApprovalFor } from '../../src/background/autoApproval';
import { sanitizePageProgress } from '../../src/constants/pageProgress';
import type { AllowedPlugin } from '../../src/constants/pluginAllowlist';

const EXT_ID = 'test-extension-id';
const ALLOWED_PAGE = 'http://localhost:5175';
const CODE = 'export default { main: () => null, config: {} };';
const OK = { method: 'EXAMPLE_MEMBERSHIP', status: 'running', index: 2, total: 8, step: 'A2' };

async function sha256Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, '0')).join('');
}
const topFrame = (origin: string) => ({
  id: EXT_ID,
  origin,
  url: `${origin}/apply`,
  frameId: 0,
  tab: { id: 1 },
});

/** What Background EXEC_CODE sends to the offscreen document (page data first, then the background's keys). */
async function offscreenSessionData(
  code: string,
  sender: ReturnType<typeof topFrame>,
  page: Record<string, string> = {},
) {
  const allowlist: AllowedPlugin[] = [
    { id: 'ours', sha256: await sha256Hex(CODE), layout: [CODE.length] },
  ];
  const auto = await autoApprovalFor(code, sender, EXT_ID, [ALLOWED_PAGE], allowlist);
  return {
    ...page,
    _approvalMode: auto ? auto.mode : 'manual',
    _pluginHash: 'h',
    _autoApproved: auto ? '1' : '0',
  };
}

function capabilitiesFor(
  sessionData: Record<string, string> | null,
  requestId: string | null = 'req-1',
) {
  hosts.length = 0;
  const sm = new SessionManager();
  const host = (sm as any).createExecutionHost(null, requestId, sessionData);
  (sm as any).addPageProgress(host, requestId, sessionData);
  return hosts[hosts.length - 1].capabilities;
}

let sent: unknown[];
beforeEach(() => {
  sent = [];
  (globalThis as any).chrome.runtime.sendMessage = vi.fn(async (m: unknown) => {
    sent.push(m);
  });
});

describe('page progress: the fields', () => {
  it('keeps a well-formed report as is', () => {
    expect(sanitizePageProgress(OK)).toEqual(OK);
    expect(
      sanitizePageProgress({ method: 'EXAMPLE_WORK', status: 'done', index: 0, total: 0 }),
    ).toEqual({
      method: 'EXAMPLE_WORK',
      status: 'done',
      index: 0,
      total: 0,
    });
  });

  it('drops every other field and a malformed step id', () => {
    expect(
      sanitizePageProgress({
        ...OK,
        cookie: 'user_session=x',
        message: 'free text',
        values: ['a'],
      }),
    ).toEqual(OK);
    expect(sanitizePageProgress({ ...OK, step: 'user_session=x' })).toEqual({
      method: OK.method,
      status: OK.status,
      index: OK.index,
      total: OK.total,
    });
  });

  for (const [label, raw] of [
    ['null', null],
    ['an array', [OK]],
    ['a string', JSON.stringify(OK)],
    ['free-text method', { ...OK, method: 'Proving acme-org' }],
    ['unknown status', { ...OK, status: 'secret' }],
    ['negative count', { ...OK, index: -1 }],
    ['fractional count', { ...OK, total: 1.5 }],
    ['huge count', { ...OK, total: 1000 }],
    ['count as text', { ...OK, index: '2' }],
  ] as const) {
    it(`refuses ${label}`, () => {
      expect(sanitizePageProgress(raw)).toBeNull();
    });
  }
});

describe('page progress: who gets reportProgress', () => {
  it('allowed origin + allowlisted plugin: the run has reportProgress; it sends PLUGIN_PROGRESS with the checked fields only', async () => {
    const caps = capabilitiesFor(
      await offscreenSessionData(CODE, topFrame(ALLOWED_PAGE), { mode: 'Proxy' }),
    );
    const report = caps.get('reportProgress');
    expect(report).toBeTypeOf('function');
    report!({ ...OK, extra: 'dropped' });
    report!({ method: 'bad method', status: 'running', index: 0, total: 0 });
    await Promise.resolve();
    expect(sent).toEqual([{ type: 'PLUGIN_PROGRESS', requestId: 'req-1', progress: OK }]);
  });

  for (const [label, sender, code] of [
    ['foreign origin + allowlisted plugin', topFrame('https://example.com'), CODE],
    ['allowed origin + unlisted plugin', topFrame(ALLOWED_PAGE), CODE + ' '],
    ['allowed origin in an iframe + allowlisted plugin', { ...topFrame(ALLOWED_PAGE), frameId: 3 }, CODE],
  ] as const) {
    it(`${label}: no reportProgress (the stock behaviour)`, async () => {
      const caps = capabilitiesFor(
        await offscreenSessionData(code, sender as ReturnType<typeof topFrame>),
      );
      expect(caps.has('reportProgress')).toBe(false);
    });
  }

  it('a page-supplied _autoApproved cannot turn it on (the background value wins)', async () => {
    const data = await offscreenSessionData(CODE, topFrame('https://example.com'), {
      _autoApproved: '1',
    });
    expect(data._autoApproved).toBe('0');
    expect(capabilitiesFor(data).has('reportProgress')).toBe(false);
  });

  it('no requestId (the page cannot match the events): no reportProgress', async () => {
    const caps = capabilitiesFor(await offscreenSessionData(CODE, topFrame(ALLOWED_PAGE)), null);
    expect(caps.has('reportProgress')).toBe(false);
  });

  it('no session data at all: no reportProgress', () => {
    expect(capabilitiesFor(null).has('reportProgress')).toBe(false);
  });
});

describe('page progress: background and content script gates', () => {
  const src = (file: string) => readFileSync(path.resolve(__dirname, '../../src', file), 'utf8');

  it('Background writes _autoApproved after the page sessionData (so the page cannot set it)', () => {
    expect(src('entries/Background/index.ts')).toMatch(
      /sessionData: \{\s*\.\.\.request\.sessionData,\s*_approvalMode: mode,\s*_pluginHash: pluginHash,[\s\S]{0,200}?_autoApproved: autoApproved \? '1' : '0',\s*\}/,
    );
  });

  it('Background marks the route only for an auto-approved run and forwards only on a marked route', () => {
    const bg = src('entries/Background/index.ts');
    expect(bg).toMatch(
      /if \(auto\) \{[\s\S]{0,300}?autoApproved = true;[\s\S]{0,200}?route\.pageProgress = true;/,
    );
    expect(bg).toMatch(
      /request\.type === 'PLUGIN_PROGRESS'\) \{\s*const route = progressRoutes\.get\(request\.requestId\);\s*if \(route\?\.pageProgress\) \{/,
    );
  });

  it('the content script posts it to the page only on an allowed origin, checked again', () => {
    expect(src('entries/Content/index.ts')).toMatch(
      /request\.type === 'PLUGIN_PROGRESS'\) \{\s*const progress = sanitizePageProgress\(request\.progress\);\s*if \(PRODUCT_PAGE && progress && typeof request\.requestId === 'string'\)/,
    );
  });
});
