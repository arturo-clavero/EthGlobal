/**
 * A wrong account keeps the window open; a trusted plugin may send
 * its own window to GitHub's logout/login/account switcher (exact URLs) and tells the embedding page which login is signed in
 * (`account` progress, the login only). Scaffolding copied from pageProgress.test.ts, whose header follows.
 *
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
import {
  allowedNavigation,
  pluginNavigateTarget,
  PLUGIN_NAVIGATE_URLS,
} from '../../src/constants/pluginNavigate';
import type { AllowedPlugin } from '../../src/constants/pluginAllowlist';

const EXT_ID = 'test-extension-id';
const ALLOWED_PAGE = 'http://localhost:5175';
const CODE = 'export default { main: () => null, config: {} };';

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
  (sm as any).addNavigate(host, requestId, sessionData);
  // The window this run opened (SessionManager records it from the OPEN_WINDOW answer).
  (sm as any).runWindows.set(host, 42);
  return hosts[hosts.length - 1].capabilities;
}

let sent: unknown[];
beforeEach(() => {
  sent = [];
  (globalThis as any).chrome.runtime.sendMessage = vi.fn(async (m: unknown) => {
    sent.push(m);
  });
});

const NAV_ID = 'test-extension-id';
const OFFSCREEN = 'chrome-extension://test-extension-id/offscreen.html';
const gate = (over: Partial<Parameters<typeof pluginNavigateTarget>[2]> = {}) => ({
  extensionId: NAV_ID,
  offscreenUrl: OFFSCREEN,
  isAutoApprovedRun: (id: string) => id === 'req-1',
  tabOfWindow: (w: number) => (w === 42 ? 99 : undefined),
  ...over,
});
const NAV = {
  type: 'PLUGIN_NAVIGATE',
  requestId: 'req-1',
  windowId: 42,
  url: 'https://github.com/logout',
};
const OFFSCREEN_SENDER = { id: NAV_ID, url: OFFSCREEN };

describe('navigate: the URL allowlist (exact, fail closed)', () => {
  it('allows exactly logout, login and switch_account', () => {
    expect([...PLUGIN_NAVIGATE_URLS].sort()).toEqual([
      'https://github.com/login',
      'https://github.com/logout',
      'https://github.com/switch_account',
    ]);
    for (const u of PLUGIN_NAVIGATE_URLS) expect(allowedNavigation(u)).toBe(u);
  });

  for (const url of [
    'https://github.com/logout?return_to=https://evil.example',
    'https://github.com/login?return_to=%2Fevil',
    'https://github.com/logout/',
    'https://github.com/logout#x',
    'https://github.com/LOGOUT',
    ' https://github.com/logout',
    'http://github.com/logout',
    'https://github.com.evil.example/logout',
    'https://user@github.com/logout',
    'https://gist.github.com/logout',
    'https://github.com/',
    'https://github.com/settings/tokens',
    'https://evil.example/',
    'javascript:alert(1)',
    'chrome://extensions',
    '',
    null,
    undefined,
    42,
    { toString: () => 'https://github.com/logout' },
    ['https://github.com/logout'],
  ] as unknown[]) {
    it(`refuses ${JSON.stringify(url) ?? String(url)}`, () => {
      expect(allowedNavigation(url)).toBeNull();
    });
  }
});

describe('navigate: the background gate', () => {
  it('our offscreen document + an auto-approved run + its managed window + an allowed URL → that tab', () => {
    expect(pluginNavigateTarget(NAV, OFFSCREEN_SENDER, gate())).toEqual({
      tabId: 99,
      url: 'https://github.com/logout',
    });
  });

  for (const [label, msg, sender, g] of [
    ['a content script (sender has a tab)', NAV, { ...OFFSCREEN_SENDER, tab: { id: 1 } }, gate()],
    ['another extension', NAV, { ...OFFSCREEN_SENDER, id: 'other' }, gate()],
    [
      'another extension page',
      NAV,
      { id: NAV_ID, url: 'chrome-extension://test-extension-id/popup.html' },
      gate(),
    ],
    ['no sender', NAV, undefined, gate()],
    [
      'a run that was not auto-approved',
      NAV,
      OFFSCREEN_SENDER,
      gate({ isAutoApprovedRun: () => false }),
    ],
    ['no requestId', { ...NAV, requestId: undefined }, OFFSCREEN_SENDER, gate()],
    [
      'a URL off the list',
      { ...NAV, url: 'https://github.com/settings' },
      OFFSCREEN_SENDER,
      gate(),
    ],
    ['a window the extension does not manage', { ...NAV, windowId: 7 }, OFFSCREEN_SENDER, gate()],
    ['a malformed window id', { ...NAV, windowId: '42' }, OFFSCREEN_SENDER, gate()],
    ['another message type', { ...NAV, type: 'OPEN_WINDOW' }, OFFSCREEN_SENDER, gate()],
  ] as const) {
    it(`refuses ${label}`, () => {
      expect(pluginNavigateTarget(msg, sender as any, g as any)).toBeNull();
    });
  }

  it('Background asks the gate with the route flag the auto-approval set, and navigates only its target', () => {
    const bg = readFileSync(
      path.resolve(__dirname, '../../src/entries/Background/index.ts'),
      'utf8',
    );
    expect(bg).toMatch(
      /request\.type === 'PLUGIN_NAVIGATE'\) \{\s*const target = pluginNavigateTarget\(request, sender, \{[\s\S]{0,200}?isAutoApprovedRun: \(requestId\) => progressRoutes\.get\(requestId\)\?\.pageProgress === true,\s*tabOfWindow: \(windowId\) => windowManager\.getWindow\(windowId\)\?\.tabId,\s*\}\);\s*if \(!target\) \{[\s\S]{0,120}?return Promise\.resolve\(\{ ok: false \}\);\s*\}\s*return browser\.tabs\s*\.update\(target\.tabId, \{ url: target\.url \}\)/,
    );
  });
});

describe('navigate: who gets the capability', () => {
  it('allowed origin + allowlisted plugin: navigate exists; an allowed URL goes to the background for its own window', async () => {
    const caps = capabilitiesFor(
      await offscreenSessionData(CODE, topFrame(ALLOWED_PAGE), { mode: 'Proxy' }),
    );
    const navigate = caps.get('navigate');
    expect(navigate).toBeTypeOf('function');
    expect(navigate!('https://github.com/logout')).toBe(true);
    expect(navigate!('https://github.com/logout?return_to=/x')).toBe(false);
    expect(navigate!('https://evil.example/')).toBe(false);
    await Promise.resolve();
    expect(sent).toEqual([
      {
        type: 'PLUGIN_NAVIGATE',
        requestId: 'req-1',
        windowId: 42,
        url: 'https://github.com/logout',
      },
    ]);
  });

  for (const [label, sender, code] of [
    ['foreign origin + allowlisted plugin', topFrame('https://example.com'), CODE],
    ['allowed origin + unlisted plugin', topFrame(ALLOWED_PAGE), CODE + ' '],
    ['allowed origin in an iframe + allowlisted plugin', { ...topFrame(ALLOWED_PAGE), frameId: 3 }, CODE],
  ] as const) {
    it(`${label}: no navigate`, async () => {
      const caps = capabilitiesFor(
        await offscreenSessionData(code, sender as ReturnType<typeof topFrame>),
      );
      expect(caps.has('navigate')).toBe(false);
    });
  }

  it('a page-supplied _autoApproved cannot turn it on; no requestId or no session data: none', async () => {
    const data = await offscreenSessionData(CODE, topFrame('https://example.com'), {
      _autoApproved: '1',
    });
    expect(capabilitiesFor(data).has('navigate')).toBe(false);
    expect(
      capabilitiesFor(await offscreenSessionData(CODE, topFrame(ALLOWED_PAGE)), null).has('navigate'),
    ).toBe(false);
    expect(capabilitiesFor(null).has('navigate')).toBe(false);
  });
});

describe('page progress: the `account` status carries the signed-in login only', () => {
  const ACC = { method: 'EXAMPLE_WORK', status: 'account', index: 0, total: 0, login: 'dev-two' };

  it('keeps method + login, forces the counts to 0 and drops everything else', () => {
    expect(sanitizePageProgress(ACC)).toEqual(ACC);
    expect(
      sanitizePageProgress({
        ...ACC,
        index: 5,
        total: 8,
        step: 'A1',
        cookie: 'user_session=x',
        expected: 'dev-one',
      }),
    ).toEqual(ACC);
  });

  for (const [label, raw] of [
    ['no login', { ...ACC, login: undefined }],
    ['a login with a cookie in it', { ...ACC, login: 'dev-two; user_session=x' }],
    ['a too long login', { ...ACC, login: 'a'.repeat(40) }],
    ['a login as a number', { ...ACC, login: 42 }],
  ] as const) {
    it(`refuses ${label}`, () => {
      expect(sanitizePageProgress(raw)).toBeNull();
    });
  }

  it('other statuses never carry a login', () => {
    expect(
      sanitizePageProgress({
        method: 'EXAMPLE_WORK',
        status: 'running',
        index: 1,
        total: 0,
        login: 'dev-two',
      }),
    ).toEqual({ method: 'EXAMPLE_WORK', status: 'running', index: 1, total: 0 });
  });

  it('reportProgress forwards it (auto-approved runs only, as every status)', async () => {
    const caps = capabilitiesFor(await offscreenSessionData(CODE, topFrame(ALLOWED_PAGE)));
    caps.get('reportProgress')!(ACC);
    await Promise.resolve();
    expect(sent).toEqual([{ type: 'PLUGIN_PROGRESS', requestId: 'req-1', progress: ACC }]);
  });
});
