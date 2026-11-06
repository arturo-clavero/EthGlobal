/**
 * Progress of a trusted plugin for the embedding page, and nothing
 * for anyone else. Pins the chain:
 *
 *   RUN_BUILTIN → autoApprovalFor() (top-frame allowed origin + built-in plugin
 *   id/fingerprint + checked values, in the background) → Background
 *   writes sessionData._autoApproved AFTER the page's keys and marks the run's
 *   progress route → SessionManager
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
import { sanitizePageProgress } from '../../src/constants/pageProgress';
import { ALLOWED_PAGE, offscreenSessionDataFor, runRequest, topFrame } from '../helpers/builtinRunFixture';

const OK = { method: 'EXAMPLE_MEMBERSHIP', status: 'running', index: 2, total: 8, step: 'A2' };

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
  it('allowed origin + built-in plugin: the run has reportProgress; it sends PLUGIN_PROGRESS with the checked fields only', async () => {
    const caps = capabilitiesFor(offscreenSessionDataFor(runRequest(), topFrame(ALLOWED_PAGE)));
    const report = caps.get('reportProgress');
    expect(report).toBeTypeOf('function');
    report!({ ...OK, extra: 'dropped' });
    report!({ method: 'bad method', status: 'running', index: 0, total: 0 });
    await Promise.resolve();
    expect(sent).toEqual([{ type: 'PLUGIN_PROGRESS', requestId: 'req-1', progress: OK }]);
  });

  // These runs no longer happen at all (no stock prompt path): refused, nothing runs.
  for (const [label, sender, request] of [
    ['foreign origin + built-in plugin', topFrame('https://example.com'), runRequest()],
    ['allowed origin + unknown plugin', topFrame(ALLOWED_PAGE), runRequest({ pluginId: 'other-plugin' })],
    [
      'allowed origin + another plugin version',
      topFrame(ALLOWED_PAGE),
      runRequest({ fingerprint: 'f'.repeat(64) }),
    ],
    ['allowed origin in an iframe + built-in plugin', topFrame(ALLOWED_PAGE, { frameId: 3 }), runRequest()],
  ] as const) {
    it(`${label}: refused, so no run and no reportProgress`, () => {
      expect(offscreenSessionDataFor(request, sender)).toBeNull();
    });
  }

  it('a run that is not auto-approved has no reportProgress (the SessionManager gate)', () => {
    expect(
      capabilitiesFor({ mode: 'Proxy', _approvalMode: 'manual', _autoApproved: '0' }).has(
        'reportProgress',
      ),
    ).toBe(false);
  });

  it('a page-supplied _autoApproved is refused outright (only four page keys)', () => {
    expect(
      offscreenSessionDataFor(runRequest({ sessionData: { _autoApproved: '1' } }), topFrame(ALLOWED_PAGE)),
    ).toBeNull();
  });

  it('no requestId (the page cannot match the events): no reportProgress', () => {
    const data = offscreenSessionDataFor(runRequest({ requestId: undefined }), topFrame(ALLOWED_PAGE));
    expect(capabilitiesFor(data, null).has('reportProgress')).toBe(false);
  });

  it('no session data at all: no reportProgress', () => {
    expect(capabilitiesFor(null).has('reportProgress')).toBe(false);
  });
});

describe('page progress: background and content script gates', () => {
  const src = (file: string) => readFileSync(path.resolve(__dirname, '../../src', file), 'utf8');

  it('Background hands the offscreen document the page keys, then _autoApproved (so the page cannot set it)', () => {
    expect(src('entries/Background/index.ts')).toMatch(
      /type: 'RUN_BUILTIN_OFFSCREEN',[\s\S]{0,300}?sessionData: offscreenSessionData\(approval\),/,
    );
    expect(src('background/autoApproval.ts')).toMatch(
      /return \{\s*\.\.\.approval\.sessionData,\s*_approvalMode: approval\.mode,[\s\S]{0,120}?_autoApproved: '1',\s*\};/,
    );
  });

  it('Background marks the route only for an approved run and forwards only on a marked route', () => {
    const bg = src('entries/Background/index.ts');
    expect(bg).toMatch(
      /if \(!approval\.ok\) \{[\s\S]{0,200}?return Promise\.resolve\(\{ success: false, error: approval\.error \}\);\s*\}[\s\S]{0,600}?progressRoutes\.set\(requestId, \{[\s\S]{0,120}?pageProgress: true,/,
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
