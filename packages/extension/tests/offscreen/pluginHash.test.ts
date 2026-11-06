/**
 * The runner reports the sha256 of the
 * packaged plugin it runs in every prove()'s sessionData, after the plugin's
 * own keys, so the server can accept only the pinned builds. A plugin can
 * neither set nor override the value.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { prepareBuiltInRun } from '../../src/offscreen/builtinRun';
import {
  PLUGIN_SHA256_KEY,
  proveSessionData,
  runSessionData,
} from '../../src/offscreen/pluginHash';
import { builtInPluginPath } from '../../src/constants/builtinPlugins';
import { EXT_ID, PARAMS, PLUGIN, PLUGINS, TEMPLATE, sha256 } from '../helpers/builtinRunFixture';

const BG_URL = 'chrome-extension://test-id/background.bundle.js';
const OTHER = 'f'.repeat(64);

describe('plugin sha256 in the session data', () => {
  it('prepareBuiltInRun returns the sha256 of the packaged file it read', async () => {
    const out = await prepareBuiltInRun(
      {
        type: 'RUN_BUILTIN_OFFSCREEN',
        pluginId: PLUGIN.id,
        fingerprint: PLUGIN.sha256,
        values: {
          verifierUrl: 'http://localhost:7048',
          proxyUrl: 'ws://localhost:7048/proxy?token=',
          params: JSON.stringify(PARAMS),
        },
        requestId: 'req-1',
        sessionData: { mode: 'Proxy' },
      },
      { id: EXT_ID, url: BG_URL },
      {
        extensionId: EXT_ID,
        backgroundUrl: BG_URL,
        plugins: PLUGINS,
        readPackaged: async (p: string) => {
          if (p !== builtInPluginPath(PLUGIN)) throw new Error('404');
          return TEMPLATE;
        },
      },
    );
    expect('sha256' in out && out.sha256).toBe(sha256(TEMPLATE));
    expect('sha256' in out && out.sha256).toBe(PLUGIN.sha256);
  });

  it('the run carries the runner hash after the background keys', () => {
    const run = runSessionData(
      { mode: 'Proxy', proofId: 'p', [PLUGIN_SHA256_KEY]: OTHER },
      PLUGIN.sha256,
    );
    expect(run).toEqual({ mode: 'Proxy', proofId: 'p', [PLUGIN_SHA256_KEY]: PLUGIN.sha256 });
    expect(runSessionData(undefined, PLUGIN.sha256)).toEqual({
      [PLUGIN_SHA256_KEY]: PLUGIN.sha256,
    });
  });

  it("a prove() sends the runner's hash; the plugin cannot override or invent it", () => {
    const run = runSessionData({ mode: 'Proxy', _autoApproved: '1' }, PLUGIN.sha256);
    // The plugin's own keys still merge after the run's (unchanged), except the runner key.
    expect(proveSessionData(run, { proofId: 'p', step: 'A', [PLUGIN_SHA256_KEY]: OTHER })).toEqual({
      mode: 'Proxy',
      _autoApproved: '1',
      proofId: 'p',
      step: 'A',
      [PLUGIN_SHA256_KEY]: PLUGIN.sha256,
    });
    expect(proveSessionData(run, undefined)[PLUGIN_SHA256_KEY]).toBe(PLUGIN.sha256);
    // No runner value (not a built-in run): a plugin-supplied value is dropped, never forwarded.
    expect(proveSessionData(null, { step: 'A', [PLUGIN_SHA256_KEY]: OTHER })).toEqual({
      step: 'A',
    });
    expect(proveSessionData({ mode: 'Proxy' }, { [PLUGIN_SHA256_KEY]: PLUGIN.sha256 })).toEqual({
      mode: 'Proxy',
    });
  });

  it('the offscreen runner and the prove capability are wired to it', () => {
    const SRC = path.resolve(__dirname, '../../src');
    const offscreen = readFileSync(path.join(SRC, 'entries/Offscreen/index.tsx'), 'utf8');
    expect(offscreen).toMatch(
      /sm\.executePlugin\(\s*prepared\.code,\s*request\.requestId \?\? undefined,[\s\S]{0,200}?runSessionData\(request\.sessionData, prepared\.sha256\),\s*\)/,
    );
    const sm = readFileSync(path.join(SRC, 'offscreen/SessionManager.ts'), 'utf8');
    expect(sm).toMatch(
      /const sessionData: Record<string, string> = proveSessionData\(\s*execSessionData,\s*proverOptions\.sessionData,\s*\);/,
    );
    // The only place a prove()'s sessionData is built.
    expect(sm.match(/\.\.\.proverOptions\.sessionData/g)).toBeNull();
  });
});
