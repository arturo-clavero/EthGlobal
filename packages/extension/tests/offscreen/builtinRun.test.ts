/**
 * The offscreen half of a built-in run reads
 * the plugin from the extension's own package, checks it is exactly the
 * fingerprinted version, fills in the values by its layout and hands only that
 * to QuickJS. Plus: no code path in the extension takes code from a message.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { prepareBuiltInRun } from '../../src/offscreen/builtinRun';
import { builtInPluginPath, pluginLayout } from '../../src/constants/builtinPlugins';
import { builtIn, EXT_ID, PARAMS, PLUGIN, PLUGINS, TEMPLATE } from '../helpers/builtinRunFixture';

const BG_URL = 'chrome-extension://test-id/background.bundle.js';
const BACKGROUND = { id: EXT_ID, url: BG_URL };
const VALUES = {
  verifierUrl: 'http://localhost:7048',
  proxyUrl: 'ws://localhost:7048/proxy?token=',
  params: JSON.stringify(PARAMS),
};
const MSG = {
  type: 'RUN_BUILTIN_OFFSCREEN',
  pluginId: PLUGIN.id,
  fingerprint: PLUGIN.sha256,
  values: VALUES,
  requestId: 'req-1',
  sessionData: { mode: 'Proxy', _approvalMode: 'all-session', _autoApproved: '1' },
};

function deps(files: Record<string, string> = { [builtInPluginPath(PLUGIN)]: TEMPLATE }) {
  const read: string[] = [];
  return {
    read,
    deps: {
      extensionId: EXT_ID,
      backgroundUrl: BG_URL,
      plugins: PLUGINS,
      readPackaged: async (p: string) => {
        read.push(p);
        if (!(p in files)) throw new Error('404');
        return files[p];
      },
    },
  };
}

describe('prepareBuiltInRun', () => {
  it('runs our packaged copy with the values filled in', async () => {
    const d = deps();
    const out = await prepareBuiltInRun(MSG, BACKGROUND, d.deps);
    expect(d.read).toEqual([builtInPluginPath(PLUGIN)]);
    expect('code' in out && out.code).toContain('JSON.parse("{\\"membership\\"');
    expect('code' in out && out.code).toContain('verifierUrl: "http://localhost:7048"');
    expect('code' in out && out.code.length).toBeGreaterThan(TEMPLATE.length);
  });

  it('only our background may start a run (not a content script, not another extension)', async () => {
    for (const sender of [
      { ...BACKGROUND, tab: { id: 1 } },
      { ...BACKGROUND, id: 'other' },
      { ...BACKGROUND, url: 'chrome-extension://test-id/options.html' },
      {},
    ]) {
      const d = deps();
      expect(await prepareBuiltInRun(MSG, sender, d.deps)).toEqual({ error: 'NOT_BACKGROUND' });
      expect(d.read).toEqual([]);
    }
  });

  it('an unknown plugin or another version is refused before anything is read', async () => {
    for (const [extra, error] of [
      [{ pluginId: 'other-plugin' }, 'UNKNOWN_PLUGIN'],
      [{ fingerprint: 'f'.repeat(64) }, 'PLUGIN_VERSION_MISMATCH'],
    ] as const) {
      const d = deps();
      expect(await prepareBuiltInRun({ ...MSG, ...extra }, BACKGROUND, d.deps)).toEqual({ error });
      expect(d.read).toEqual([]);
    }
  });

  it('a packaged file that is not the fingerprinted version is refused', async () => {
    const tampered = TEMPLATE.replace('REVEAL', 'REVEAX');
    expect(
      await prepareBuiltInRun(
        MSG,
        BACKGROUND,
        deps({ [builtInPluginPath(PLUGIN)]: tampered }).deps,
      ),
    ).toEqual({ error: 'PLUGIN_CORRUPT' });
    expect(await prepareBuiltInRun(MSG, BACKGROUND, deps({}).deps)).toEqual({
      error: 'PLUGIN_UNAVAILABLE',
    });
  });

  it('an index layout that does not match the packaged file is refused', async () => {
    const wrong = { ...PLUGIN, layout: pluginLayout(TEMPLATE.replace('github.com', 'x')) };
    const d = deps();
    expect(await prepareBuiltInRun(MSG, BACKGROUND, { ...d.deps, plugins: [wrong] })).toEqual({
      error: 'PLUGIN_CORRUPT',
    });
  });

  it('bad values are refused', async () => {
    for (const values of [
      { ...VALUES, verifierUrl: 'http://x" + evil() + "' },
      { ...VALUES, params: '{"a":1} + evil()' },
      undefined,
    ]) {
      expect(await prepareBuiltInRun({ ...MSG, values }, BACKGROUND, deps().deps)).toEqual({
        error: 'BAD_VALUES',
      });
    }
  });

  it('a `code` field in the message is never used', async () => {
    const out = await prepareBuiltInRun(
      { ...MSG, code: 'export default { main(){ steal() } }' },
      BACKGROUND,
      deps().deps,
    );
    expect('code' in out && out.code).not.toContain('steal');
  });

  it('two packaged versions: each fingerprint gets its own file', async () => {
    const previousTemplate = TEMPLATE.replace('REVEAL', 'REVEAL ');
    const previous = builtIn(previousTemplate);
    const files = {
      [builtInPluginPath(PLUGIN)]: TEMPLATE,
      [builtInPluginPath(previous)]: previousTemplate,
    };
    const d = deps(files);
    const out = await prepareBuiltInRun({ ...MSG, fingerprint: previous.sha256 }, BACKGROUND, {
      ...d.deps,
      plugins: [PLUGIN, previous],
    });
    expect('code' in out && out.code).toContain('action: "REVEAL " }');
    expect(d.read).toEqual([builtInPluginPath(previous)]);
  });
});

describe('no code path accepts page-supplied code', () => {
  const SRC = path.resolve(__dirname, '../../src');
  const files = (dir: string): string[] =>
    readdirSync(dir).flatMap((f) => {
      const p = path.join(dir, f);
      return statSync(p).isDirectory() ? files(p) : /\.(ts|tsx|js)$/.test(f) ? [p] : [];
    });
  // Code only: upstream comments may still mention the stock API by name.
  const stripComments = (t: string) =>
    t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/.*$/gm, '$1');
  const all = files(SRC).map(
    (f) => [path.relative(SRC, f), stripComments(readFileSync(f, 'utf8'))] as const,
  );
  const src = (f: string) => readFileSync(path.join(SRC, f), 'utf8');

  it('no stock page-code message or API is left anywhere in the extension sources', () => {
    for (const [file, text] of all) {
      for (const needle of [
        'EXEC_CODE',
        'execCode',
        'GET_PLUGIN_STATS_OFFSCREEN',
        'getPluginStatsViaOffscreen',
      ]) {
        expect(`${file}: ${text.includes(needle)}`).toBe(`${file}: false`);
      }
    }
  });

  it('the only executePlugin call runs the code prepareBuiltInRun read from the package', () => {
    const calls = all.filter(([, t]) => /\.executePlugin\(/.test(t)).map(([f]) => f);
    expect(calls).toEqual(['entries/Offscreen/index.tsx', 'offscreen/SessionManager.ts']);
    expect(src('entries/Offscreen/index.tsx')).toMatch(
      /prepareBuiltInRun\(request, sender, \{[\s\S]{0,1200}?sm\.executePlugin\(\s*prepared\.code,/,
    );
  });

  it('the content script forwards named fields only (no code) and the page API sends none', () => {
    const content = src('entries/Content/index.ts');
    const forward = /type: 'RUN_BUILTIN',([\s\S]*?)\}\)/.exec(content)![1];
    expect(forward.replace(/\s+/g, ' ').trim()).toBe(
      'pluginId: p.pluginId, fingerprint: p.fingerprint, verifierUrl: p.verifierUrl, proxyUrl: p.proxyUrl, params: p.params, requestId: p.requestId, sessionData: p.sessionData,',
    );
    const page = src('entries/Content/content.ts');
    expect(page).not.toMatch(/\bcode\b\s*[,:]/);
  });

  it('the background decides from Chrome sender and sends the offscreen document no code', () => {
    const bg = src('entries/Background/index.ts');
    expect(bg).toMatch(
      /request\.type === 'RUN_BUILTIN'\) \{\s*const approval = autoApprovalFor\(request, sender, browser\.runtime\.id\);\s*if \(!approval\.ok\) \{/,
    );
    const offscreenCall = /type: 'RUN_BUILTIN_OFFSCREEN',([\s\S]*?)\}\);/.exec(bg)![1];
    expect(offscreenCall).not.toMatch(/\bcode\b/);
    expect(offscreenCall).toMatch(/sessionData: offscreenSessionData\(approval\),/);
  });
});
