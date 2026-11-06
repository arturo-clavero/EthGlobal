/**
 * The page asks for one of the extension's
 * BUILT-IN plugins by id + fingerprint; it never sends code. The background
 * runs it only for our content script in the top frame of an allowed origin,
 * only a packaged version, and only with well-formed values; everything else
 * is refused (there is no prompt path and no page-code path).
 */
import { describe, it, expect } from 'vitest';
import {
  BUILTIN_PLUGINS,
  builtInPluginPath,
  canonicalizePlugin,
  checkRunValues,
  findBuiltInPlugin,
  parseBuiltInPlugins,
  pluginLayout,
  substitutePlugin,
} from '../../src/constants/builtinPlugins';
import {
  autoApprovalFor,
  checkPageSessionData,
  offscreenSessionData,
  senderProductOrigin,
} from '../../src/background/autoApproval';
import { parseProductOrigins } from '../../src/constants/productOrigins';
import {
  builtIn,
  EXT_ID,
  PARAMS,
  PLUGIN,
  PLUGINS,
  runRequest,
  TEMPLATE,
  topFrame,
} from '../helpers/builtinRunFixture';

const ORIGINS = parseProductOrigins(
  'http://localhost:5173,http://127.0.0.1:5173,http://localhost:5175,http://127.0.0.1:5175,https://app.example.com',
);

// The page-side preparePluginCode (reference implementation): the
// built-in substitution must produce exactly the same bytes.
function preparePluginCode(
  code: string,
  subs: { verifierUrl: string; proxyUrl: string; params: Record<string, unknown> },
): string {
  return code
    .split('__VERIFIER_URL__')
    .join(subs.verifierUrl)
    .split('__PROXY_URL__')
    .join(subs.proxyUrl)
    .replace(/(["'])__PLUGIN_PARAMS__\1/, () => JSON.stringify(JSON.stringify(subs.params)));
}

const VALUES = {
  verifierUrl: 'http://localhost:7048',
  proxyUrl: 'ws://localhost:7048/proxy?token=',
  params: JSON.stringify(PARAMS),
};

describe('substitutePlugin (our copy, by layout)', () => {
  it('is byte-identical to the page-side substitution of the same values', () => {
    const code = substitutePlugin(TEMPLATE, pluginLayout(TEMPLATE), VALUES);
    expect(code).toBe(
      preparePluginCode(TEMPLATE, {
        verifierUrl: VALUES.verifierUrl,
        proxyUrl: VALUES.proxyUrl,
        params: PARAMS,
      }),
    );
    expect(canonicalizePlugin(code!, pluginLayout(TEMPLATE))).toBe(TEMPLATE);
  });

  it('puts the params in as one JSON string literal, whatever they contain', () => {
    const code = substitutePlugin(TEMPLATE, pluginLayout(TEMPLATE), VALUES)!;
    const literal = /JSON\.parse\((".*?(?<!\\)")\);/.exec(code)![1];
    expect(JSON.parse(JSON.parse(literal))).toEqual(PARAMS);
  });

  for (const [label, values] of [
    [
      'a verifier URL that leaves its literal',
      { ...VALUES, verifierUrl: 'http://x" + evil() + "' },
    ],
    ['a proxy URL with a backslash', { ...VALUES, proxyUrl: 'ws://x\\u0022' }],
    ['a URL with whitespace', { ...VALUES, verifierUrl: 'http://x y' }],
    ['a javascript: URL', { ...VALUES, verifierUrl: 'javascript:alert(1)' }],
    ['an empty URL', { ...VALUES, proxyUrl: '' }],
    ['a URL as a number', { ...VALUES, verifierUrl: 7048 }],
    ['params as an object (not JSON text)', { ...VALUES, params: PARAMS }],
    ['params that are not JSON', { ...VALUES, params: '{"a":1} + evil()' }],
    ['params that are an array', { ...VALUES, params: '[1]' }],
    ['params that are null', { ...VALUES, params: 'null' }],
    ['params over 256 KiB', { ...VALUES, params: JSON.stringify({ a: 'x'.repeat(256 * 1024) }) }],
    ['nothing', undefined],
  ] as const) {
    it(`refuses ${label}`, () => {
      expect(checkRunValues(values)).toBeNull();
      expect(substitutePlugin(TEMPLATE, pluginLayout(TEMPLATE), values)).toBeNull();
    });
  }

  it('refuses a layout that does not fit the template', () => {
    const other = pluginLayout(TEMPLATE.replace('github.com', 'example.org'));
    expect(substitutePlugin(TEMPLATE + ' ', pluginLayout(TEMPLATE), VALUES)).toBeNull();
    expect(substitutePlugin(TEMPLATE, [...other.slice(0, -1), 5], VALUES)).toBeNull();
  });

  it('refuses to lay out a bundle without whole-literal placeholders', () => {
    expect(() => pluginLayout('var a = 1;')).toThrow(/missing/);
    expect(() =>
      pluginLayout(TEMPLATE.replace('"__PROXY_URL__" + HOST', '`__PROXY_URL__${HOST}`')),
    ).toThrow(/string literal/);
  });
});

describe('the build-time index (fail closed)', () => {
  it('keeps a well-formed index, two versions of a plugin included', () => {
    const previous = builtIn(TEMPLATE.replace('REVEAL', 'REVEAL '));
    expect(parseBuiltInPlugins(JSON.stringify([PLUGIN, previous]))).toEqual([PLUGIN, previous]);
  });

  it('is empty for a missing or malformed index', () => {
    for (const bad of [
      '',
      'not json',
      '{}',
      JSON.stringify([{ ...PLUGIN, sha256: 'abc' }]),
      JSON.stringify([{ ...PLUGIN, sha256: PLUGIN.sha256.toUpperCase() }]),
      JSON.stringify([{ ...PLUGIN, id: '../x' }]),
      JSON.stringify([{ ...PLUGIN, layout: [1, '__EVIL__', 2] }]),
      JSON.stringify([PLUGIN, PLUGIN]),
      JSON.stringify([PLUGIN, null]),
    ]) {
      expect(parseBuiltInPlugins(bad)).toEqual([]);
    }
  });

  it('has no build-time index under vitest (nothing can run)', () => {
    expect(BUILTIN_PLUGINS).toEqual([]);
    expect(autoApprovalFor(runRequest(), topFrame('http://localhost:5175'), EXT_ID)).toEqual({
      ok: false,
      error: 'NOT_PRODUCT_PAGE',
    });
  });

  it('names the packaged file by id and fingerprint', () => {
    expect(builtInPluginPath(PLUGIN)).toBe(
      `builtin-plugins/example-work-${PLUGIN.sha256}.js`,
    );
  });

  it('tells an unknown plugin from another version of a known one', () => {
    expect(findBuiltInPlugin(PLUGIN.id, PLUGIN.sha256, PLUGINS)).toEqual({ plugin: PLUGIN });
    expect(findBuiltInPlugin(PLUGIN.id, 'f'.repeat(64), PLUGINS)).toEqual({
      error: 'PLUGIN_VERSION_MISMATCH',
    });
    expect(findBuiltInPlugin('other-plugin', PLUGIN.sha256, PLUGINS)).toEqual({
      error: 'UNKNOWN_PLUGIN',
    });
    expect(findBuiltInPlugin({ id: PLUGIN.id }, PLUGIN.sha256, PLUGINS)).toEqual({
      error: 'UNKNOWN_PLUGIN',
    });
  });
});

describe('autoApprovalFor (RUN_BUILTIN)', () => {
  it('allowed origin + top frame + built-in plugin ⇒ runs our copy as all-session', () => {
    for (const origin of [
      'http://localhost:5175',
      'http://127.0.0.1:5173',
      'https://app.example.com',
    ]) {
      const approval = autoApprovalFor(runRequest(), topFrame(origin), EXT_ID, ORIGINS, PLUGINS);
      expect(approval).toEqual({
        ok: true,
        mode: 'all-session',
        plugin: PLUGIN,
        origin,
        values: VALUES,
        requestId: 'req-1',
        sessionData: { mode: 'Proxy', proofId: 'p-1', method: 'EXAMPLE_MEMBERSHIP' },
      });
    }
  });

  it('the previous packaged version runs too (rollout window)', () => {
    const previous = builtIn(TEMPLATE.replace('REVEAL', 'REVEAL '));
    const approval = autoApprovalFor(
      runRequest({ fingerprint: previous.sha256 }),
      topFrame('http://localhost:5175'),
      EXT_ID,
      ORIGINS,
      [PLUGIN, previous],
    );
    expect(approval.ok && approval.plugin).toEqual(previous);
  });

  it('foreign origin ⇒ refused', () => {
    for (const origin of [
      'https://example.com',
      'http://localhost:5174',
      'https://app.example.com.evil.com',
      'http://app.example.com',
    ]) {
      expect(autoApprovalFor(runRequest(), topFrame(origin), EXT_ID, ORIGINS, PLUGINS)).toEqual({
        ok: false,
        error: 'NOT_PRODUCT_PAGE',
      });
    }
  });

  it('iframe, non-tab, other extension or unreadable origin ⇒ refused', () => {
    const page = topFrame('http://localhost:5175');
    for (const sender of [
      { ...page, frameId: 3 },
      { ...page, frameId: undefined },
      { ...page, tab: undefined },
      { ...page, id: 'otherextension' },
      { ...page, origin: undefined, url: 'not a url' },
      { ...page, origin: 'null' },
    ]) {
      expect(autoApprovalFor(runRequest(), sender, EXT_ID, ORIGINS, PLUGINS)).toEqual({
        ok: false,
        error: 'NOT_PRODUCT_PAGE',
      });
    }
    // origin missing (older Chrome): taken from the frame URL
    expect(senderProductOrigin({ ...page, origin: undefined }, EXT_ID, ORIGINS)).toBe(
      'http://localhost:5175',
    );
  });

  it('no origin list ⇒ refused', () => {
    expect(
      autoApprovalFor(runRequest(), topFrame('http://localhost:5175'), EXT_ID, [], PLUGINS),
    ).toEqual({ ok: false, error: 'NOT_PRODUCT_PAGE' });
  });

  it('unknown pluginId ⇒ refused; known id with another fingerprint ⇒ version mismatch', () => {
    const page = topFrame('http://localhost:5175');
    for (const pluginId of ['other-plugin', '', undefined, 'GITHUB', '../x', 42]) {
      expect(autoApprovalFor(runRequest({ pluginId }), page, EXT_ID, ORIGINS, PLUGINS)).toEqual({
        ok: false,
        error: 'UNKNOWN_PLUGIN',
      });
    }
    for (const fingerprint of ['f'.repeat(64), PLUGIN.sha256.toUpperCase(), undefined, '']) {
      expect(autoApprovalFor(runRequest({ fingerprint }), page, EXT_ID, ORIGINS, PLUGINS)).toEqual({
        ok: false,
        error: 'PLUGIN_VERSION_MISMATCH',
      });
    }
    expect(autoApprovalFor(runRequest(), page, EXT_ID, ORIGINS, [])).toEqual({
      ok: false,
      error: 'UNKNOWN_PLUGIN',
    });
  });

  it('bad values ⇒ refused', () => {
    const page = topFrame('http://localhost:5175');
    for (const extra of [
      { verifierUrl: 'http://x" + evil() + "' },
      { proxyUrl: 'ws://x y' },
      { params: '{"a":1} + evil()' },
      { params: { a: 1 } },
      { requestId: 'req 1' },
      { requestId: 7 },
      { sessionData: { mode: 'Proxy', _autoApproved: '1' } },
      { sessionData: { mode: 'Proxy', _approvalMode: 'all-session' } },
      { sessionData: { mode: 'Native' } },
      { sessionData: { mode: 'Proxy', proofId: 'a"b' } },
      { sessionData: { mode: 'Proxy', proofId: 'p-1', nonce: 'n-1', method: 'EXAMPLE_MEMBERSHIP' } }, // No raw nonce
      { sessionData: { mode: 'Proxy', proofId: 5 } },
      { sessionData: 'mode=Proxy' },
    ]) {
      expect(autoApprovalFor(runRequest(extra), page, EXT_ID, ORIGINS, PLUGINS)).toEqual({
        ok: false,
        error: 'BAD_VALUES',
      });
    }
  });

  it('a page cannot smuggle code: a `code` field is ignored, only our copy is named', () => {
    const approval = autoApprovalFor(
      runRequest({ code: 'export default { main(){ steal() } }' }),
      topFrame('http://localhost:5175'),
      EXT_ID,
      ORIGINS,
      PLUGINS,
    );
    expect(approval.ok).toBe(true);
    expect(JSON.stringify(approval)).not.toContain('steal');
  });

  it('the offscreen sessionData is the page keys, then ours (the page cannot set ours)', () => {
    const approval = autoApprovalFor(
      runRequest(),
      topFrame('http://localhost:5175'),
      EXT_ID,
      ORIGINS,
      PLUGINS,
    );
    if (!approval.ok) throw new Error('refused');
    expect(offscreenSessionData(approval)).toEqual({
      mode: 'Proxy',
      proofId: 'p-1',
      method: 'EXAMPLE_MEMBERSHIP',
      _approvalMode: 'all-session',
      _autoApproved: '1',
    });
    expect(checkPageSessionData(undefined)).toEqual({});
  });
});
