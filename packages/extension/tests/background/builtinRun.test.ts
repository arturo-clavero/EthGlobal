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
import { MAX_METHODS, methodSlots } from '../../src/constants/builtinPlugins';
import { validateProvePermission } from '../../src/offscreen/permissionValidator';
import { METHOD_PARAMS, METHOD_URLS, TEMPLATE_METHODS } from '../helpers/builtinRunFixture';
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

// One window, a URL pair per method. Each proof
// keeps its own upgrade token; every per-method URL gets the run pair's checks.
describe('per-method URL pairs (one window, each proof its own token)', () => {
  const LAYOUT = pluginLayout(TEMPLATE_METHODS);
  const TWO = builtIn(TEMPLATE_METHODS);
  const RUN_PAIR = {
    verifierUrl: 'http://localhost:7048',
    proxyUrl: 'ws://localhost:7048/proxy?token=',
  };
  const values = (methodUrls: unknown = METHOD_URLS) => ({
    ...RUN_PAIR,
    params: JSON.stringify(METHOD_PARAMS),
    methodUrls,
  });
  // What a split/join of each method's placeholders would give.
  const reference = (pairs: Record<string, { verifierUrl: string; proxyUrl: string }>) => {
    let code = TEMPLATE_METHODS;
    for (const [method, pair] of Object.entries(pairs)) {
      const [v, p] = methodSlots(method);
      code = code.split(v).join(pair.verifierUrl).split(p).join(pair.proxyUrl);
    }
    return code.replace(/(["'])__PLUGIN_PARAMS__\1/, () =>
      JSON.stringify(JSON.stringify(METHOD_PARAMS)),
    );
  };
  /** Evaluates the filled bundle: its permissions and the prove() calls it makes. */
  const evaluate = async (code: string) => {
    const calls: Array<{ req: { url: string; method: string }; opts: Record<string, unknown> }> =
      [];
    const prove = async (req: { url: string; method: string }, opts: Record<string, unknown>) => {
      calls.push({ req, opts });
    };
    const body = code.replace(/export \{ plugin_default as default \};/, 'return plugin_default;');
    const plugin = new Function('prove', body)(prove) as {
      onClick: () => Promise<void>;
      config: { requests: unknown[] };
    };
    await plugin.onClick();
    return { calls, config: plugin.config };
  };

  it('lays out both halves of every method pair, no run pair needed', () => {
    const slots = LAYOUT.filter((x) => typeof x === 'string');
    expect([...new Set(slots)].sort()).toEqual(
      [
        '"__PLUGIN_PARAMS__"',
        ...methodSlots('EXAMPLE_WORK'),
        ...methodSlots('EXAMPLE_MEMBERSHIP'),
      ].sort(),
    );
    expect(parseBuiltInPlugins(JSON.stringify([TWO, PLUGIN]))).toEqual([TWO, PLUGIN]);
  });

  it("fills each method's slots with its own pair (byte for byte), and maps back to the template", () => {
    const code = substitutePlugin(TEMPLATE_METHODS, LAYOUT, values());
    expect(code).toBe(reference(METHOD_URLS));
    expect(canonicalizePlugin(code!, LAYOUT)).toBe(TEMPLATE_METHODS);
  });

  it('each prove() carries its own token URLs and passes the permission of its own method only', async () => {
    const { calls, config } = await evaluate(substitutePlugin(TEMPLATE_METHODS, LAYOUT, values())!);
    expect(calls.map((c) => [c.opts.verifierUrl, c.opts.proxyUrl, c.opts.sessionData])).toEqual([
      [
        METHOD_URLS.EXAMPLE_WORK.verifierUrl,
        `${METHOD_URLS.EXAMPLE_WORK.proxyUrl}github.com`,
        { proofId: 'pr-proof' },
      ],
      [
        METHOD_URLS.EXAMPLE_MEMBERSHIP.verifierUrl,
        `${METHOD_URLS.EXAMPLE_MEMBERSHIP.proxyUrl}github.com`,
        { proofId: 'org-proof' },
      ],
    ]);
    const urls = (c: (typeof calls)[number]) => ({
      verifierUrl: String(c.opts.verifierUrl),
      proxyUrl: String(c.opts.proxyUrl),
    });
    for (const c of calls) {
      expect(() => validateProvePermission(c.req, urls(c), config as never)).not.toThrow();
    }
    // The other proof's token URLs never pass this request's permission.
    expect(() => validateProvePermission(calls[0].req, urls(calls[1]), config as never)).toThrow(
      /Permission denied/,
    );
    expect(() => validateProvePermission(calls[1].req, urls(calls[0]), config as never)).toThrow(
      /Permission denied/,
    );
  });

  it('a bundle with only per-method slots needs a pair for every method (no fallback to another token)', () => {
    const only = { EXAMPLE_WORK: METHOD_URLS.EXAMPLE_WORK };
    for (const methodUrls of [only, undefined]) {
      const run = { ...values(), methodUrls };
      expect(checkRunValues(run, LAYOUT)).toBeNull();
      expect(substitutePlugin(TEMPLATE_METHODS, LAYOUT, run)).toBeNull();
      // Refused in the background, before any window opens.
      expect(
        autoApprovalFor(
          runRequest({
            fingerprint: TWO.sha256,
            params: JSON.stringify(METHOD_PARAMS),
            methodUrls,
          }),
          topFrame('http://localhost:5175'),
          EXT_ID,
          ORIGINS,
          [TWO],
        ),
      ).toEqual({ ok: false, error: 'BAD_VALUES' });
    }
    // Without a layout only the shape is checked (the background and offscreen always pass one).
    expect(checkRunValues(values(only))).not.toBeNull();
  });

  it("in a bundle that also has the run pair, a method the page does not name gets the run's pair", () => {
    const mixed = TEMPLATE_METHODS.split('__VERIFIER_URL_EXAMPLE_WORK__')
      .join('__VERIFIER_URL__')
      .split('__PROXY_URL_EXAMPLE_WORK__')
      .join('__PROXY_URL__');
    const only = { EXAMPLE_MEMBERSHIP: METHOD_URLS.EXAMPLE_MEMBERSHIP };
    const [v, p] = methodSlots('EXAMPLE_MEMBERSHIP');
    const expected = mixed
      .split(v)
      .join(only.EXAMPLE_MEMBERSHIP.verifierUrl)
      .split(p)
      .join(only.EXAMPLE_MEMBERSHIP.proxyUrl)
      .split('__VERIFIER_URL__')
      .join(RUN_PAIR.verifierUrl)
      .split('__PROXY_URL__')
      .join(RUN_PAIR.proxyUrl)
      .replace(/(["'])__PLUGIN_PARAMS__\1/, () => JSON.stringify(JSON.stringify(METHOD_PARAMS)));
    expect(substitutePlugin(mixed, pluginLayout(mixed), values(only))).toBe(expected);
  });

  it('the canonicalizePlugin round trip refuses a fill that does not map back to the template', () => {
    // A hand-made layout (never what pluginLayout gives) where a URL slot is followed by a URL
    // character: the filled URL would swallow it, so the result is not this template plus data.
    const template =
      'var v = "__VERIFIER_URL__"; var p = __PROXY_URL__x; var j = JSON.parse("__PLUGIN_PARAMS__");';
    const layout = (t: string) => {
      const out: Array<number | string> = [];
      let pos = 0;
      for (const slot of ['__VERIFIER_URL__', '__PROXY_URL__', '"__PLUGIN_PARAMS__"']) {
        const at = t.indexOf(slot, pos);
        out.push(at - pos, slot);
        pos = at + slot.length;
      }
      out.push(t.length - pos);
      return out;
    };
    const run = { ...RUN_PAIR, params: '{}' };
    expect(substitutePlugin(template, layout(template), run)).toBeNull();
    // Control: the same layout with a non-URL character after the slot fills fine.
    const ok = template.replace('__PROXY_URL__x', '__PROXY_URL__ ');
    expect(substitutePlugin(ok, layout(ok), run)).toBe(
      ok
        .replace('__VERIFIER_URL__', RUN_PAIR.verifierUrl)
        .replace('__PROXY_URL__', RUN_PAIR.proxyUrl)
        .replace('"__PLUGIN_PARAMS__"', JSON.stringify('{}')),
    );
  });

  it(`refuses to lay out a bundle with more than ${MAX_METHODS} methods`, () => {
    const pairs = (n: number) =>
      Array.from({ length: n }, (_, i) => {
        const [v, p] = methodSlots(`M${i}`);
        return `prove({}, { verifierUrl: "${v}", proxyUrl: "${p}" });`;
      }).join('\n');
    const bundle = (n: number) => `var RUN = JSON.parse("__PLUGIN_PARAMS__");\n${pairs(n)}\n`;
    expect(pluginLayout(bundle(MAX_METHODS)).filter((x) => typeof x === 'string')).toHaveLength(
      2 * MAX_METHODS + 1,
    );
    expect(() => pluginLayout(bundle(MAX_METHODS + 1))).toThrow(/more than 8 methods/);
  });

  it('the run-pair bundle (the previous release) is unchanged and takes no method it does not have', () => {
    const legacy = pluginLayout(TEMPLATE);
    expect(substitutePlugin(TEMPLATE, legacy, VALUES)).toBe(
      preparePluginCode(TEMPLATE, {
        verifierUrl: VALUES.verifierUrl,
        proxyUrl: VALUES.proxyUrl,
        params: PARAMS,
      }),
    );
    expect(substitutePlugin(TEMPLATE, legacy, { ...VALUES, methodUrls: METHOD_URLS })).toBeNull();
    expect(checkRunValues({ ...VALUES, methodUrls: METHOD_URLS }, legacy)).toBeNull();
  });

  const BAD_URLS: Array<[string, unknown]> = [
    ['a URL that leaves its literal', 'http://x" + evil() + "'],
    ['a URL with a backslash', 'ws://x\\u0022'],
    ['a URL with whitespace', 'http://x y'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['an empty URL', ''],
    ['a URL as a number', 7048],
    ['a URL over 2048 characters', `http://x/${'a'.repeat(2048)}`],
  ];
  for (const [label, bad] of BAD_URLS) {
    for (const half of ['verifierUrl', 'proxyUrl'] as const) {
      it(`refuses a per-method ${half}: ${label} (the run pair's check)`, () => {
        const methodUrls = {
          ...METHOD_URLS,
          EXAMPLE_MEMBERSHIP: { ...METHOD_URLS.EXAMPLE_MEMBERSHIP, [half]: bad },
        };
        expect(checkRunValues({ ...RUN_PAIR, [half]: bad, params: '{}' })).toBeNull();
        expect(checkRunValues(values(methodUrls))).toBeNull();
        expect(substitutePlugin(TEMPLATE_METHODS, LAYOUT, values(methodUrls))).toBeNull();
      });
    }
  }

  it('refuses malformed methodUrls', () => {
    const pr = METHOD_URLS.EXAMPLE_WORK;
    const many = Object.fromEntries(
      Array.from({ length: MAX_METHODS + 1 }, (_, i) => [`M${i}`, pr]),
    );
    for (const bad of [
      null,
      'EXAMPLE_WORK',
      [pr],
      {},
      many,
      { example_work: pr },
      JSON.parse(`{"__proto__": ${JSON.stringify(pr)}}`),
      { GITHUB__PR: pr },
      { EXAMPLE_: pr },
      { _GITHUB: pr },
      { 'GITHUB-PR': pr },
      { [`A${'B'.repeat(64)}`]: pr },
      { EXAMPLE_WORK: null },
      { EXAMPLE_WORK: 'http://x' },
      { EXAMPLE_WORK: [pr.verifierUrl, pr.proxyUrl] },
      { EXAMPLE_WORK: { verifierUrl: pr.verifierUrl } },
      { EXAMPLE_WORK: { ...pr, code: 'steal()' } },
      { EXAMPLE_WORK: { ...pr, verifierUrl: undefined } },
    ]) {
      expect(checkRunValues(values(bad))).toBeNull();
      expect(substitutePlugin(TEMPLATE_METHODS, LAYOUT, values(bad))).toBeNull();
    }
    // A method this bundle does not have is refused once the layout is known.
    const other = { ...METHOD_URLS, EXAMPLE_OTHER: pr };
    expect(checkRunValues(values(other))).not.toBeNull();
    expect(checkRunValues(values(other), LAYOUT)).toBeNull();
    expect(substitutePlugin(TEMPLATE_METHODS, LAYOUT, values(other))).toBeNull();
  });

  it('refuses to lay out a bundle with half a pair or a non-literal method placeholder', () => {
    expect(() =>
      pluginLayout(
        TEMPLATE_METHODS.split('__PROXY_URL_EXAMPLE_MEMBERSHIP__').join(
          '__PROXY_URL_EXAMPLE_WORK__',
        ),
      ),
    ).toThrow(/__PROXY_URL_EXAMPLE_MEMBERSHIP__ missing/);
    expect(() =>
      pluginLayout(
        TEMPLATE_METHODS.replace(
          '"__PROXY_URL_EXAMPLE_WORK__" + HOST',
          '`__PROXY_URL_EXAMPLE_WORK__${HOST}`',
        ),
      ),
    ).toThrow(/string literal/);
    expect(() =>
      pluginLayout(
        TEMPLATE_METHODS.replace(
          '"__VERIFIER_URL_EXAMPLE_WORK__"',
          '"__VERIFIER_URL_EXAMPLE_WORK__x"',
        ),
      ),
    ).toThrow(/string literal/);
    // The run pair stays all or nothing.
    expect(() => pluginLayout(TEMPLATE.split('"__PROXY_URL__"').join('"x"'))).toThrow(
      /__PROXY_URL__ missing/,
    );
  });

  it('an index entry with a malformed method slot is refused (fail closed)', () => {
    for (const slot of ['__VERIFIER_URL_bad__', '__VERIFIER_URL___', '__TOKEN_URL_A__']) {
      expect(parseBuiltInPlugins(JSON.stringify([{ ...TWO, layout: [1, slot, 2] }]))).toEqual([]);
    }
  });

  it('autoApprovalFor: one RUN_BUILTIN with both pairs runs; a method this version lacks is BAD_VALUES', () => {
    const page = topFrame('http://localhost:5175');
    const request = runRequest({
      fingerprint: TWO.sha256,
      params: JSON.stringify(METHOD_PARAMS),
      methodUrls: METHOD_URLS,
    });
    const approval = autoApprovalFor(request, page, EXT_ID, ORIGINS, [TWO]);
    expect(approval.ok && approval.values).toEqual({
      verifierUrl: VALUES.verifierUrl,
      proxyUrl: VALUES.proxyUrl,
      params: JSON.stringify(METHOD_PARAMS),
      methodUrls: METHOD_URLS,
    });
    for (const methodUrls of [
      { ...METHOD_URLS, EXAMPLE_OTHER: METHOD_URLS.EXAMPLE_WORK },
      { EXAMPLE_WORK: { verifierUrl: 'http://x y', proxyUrl: 'ws://x' } },
      null,
    ]) {
      expect(autoApprovalFor({ ...request, methodUrls }, page, EXT_ID, ORIGINS, [TWO])).toEqual({
        ok: false,
        error: 'BAD_VALUES',
      });
    }
    // The previous release's bundle has no method slots: per-method pairs are refused for it.
    expect(
      autoApprovalFor(runRequest({ methodUrls: METHOD_URLS }), page, EXT_ID, ORIGINS, PLUGINS),
    ).toEqual({ ok: false, error: 'BAD_VALUES' });
  });
});
