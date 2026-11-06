/**
 * Auto-approval of allowlisted plugins on
 * allowed origins only; everything else keeps the stock prompt.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  canonicalizePlugin,
  matchAllowedPlugin,
  parsePluginAllowlist,
  PLUGIN_ALLOWLIST,
  pluginLayout,
  type AllowedPlugin,
} from '../../src/constants/pluginAllowlist';
import { autoApprovalFor, senderProductOrigin } from '../../src/background/autoApproval';
import { parseProductOrigins } from '../../src/constants/productOrigins';

const EXT = 'djikndclbfiillgjioganlljdlhfepkd';
const ORIGINS = parseProductOrigins(
  'http://localhost:5173,http://127.0.0.1:5173,http://localhost:5175,http://127.0.0.1:5175,https://app.example.com',
);

// Shaped like a built verification plugin bundle (esbuild output).
const TEMPLATE = [
  '// src/verification-plugins/github-private-org/plugin.ts',
  'var P = JSON.parse("__PLUGIN_PARAMS__");',
  'var HOST = "github.com";',
  'var perm = (pathname) => ({ method: "GET", host: HOST, pathname, verifierUrl: "__VERIFIER_URL__" });',
  'var config = { name: "GitHub organization membership", requests: [perm("/orgs")] };',
  'async function onClick() {',
  '  await prove({ url: "https://github.com/" + P.org }, {',
  '    verifierUrl: "__VERIFIER_URL__",',
  '    proxyUrl: "__PROXY_URL__" + HOST,',
  '    handlers: [{ type: "RECV", part: "BODY", action: "REVEAL" }],',
  '  });',
  '}',
  'var plugin_default = { main, onClick, config };',
  'export { plugin_default as default };',
  '',
].join('\n');

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

function entry(template = TEMPLATE, id = 'github-private-org'): AllowedPlugin {
  return { id, sha256: sha256(template), layout: pluginLayout(template) };
}

// Same substitution as the page's preparePluginCode.
function prepare(
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

const SUBS = {
  verifierUrl: 'http://localhost:7048',
  proxyUrl: 'ws://localhost:7048/proxy?token=',
  params: {
    org: 'acme',
    nonce: 'aB-_x9',
    // hostile-looking data stays data: quotes, backslashes, newlines, unicode, placeholders
    note: 'a "quote" \\ back\nline   é 😀 __VERIFIER_URL__ "__PLUGIN_PARAMS__"',
  },
};
const RUN = prepare(TEMPLATE, SUBS);

const PAGE = (origin: string, extra: Record<string, unknown> = {}) => ({
  id: EXT,
  tab: { id: 7 },
  frameId: 0,
  origin,
  url: `${origin}/apply/setup/x`,
  ...extra,
});

describe('pluginLayout / canonicalizePlugin', () => {
  it('maps a prepared run back to the exact template', () => {
    expect(canonicalizePlugin(RUN, pluginLayout(TEMPLATE))).toBe(TEMPLATE);
  });

  it('refuses code that differs outside the placeholders', () => {
    const layout = pluginLayout(TEMPLATE);
    // same length: canonicalizes, but not to the template (the hash check refuses it)
    expect(canonicalizePlugin(RUN.replace('REVEAL', 'REVEAX'), layout)).not.toBe(TEMPLATE);
    expect(canonicalizePlugin(RUN + ' ', layout)).toBeNull();
    expect(canonicalizePlugin(RUN.slice(1), layout)).toBeNull();
    expect(canonicalizePlugin('', layout)).toBeNull();
  });

  it('refuses values outside their grammar', () => {
    const layout = pluginLayout(TEMPLATE);
    // a URL value that would break out of its string literal
    expect(
      canonicalizePlugin(
        prepare(TEMPLATE, { ...SUBS, verifierUrl: 'http://x" + evil() + "' }),
        layout,
      ),
    ).toBeNull();
    // the two verifierUrl occurrences must carry the same value
    const twoUrls = RUN.replace('"http://localhost:7048"', '"http://localhost:7049"');
    expect(canonicalizePlugin(twoUrls, layout)).toBeNull();
    // params must be one JSON string literal
    expect(
      canonicalizePlugin(
        TEMPLATE.replace('"__PLUGIN_PARAMS__"', '"{}" + evil()')
          .split('__VERIFIER_URL__')
          .join('http://v')
          .split('__PROXY_URL__')
          .join('ws://p'),
        layout,
      ),
    ).toBeNull();
    // empty URL
    expect(canonicalizePlugin(prepare(TEMPLATE, { ...SUBS, proxyUrl: '' }), layout)).toBeNull();
  });

  it('refuses to build a layout for a bundle without whole-literal placeholders', () => {
    expect(() => pluginLayout('var a = 1;')).toThrow(/missing/);
    expect(() =>
      pluginLayout(TEMPLATE.replace('"__PROXY_URL__" + HOST', '`__PROXY_URL__${HOST}`')),
    ).toThrow(/string literal/);
    expect(() =>
      pluginLayout(TEMPLATE.replace('JSON.parse("__PLUGIN_PARAMS__")', 'JSON.parse(x)')),
    ).toThrow(/__PLUGIN_PARAMS__ missing/);
  });
});

describe('parsePluginAllowlist (fail closed)', () => {
  const good = entry();

  it('keeps a well-formed list', () => {
    expect(parsePluginAllowlist(JSON.stringify([good]))).toEqual([good]);
  });

  it('is empty for a missing or malformed list', () => {
    for (const bad of [
      '',
      'not json',
      '{}',
      'null',
      JSON.stringify([{ ...good, sha256: 'abc' }]),
      JSON.stringify([{ ...good, sha256: good.sha256.toUpperCase() }]),
      JSON.stringify([{ ...good, id: '../x' }]),
      JSON.stringify([{ ...good, layout: [1, '__EVIL__', 2] }]),
      JSON.stringify([{ ...good, layout: [1, '__VERIFIER_URL__'] }]),
      JSON.stringify([{ ...good, layout: [-1] }]),
      JSON.stringify([good, null]),
    ]) {
      expect(parsePluginAllowlist(bad)).toEqual([]);
    }
  });

  it('has no build-time list under vitest (nothing is auto-approved)', () => {
    expect(PLUGIN_ALLOWLIST).toEqual([]);
  });
});

describe('matchAllowedPlugin', () => {
  it('matches a prepared run of a listed bundle', async () => {
    expect((await matchAllowedPlugin(RUN, [entry()]))?.id).toBe('github-private-org');
  });

  it('does not match an unlisted or modified bundle', async () => {
    const other = TEMPLATE.replace('REVEAL', 'REVEAX');
    expect(await matchAllowedPlugin(prepare(other, SUBS), [entry()])).toBeNull();
    expect(await matchAllowedPlugin(RUN, [entry(other)])).toBeNull();
    expect(await matchAllowedPlugin(RUN, [])).toBeNull();
    expect(await matchAllowedPlugin(undefined, [entry()])).toBeNull();
  });
});

describe('autoApprovalFor (EXEC_CODE)', () => {
  const list = [entry()];

  it('allowed origin + listed hash ⇒ auto-approve as all-session', async () => {
    for (const origin of [
      'http://localhost:5175',
      'http://127.0.0.1:5173',
      'https://app.example.com',
    ]) {
      const auto = await autoApprovalFor(RUN, PAGE(origin), EXT, ORIGINS, list);
      expect(auto).toEqual({ mode: 'all-session', plugin: list[0], origin });
    }
  });

  it('allowed origin + unlisted hash ⇒ prompt', async () => {
    const unlisted = prepare(TEMPLATE.replace('REVEAL', 'REVEAX'), SUBS);
    expect(
      await autoApprovalFor(unlisted, PAGE('http://localhost:5175'), EXT, ORIGINS, list),
    ).toBeNull();
    expect(
      await autoApprovalFor('export default {}', PAGE('http://localhost:5175'), EXT, ORIGINS, list),
    ).toBeNull();
  });

  it('foreign origin + listed hash ⇒ prompt', async () => {
    for (const origin of [
      'https://example.com',
      'http://localhost:5174',
      'https://app.example.com.evil.com',
      'http://app.example.com',
    ]) {
      expect(await autoApprovalFor(RUN, PAGE(origin), EXT, ORIGINS, list)).toBeNull();
    }
  });

  it('malformed or missing list ⇒ prompt', async () => {
    const page = PAGE('http://localhost:5175');
    expect(await autoApprovalFor(RUN, page, EXT, ORIGINS, parsePluginAllowlist(''))).toBeNull();
    expect(
      await autoApprovalFor(RUN, page, EXT, ORIGINS, parsePluginAllowlist('[{"id":1}]')),
    ).toBeNull();
    // defaults = the build-time lists, empty under vitest
    expect(await autoApprovalFor(RUN, page, EXT)).toBeNull();
  });

  it('no origin list ⇒ prompt', async () => {
    expect(
      await autoApprovalFor(RUN, PAGE('http://localhost:5175'), EXT, parseProductOrigins(''), list),
    ).toBeNull();
  });

  it('only our top-frame content script counts as the page', async () => {
    const page = PAGE('http://localhost:5175');
    for (const sender of [
      { ...page, frameId: 3 }, // iframe
      { ...page, frameId: undefined },
      { ...page, tab: undefined }, // not a tab
      { ...page, id: 'otherextension' },
      { ...page, origin: undefined, url: 'not a url' },
      { ...page, origin: 'null' },
    ]) {
      expect(await autoApprovalFor(RUN, sender, EXT, ORIGINS, list)).toBeNull();
    }
    // origin missing (older Chrome): taken from the frame URL
    expect(senderProductOrigin({ ...page, origin: undefined }, EXT, ORIGINS)).toBe(
      'http://localhost:5175',
    );
  });
});
