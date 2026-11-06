/**
 * Shared fixture for the built-in plugin tests. One
 * built-in plugin shaped like a real built bundle, a RUN_BUILTIN
 * request as the embedding page sends it, and what the background hands the offscreen
 * document for it (or null: refused, nothing runs).
 */
import { createHash } from 'node:crypto';
import {
  autoApprovalFor,
  offscreenSessionData,
  type ExecSender,
} from '../../src/background/autoApproval';
import { pluginLayout, type BuiltInPlugin } from '../../src/constants/builtinPlugins';

export const EXT_ID = 'test-extension-id';
export const ALLOWED_PAGE = 'http://localhost:5175';

// Shaped like a built verification plugin bundle (esbuild output).
export const TEMPLATE = [
  '// src/verification-plugins/example-work/plugin.ts',
  'var P = JSON.parse("__PLUGIN_PARAMS__");',
  'var HOST = "github.com";',
  'var perm = (pathname) => ({ method: "GET", host: HOST, pathname, verifierUrl: "__VERIFIER_URL__" });',
  'var config = { name: "GitHub private work", requests: [perm("/orgs")] };',
  'function main() { return null; }',
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

// Shaped like the bundle with a URL pair per method (two checks in order,
// each with its own upgrade token in its URLs).
export const TEMPLATE_METHODS = [
  '// src/verification-plugins/example-work/plugin.ts',
  'var RUN = JSON.parse("__PLUGIN_PARAMS__");',
  'var HOST = "github.com";',
  'var perm = (pathname) => ({ method: "GET", host: HOST, pathname, verifierUrl: "__VERIFIER_URL_EXAMPLE_WORK__", proxyUrl: "__PROXY_URL_EXAMPLE_WORK__" + HOST });',
  'var perm2 = (pathname) => ({ method: "GET", host: HOST, pathname, verifierUrl: "__VERIFIER_URL_EXAMPLE_MEMBERSHIP__", proxyUrl: "__PROXY_URL_EXAMPLE_MEMBERSHIP__" + HOST });',
  'var config = { name: "GitHub private work", requests: [perm("/search"), perm2("/orgs/*/people")] };',
  'function main() { return null; }',
  'async function onClick() {',
  '  await prove({ url: "https://github.com/search", method: "GET" }, {',
  '    verifierUrl: "__VERIFIER_URL_EXAMPLE_WORK__",',
  '    proxyUrl: "__PROXY_URL_EXAMPLE_WORK__" + HOST,',
  '    sessionData: { proofId: RUN.prWork.proofId },',
  '  });',
  '  await prove({ url: "https://github.com/orgs/acme/people", method: "GET" }, {',
  '    verifierUrl: "__VERIFIER_URL_EXAMPLE_MEMBERSHIP__",',
  '    proxyUrl: "__PROXY_URL_EXAMPLE_MEMBERSHIP__" + HOST,',
  '    sessionData: { proofId: RUN.membership.proofId },',
  '  });',
  '}',
  'var plugin_default = { main, onClick, config };',
  'export { plugin_default as default };',
  '',
].join('\n');

/** Two proofs in one window, each with its own token (as the server issues them). */
export const METHOD_URLS = {
  EXAMPLE_WORK: {
    verifierUrl: 'http://localhost:7048/v/0.1.0.1501/t/1790000000.pr-proof.TokPr_1',
    proxyUrl: 'ws://localhost:7048/v/0.1.0.1501/t/1790000000.pr-proof.TokPr_1/proxy?token=',
  },
  EXAMPLE_MEMBERSHIP: {
    verifierUrl: 'http://localhost:7048/v/0.1.0.1501/t/1790000000.org-proof.TokOrg_2',
    proxyUrl: 'ws://localhost:7048/v/0.1.0.1501/t/1790000000.org-proof.TokOrg_2/proxy?token=',
  },
};
export const METHOD_PARAMS = {
  prWork: { proofId: 'pr-proof' },
  membership: { proofId: 'org-proof' },
};

export const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

export function builtIn(template = TEMPLATE, id = 'example-work'): BuiltInPlugin {
  return { id, sha256: sha256(template), layout: pluginLayout(template) };
}

export const PLUGIN = builtIn();
export const PLUGINS: readonly BuiltInPlugin[] = [PLUGIN];

export const topFrame = (origin: string, extra: Partial<ExecSender> = {}): ExecSender => ({
  id: EXT_ID,
  origin,
  url: `${origin}/apply/setup/x`,
  frameId: 0,
  tab: { id: 1 },
  ...extra,
});

export const PARAMS = {
  membership: { org: 'acme', login: 'dev-one', nonceMac: 'aB-_x9' },
  // hostile-looking data stays data: quotes, backslashes, newlines, unicode, placeholders
  note: 'a "quote" \\ back\nline   é 😀 __VERIFIER_URL__ "__PLUGIN_PARAMS__" </script>',
};

/** A RUN_BUILTIN request as our content script forwards it. */
export const runRequest = (extra: Record<string, unknown> = {}) => ({
  type: 'RUN_BUILTIN',
  pluginId: PLUGIN.id,
  fingerprint: PLUGIN.sha256,
  verifierUrl: 'http://localhost:7048',
  proxyUrl: 'ws://localhost:7048/proxy?token=',
  params: JSON.stringify(PARAMS),
  requestId: 'req-1',
  sessionData: { mode: 'Proxy', proofId: 'p-1', method: 'EXAMPLE_MEMBERSHIP' },
  ...extra,
});

/**
 * What Background RUN_BUILTIN hands the offscreen document as sessionData for
 * this request (the page's checked keys, then the background's), or null when
 * the background refuses it (then nothing runs at all).
 */
export function offscreenSessionDataFor(
  request: unknown,
  sender: ExecSender,
  plugins: readonly BuiltInPlugin[] = PLUGINS,
): Record<string, string> | null {
  const approval = autoApprovalFor(request, sender, EXT_ID, [ALLOWED_PAGE], plugins);
  return approval.ok ? offscreenSessionData(approval) : null;
}
