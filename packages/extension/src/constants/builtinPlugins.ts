/**
 * Built-in plugins: the verification
 * plugins ship INSIDE the extension. The page never sends JavaScript; it asks
 * "run built-in plugin <id> (fingerprint <sha256>) with these values" through
 * `window.tlsn.runBuiltIn()`, and the extension runs its own packaged copy
 * (`builtin-plugins/<id>-<sha256>.js`, copied in by build.sh). Chrome MV3
 * forbids executing remotely fetched code, also as data through an
 * interpreter; with this the only code QuickJS runs is code in the package.
 *
 * Per-run values: the built bundle
 * keeps three placeholders: `__VERIFIER_URL__` and `__PROXY_URL__` inside "…"
 * string literals (every occurrence) and the first `"__PLUGIN_PARAMS__"`
 * literal. The extension fills them in ITS OWN copy, by the bundle's layout
 * (segment lengths alternating with the placeholder between them): each URL
 * must be plain URL characters (the page's URL_SAFE alphabet, so it cannot
 * leave its string literal) and the same value goes to every occurrence; the
 * params arrive as JSON text and go in as exactly one JSON string literal.
 * `canonicalizePlugin` then maps the result back to the template, which must
 * be the packaged file byte for byte (belt and braces: a value can only ever be
 * data inside a string literal). Same rules as the earlier plugin allowlist,
 * now applied to the extension's own copy instead of page-supplied code.
 *
 * Build-time index: build.sh computes [{id, sha256, layout}] of the bundles it
 * packages (builtin-plugins.mts → FORK_PLUGIN_ALLOWLIST) and webpack bakes it
 * in as __FORK_PLUGIN_ALLOWLIST__ (the earlier allowlist's name). Missing or
 * malformed = empty = nothing can run (fail closed). The index may hold two
 * versions of a plugin (the current and the previously released one) so a
 * page deploy and an extension update need not land at the same moment.
 * No imports: build.sh also loads this file with Node.
 */
declare const __FORK_PLUGIN_ALLOWLIST__: string | undefined;

export const URL_SLOTS = ['__VERIFIER_URL__', '__PROXY_URL__'] as const;
export const PARAMS_SLOTS = ['"__PLUGIN_PARAMS__"', "'__PLUGIN_PARAMS__'"] as const;
const SLOTS: readonly string[] = [...URL_SLOTS, ...PARAMS_SLOTS];

/** Segment length, then a placeholder, then a segment length, …, ending with a segment length. */
export type PluginLayout = Array<number | string>;

export interface BuiltInPlugin {
  id: string;
  /** sha256 of the packaged bundle (the template), lowercase hex: the plugin's fingerprint. */
  sha256: string;
  layout: PluginLayout;
}

/** The values a page may supply for one run (nothing else reaches the plugin). */
export interface RunValues {
  verifierUrl: string;
  proxyUrl: string;
  /** JSON text of the params object; goes in as one JSON string literal. */
  params: string;
}

/** The page's URL_SAFE alphabet (no quotes, backslashes or whitespace). */
const URL_CHAR = /[A-Za-z0-9:/._?=&%~+-]/;
const URL_VALUE = /^(?:https?|wss?):\/\/[A-Za-z0-9:/._?=&%~+-]{1,2040}$/;
export const PARAMS_MAX_BYTES = 256 * 1024;
const HEX64 = /^[0-9a-f]{64}$/;
export const PLUGIN_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** Packaged path of a built-in plugin (build.sh copies each bundle here). */
export function builtInPluginPath(plugin: Pick<BuiltInPlugin, 'id' | 'sha256'>): string {
  return `builtin-plugins/${plugin.id}-${plugin.sha256}.js`;
}

/**
 * Layout of a built bundle (build time, and again at run time on the packaged
 * copy). Throws when the bundle lacks a placeholder or a URL placeholder is
 * not a whole "…" literal.
 */
export function pluginLayout(template: string): PluginLayout {
  const hits: Array<{ at: number; slot: string }> = [];
  for (const slot of URL_SLOTS) {
    let at = template.indexOf(slot);
    if (at < 0) throw new Error(`placeholder ${slot} missing`);
    while (at >= 0) {
      if (template[at - 1] !== '"' || template[at + slot.length] !== '"') {
        throw new Error(`${slot} at ${at} is not a whole "…" string literal`);
      }
      hits.push({ at, slot });
      at = template.indexOf(slot, at + slot.length);
    }
  }
  // Like the page's preparePluginCode: the first params literal only.
  const params = /(["'])__PLUGIN_PARAMS__\1/.exec(template);
  if (!params) throw new Error('placeholder __PLUGIN_PARAMS__ missing');
  hits.push({ at: params.index, slot: params[0] });
  hits.sort((a, b) => a.at - b.at);
  const layout: PluginLayout = [];
  let pos = 0;
  for (const { at, slot } of hits) {
    if (at < pos) throw new Error('overlapping placeholders');
    layout.push(at - pos, slot);
    pos = at + slot.length;
  }
  layout.push(template.length - pos);
  return layout;
}

/** End index of the JSON string literal starting at `p`, or -1. */
function jsonStringEnd(code: string, p: number): number {
  if (code[p] !== '"') return -1;
  for (let i = p + 1; i < code.length; i++) {
    const c = code.charCodeAt(i);
    if (c === 0x22) return i + 1;
    if (c < 0x20) return -1;
    if (c === 0x5c) {
      const e = code[i + 1];
      if (e === 'u') {
        if (!/^[0-9a-fA-F]{4}$/.test(code.slice(i + 2, i + 6))) return -1;
        i += 5;
      } else if (e !== undefined && '"\\/bfnrt'.includes(e)) {
        i += 1;
      } else {
        return -1;
      }
    }
  }
  return -1;
}

/**
 * The template behind `code` if `code` is this layout with each placeholder
 * replaced by a value of its grammar (the same value for every occurrence of
 * a URL placeholder); null otherwise.
 */
export function canonicalizePlugin(code: string, layout: PluginLayout): string | null {
  const out: string[] = [];
  const urls = new Map<string, string>();
  let p = 0;
  for (const item of layout) {
    if (typeof item === 'number') {
      if (p + item > code.length) return null;
      out.push(code.slice(p, p + item));
      p += item;
      continue;
    }
    let end = p;
    if ((PARAMS_SLOTS as readonly string[]).includes(item)) {
      end = jsonStringEnd(code, p);
      if (end < 0) return null;
    } else {
      while (end < code.length && URL_CHAR.test(code[end])) end++;
      if (end === p) return null;
      const value = code.slice(p, end);
      const seen = urls.get(item);
      if (seen !== undefined && seen !== value) return null;
      urls.set(item, value);
    }
    out.push(item);
    p = end;
  }
  return p === code.length ? out.join('') : null;
}

/**
 * The page's values, checked: both URLs http(s)/ws(s) with URL characters only,
 * params the JSON text of one object (≤ 256 KiB). Anything else: null.
 */
export function checkRunValues(raw: unknown): RunValues | null {
  if (!raw || typeof raw !== 'object') return null;
  const { verifierUrl, proxyUrl, params } = raw as Record<string, unknown>;
  if (typeof verifierUrl !== 'string' || !URL_VALUE.test(verifierUrl)) return null;
  if (typeof proxyUrl !== 'string' || !URL_VALUE.test(proxyUrl)) return null;
  if (typeof params !== 'string' || params.length > PARAMS_MAX_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(params);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  return { verifierUrl, proxyUrl, params };
}

/**
 * Our packaged `template` with the run's values filled in by its `layout`, or
 * null when a value is refused or the result does not map back to the
 * template exactly. Byte for byte what the page's preparePluginCode makes
 * of the same values.
 */
export function substitutePlugin(
  template: string,
  layout: PluginLayout,
  raw: unknown,
): string | null {
  const values = checkRunValues(raw);
  if (!values) return null;
  const out: string[] = [];
  let p = 0;
  for (const item of layout) {
    if (typeof item === 'number') {
      if (p + item > template.length) return null;
      out.push(template.slice(p, p + item));
      p += item;
      continue;
    }
    if (template.slice(p, p + item.length) !== item) return null;
    if (item === '__VERIFIER_URL__') out.push(values.verifierUrl);
    else if (item === '__PROXY_URL__') out.push(values.proxyUrl);
    else if ((PARAMS_SLOTS as readonly string[]).includes(item))
      out.push(JSON.stringify(values.params));
    else return null;
    p += item.length;
  }
  if (p !== template.length) return null;
  const code = out.join('');
  return canonicalizePlugin(code, layout) === template ? code : null;
}

function validLayout(layout: unknown): layout is PluginLayout {
  if (!Array.isArray(layout) || layout.length % 2 !== 1) return false;
  return layout.every((item, i) =>
    i % 2 === 0
      ? Number.isSafeInteger(item) && (item as number) >= 0
      : typeof item === 'string' && SLOTS.includes(item),
  );
}

/** Parses the build-time JSON index; anything malformed yields [] (fail closed). */
export function parseBuiltInPlugins(json: string): BuiltInPlugin[] {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return [];
  }
  if (!Array.isArray(raw)) return [];
  const out: BuiltInPlugin[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') return [];
    const { id, sha256, layout } = entry as Record<string, unknown>;
    if (typeof id !== 'string' || !PLUGIN_ID.test(id)) return [];
    if (typeof sha256 !== 'string' || !HEX64.test(sha256)) return [];
    if (!validLayout(layout)) return [];
    if (out.some((e) => e.id === id && e.sha256 === sha256)) return [];
    out.push({ id, sha256, layout: [...layout] });
  }
  return out;
}

export const BUILTIN_PLUGINS: readonly BuiltInPlugin[] = parseBuiltInPlugins(
  typeof __FORK_PLUGIN_ALLOWLIST__ === 'string' ? __FORK_PLUGIN_ALLOWLIST__ : '',
);

/** The index entry for a run of `pluginId` @ `fingerprint`, or why it cannot run. */
export function findBuiltInPlugin(
  pluginId: unknown,
  fingerprint: unknown,
  plugins: readonly BuiltInPlugin[] = BUILTIN_PLUGINS,
): { plugin: BuiltInPlugin } | { error: 'UNKNOWN_PLUGIN' | 'PLUGIN_VERSION_MISMATCH' } {
  if (typeof pluginId !== 'string' || !PLUGIN_ID.test(pluginId)) return { error: 'UNKNOWN_PLUGIN' };
  const versions = plugins.filter((p) => p.id === pluginId);
  if (!versions.length) return { error: 'UNKNOWN_PLUGIN' };
  const plugin = versions.find((p) => p.sha256 === fingerprint);
  return plugin ? { plugin } : { error: 'PLUGIN_VERSION_MISMATCH' };
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}
