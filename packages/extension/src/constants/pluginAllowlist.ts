/**
 * The allowlist of the trusted plugins. EXEC_CODE
 * skips the stock approval prompt only for a plugin on this list AND a
 * allowed-origin page (background/autoApproval.ts); anything else gets the
 * unchanged prompt.
 *
 * What is hashed: the page sends the built plugin bundle with three per-run
 * values substituted (the page's `preparePluginCode`):
 * `__VERIFIER_URL__` and `__PROXY_URL__` inside "…" string literals (plain URL
 * characters only, every occurrence) and the first `"__PLUGIN_PARAMS__"`
 * literal, replaced whole by a JSON string literal. So the exact code differs
 * per run. Each entry carries the sha256 of the built bundle (the template,
 * byte for byte as served) and its layout: segment lengths alternating with
 * the placeholder that sits between them. `canonicalizePlugin` puts the
 * placeholders back (checking each value's grammar: URL characters only, or
 * one JSON string literal) and the result must hash to the entry's sha256.
 * A substituted value can only be data inside a string literal; any other
 * difference changes the hash.
 *
 * Build-time list: build.sh computes it from the built bundles
 * (plugin-allowlist.mts → FORK_PLUGIN_ALLOWLIST) and webpack bakes it in as
 * __FORK_PLUGIN_ALLOWLIST__. Missing or malformed = empty = no auto-approval
 * (fail closed). No imports: build.sh also loads this file with Node.
 */
declare const __FORK_PLUGIN_ALLOWLIST__: string | undefined;

export const URL_SLOTS = ['__VERIFIER_URL__', '__PROXY_URL__'] as const;
export const PARAMS_SLOTS = ['"__PLUGIN_PARAMS__"', "'__PLUGIN_PARAMS__'"] as const;
const SLOTS: readonly string[] = [...URL_SLOTS, ...PARAMS_SLOTS];

/** Segment length, then a placeholder, then a segment length, …, ending with a segment length. */
export type PluginLayout = Array<number | string>;

export interface AllowedPlugin {
  id: string;
  sha256: string;
  layout: PluginLayout;
}

/** The page's URL_SAFE alphabet (no quotes, backslashes or whitespace). */
const URL_CHAR = /[A-Za-z0-9:/._?=&%~+-]/;
const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^[a-z0-9][a-z0-9-]{0,63}$/;

/**
 * Layout of a built bundle (build time). Throws when the bundle lacks a
 * placeholder or a URL placeholder is not a whole "…" literal (its value's end
 * could not be found unambiguously).
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
  // Like preparePluginCode: the first params literal only.
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
 * a URL placeholder); null otherwise. Hash the result and compare.
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

function validLayout(layout: unknown): layout is PluginLayout {
  if (!Array.isArray(layout) || layout.length % 2 !== 1) return false;
  return layout.every((item, i) =>
    i % 2 === 0
      ? Number.isSafeInteger(item) && (item as number) >= 0
      : typeof item === 'string' && SLOTS.includes(item),
  );
}

/** Parses the build-time JSON list; anything malformed yields [] (fail closed). */
export function parsePluginAllowlist(json: string): AllowedPlugin[] {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return [];
  }
  if (!Array.isArray(raw)) return [];
  const out: AllowedPlugin[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') return [];
    const { id, sha256, layout } = entry as Record<string, unknown>;
    if (typeof id !== 'string' || !ID.test(id)) return [];
    if (typeof sha256 !== 'string' || !HEX64.test(sha256)) return [];
    if (!validLayout(layout)) return [];
    out.push({ id, sha256, layout: [...layout] });
  }
  return out;
}

export const PLUGIN_ALLOWLIST: readonly AllowedPlugin[] = parsePluginAllowlist(
  typeof __FORK_PLUGIN_ALLOWLIST__ === 'string' ? __FORK_PLUGIN_ALLOWLIST__ : '',
);

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** The allowlisted plugin `code` is an instance of, or null (also on any error). */
export async function matchAllowedPlugin(
  code: unknown,
  allowlist: readonly AllowedPlugin[] = PLUGIN_ALLOWLIST,
): Promise<AllowedPlugin | null> {
  if (typeof code !== 'string') return null;
  try {
    for (const entry of allowlist) {
      const template = canonicalizePlugin(code, entry.layout);
      if (template !== null && (await sha256Hex(template)) === entry.sha256) return entry;
    }
  } catch {
    return null;
  }
  return null;
}
