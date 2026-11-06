/**
 * The allowed origins. Only pages on these origins get
 * `window.tlsn.extensionId` and answers to `window.tlsn.helperStatus()`; any
 * other site sees no extension ID and gets no helper answer, so it cannot
 * learn whether the native helper is installed. proveNative keeps its own
 * checks (plugin permissions, offscreen-only relay) and is not affected.
 *
 * Build-time list: build.sh passes FORK_PRODUCT_ORIGINS (comma-separated
 * origins) to webpack as __FORK_PRODUCT_ORIGINS__. Dev build default:
 * http://localhost:5173, http://127.0.0.1:5173, http://localhost:5175,
 * http://127.0.0.1:5175. A production build (FORK_KEY_FILE) must set it to the
 * embedding page's https origin(s). No list (e.g. a plain upstream `npm run build`)
 * means no origin is allowed (fail closed).
 */
declare const __FORK_PRODUCT_ORIGINS__: string | undefined;

/**
 * Parses a comma-separated origin list. Keeps exact origins only
 * (`scheme://host[:port]`, no path, no trailing slash); `http:` only for
 * localhost and 127.0.0.1. Anything else is dropped.
 */
export function parseProductOrigins(csv: string): string[] {
  const out: string[] = [];
  for (const raw of csv.split(',')) {
    const value = raw.trim();
    if (!value) continue;
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      continue;
    }
    if (url.origin !== value) continue; // path, trailing slash, userinfo, default port spelled out
    const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) continue;
    if (!out.includes(value)) out.push(value);
  }
  return out;
}

export const PRODUCT_ORIGINS: readonly string[] = parseProductOrigins(
  typeof __FORK_PRODUCT_ORIGINS__ === 'string' ? __FORK_PRODUCT_ORIGINS__ : '',
);

/** Exact match against the build-time list (no wildcards, no suffix match). */
export function isProductOrigin(
  origin: string | null | undefined,
  allowed: readonly string[] = PRODUCT_ORIGINS,
): boolean {
  return typeof origin === 'string' && allowed.includes(origin);
}
