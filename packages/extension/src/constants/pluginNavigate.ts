/**
 * When the wrong account is
 * signed in, a trusted plugin keeps its window open and offers "Switch account": it may send ITS OWN window to one of these
 * pages, and nowhere else. Exact strings (no prefix, query, fragment or redirect parameter); anything else is refused.
 *
 * Only runs that autoApprovalFor() approved get the capability (an allowlisted plugin, top frame of an allowed-origin
 * tab; decided in the background, fail closed), and the background checks the URL, the sender (our offscreen
 * document), the run (an auto-approved route) and the window (a managed one) again before it navigates.
 *
 * Build-time list: build.sh passes FORK_NAVIGATE_URLS (comma-separated exact https URLs) to webpack as
 * __FORK_NAVIGATE_URLS__. No list (the default) means no navigation target (fail closed).
 */
declare const __FORK_NAVIGATE_URLS__: string | undefined;

/**
 * Parses a comma-separated URL list. Keeps exact https URLs only (already in canonical form, no userinfo, query or
 * fragment); anything else is dropped.
 */
export function parseNavigateUrls(csv: string): string[] {
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
    if (url.href !== value || url.protocol !== 'https:') continue;
    if (url.username || url.password || url.search || url.hash || value.includes('?') || value.includes('#'))
      continue;
    if (!out.includes(value)) out.push(value);
  }
  return out;
}

export const PLUGIN_NAVIGATE_URLS: readonly string[] = Object.freeze(
  parseNavigateUrls(typeof __FORK_NAVIGATE_URLS__ === 'string' ? __FORK_NAVIGATE_URLS__ : ''),
);

/** `url` itself when it is exactly one of PLUGIN_NAVIGATE_URLS; null for anything else. */
export function allowedNavigation(url: unknown): string | null {
  if (typeof url !== 'string') return null;
  return PLUGIN_NAVIGATE_URLS.includes(url) ? url : null;
}

export interface PluginNavigateGate {
  /** Our extension's ID (browser.runtime.id). */
  extensionId: string;
  /** Our offscreen document's URL (runtime.getURL('offscreen.html')). */
  offscreenUrl: string;
  /** True only for a live run that the background auto-approved (RUN_BUILTIN marked its route). */
  isAutoApprovedRun: (requestId: string) => boolean;
  /** The tab of a window the extension manages (opened by a plugin); undefined otherwise. */
  tabOfWindow: (windowId: number) => number | undefined;
}

/**
 * The background's decision for a PLUGIN_NAVIGATE message: the tab to navigate and the URL, or null (refused).
 * Every condition must hold; any doubt refuses.
 */
export function pluginNavigateTarget(
  message: unknown,
  sender: { id?: string; url?: string; tab?: unknown; frameId?: number } | undefined,
  gate: PluginNavigateGate,
): { tabId: number; url: string } | null {
  if (!message || typeof message !== 'object') return null;
  const m = message as Record<string, unknown>;
  if (m.type !== 'PLUGIN_NAVIGATE') return null;
  // Only our own offscreen document (never a content script, a page or another extension).
  if (!sender || sender.id !== gate.extensionId || sender.tab || sender.url !== gate.offscreenUrl)
    return null;
  if (typeof m.requestId !== 'string' || !m.requestId || !gate.isAutoApprovedRun(m.requestId))
    return null;
  const url = allowedNavigation(m.url);
  if (!url) return null;
  if (typeof m.windowId !== 'number' || !Number.isInteger(m.windowId) || m.windowId <= 0)
    return null;
  const tabId = gate.tabOfWindow(m.windowId);
  if (typeof tabId !== 'number') return null;
  return { tabId, url };
}
