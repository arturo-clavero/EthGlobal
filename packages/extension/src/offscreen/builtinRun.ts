/**
 * The offscreen half of a built-in plugin
 * run. The background has already decided (background/autoApproval.ts: top
 * frame, allowed origin, built-in id + fingerprint, checked values) and sends
 * RUN_BUILTIN_OFFSCREEN with the plugin id, fingerprint and values, never code.
 * Here the plugin is read from the extension's own package, its sha256 must be
 * the fingerprint, and the values are filled in by its layout
 * (constants/builtinPlugins.ts substitutePlugin, which maps the result back to
 * the packaged template). Only the result reaches QuickJS.
 */
import {
  BUILTIN_PLUGINS,
  builtInPluginPath,
  findBuiltInPlugin,
  pluginLayout,
  sha256Hex,
  substitutePlugin,
  type BuiltInPlugin,
  type RunValues,
} from '../constants/builtinPlugins';

/** The parts of a runtime.MessageSender the check reads. */
export interface OffscreenSender {
  id?: string;
  tab?: unknown;
  url?: string;
}

export interface BuiltInRunMessage {
  type: 'RUN_BUILTIN_OFFSCREEN';
  pluginId: string;
  fingerprint: string;
  values: RunValues;
  requestId?: string | null;
  sessionData: Record<string, string>;
}

export interface BuiltInRunDeps {
  extensionId: string;
  /** The background service worker's URL (only it may start a run). */
  backgroundUrl?: string;
  plugins?: readonly BuiltInPlugin[];
  /** Reads a packaged file as text (default: fetch of chrome.runtime.getURL(path)). */
  readPackaged: (path: string) => Promise<string>;
}

/**
 * The code to execute for this message (and the sha256 of the packaged file
 * it comes from), or why not. The sender must be our
 * background (our ID, no tab: a content script always has one), the plugin a
 * built-in version, the packaged file exactly that version, the values valid.
 */
export async function prepareBuiltInRun(
  msg: unknown,
  sender: OffscreenSender,
  deps: BuiltInRunDeps,
): Promise<{ code: string; sha256: string } | { error: string }> {
  try {
    if (!sender || sender.id !== deps.extensionId || sender.tab) return { error: 'NOT_BACKGROUND' };
    if (deps.backgroundUrl && sender.url && sender.url !== deps.backgroundUrl) {
      return { error: 'NOT_BACKGROUND' };
    }
    const m = (msg ?? {}) as Partial<BuiltInRunMessage>;
    const found = findBuiltInPlugin(m.pluginId, m.fingerprint, deps.plugins ?? BUILTIN_PLUGINS);
    if ('error' in found) return { error: found.error };
    const template = await deps.readPackaged(builtInPluginPath(found.plugin));
    const sha256 = await sha256Hex(template);
    if (sha256 !== found.plugin.sha256) return { error: 'PLUGIN_CORRUPT' };
    const layout = pluginLayout(template);
    if (JSON.stringify(layout) !== JSON.stringify(found.plugin.layout))
      return { error: 'PLUGIN_CORRUPT' };
    const code = substitutePlugin(template, layout, m.values);
    // `sha256` is the hash of the packaged file this run executes (the
    // code maps back to it byte for byte); the runner reports it (pluginHash.ts).
    return code === null ? { error: 'BAD_VALUES' } : { code, sha256 };
  } catch {
    return { error: 'PLUGIN_UNAVAILABLE' };
  }
}

/** Default reader: the extension's own packaged file. */
export async function readPackagedFile(path: string): Promise<string> {
  const chrome = (globalThis as unknown as { chrome: typeof globalThis.chrome }).chrome;
  const res = await fetch(chrome.runtime.getURL(path), { cache: 'no-store' });
  if (!res.ok) throw new Error(`packaged ${path}: ${res.status}`);
  return res.text();
}
