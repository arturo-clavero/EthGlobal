// Note: This file runs in page context, not extension context
// We use console.log here intentionally as @tlsn/common may not be available
import { installPageApi } from './pageApiLock';

// Injected by webpack DefinePlugin from package.json
declare const __EXTENSION_VERSION__: string;

/**
 * ExtensionAPI - Public API exposed to web pages via window.tlsn
 *
 * Provides methods for web pages to interact with the TLSN extension,
 * including opening new windows for notarization.
 */
// This extension's ID, set by the content script on the <script>
// element that loads this file (read synchronously, while it is current).
const FORK_EXTENSION_ID: string | null = (() => {
  try {
    const id = (document.currentScript as HTMLScriptElement | null)?.dataset?.extensionId;
    return id && /^[a-p]{32}$/.test(id) ? id : null;
  } catch {
    return null;
  }
})();

// The built-in plugins (id + fingerprint), tagged by the content script on
// allowed origins only (constants/builtinPlugins.ts); elsewhere none.
const FORK_BUILTIN_PLUGINS: ReadonlyArray<Readonly<{ id: string; sha256: string }>> = (() => {
  try {
    const raw = JSON.parse(
      (document.currentScript as HTMLScriptElement | null)?.dataset?.builtinPlugins ?? '[]',
    ) as unknown;
    if (!Array.isArray(raw)) return [];
    return Object.freeze(
      raw
        .filter(
          (e) =>
            e &&
            typeof e.id === 'string' &&
            /^[a-z0-9][a-z0-9-]{0,63}$/.test(e.id) &&
            typeof e.sha256 === 'string' &&
            /^[0-9a-f]{64}$/.test(e.sha256),
        )
        .map((e) => Object.freeze({ id: e.id as string, sha256: e.sha256 as string })),
    );
  } catch {
    return [];
  }
})();

/** What a page may ask for one run of a built-in plugin. */
interface RunBuiltInOptions {
  pluginId: string;
  /** sha256 of the plugin bundle the page was built with (one of builtInPlugins). */
  fingerprint: string;
  verifierUrl: string;
  proxyUrl: string;
  /** JSON text of the plugin params object. */
  params: string;
  /**
   * One verifier/proxy URL pair per method (proof) in this window,
   * e.g. {EXAMPLE_WORK: {verifierUrl, proxyUrl}, EXAMPLE_MEMBERSHIP: {…}};
   * each proof keeps its own upgrade token. A method not named gets the
   * run's pair above.
   */
  methodUrls?: Record<string, { verifierUrl: string; proxyUrl: string }>;
  requestId?: string;
  sessionData?: Record<string, string>;
}

class ExtensionAPI {
  // Extension version (matches manifest). Pages can compare against a
  // minimum required version to detect outdated installs.
  readonly version: string = __EXTENSION_VERSION__;

  // Lets the page tell this build from the stock one (UX only;
  // the verifier checks the real Origin).
  readonly extensionId: string | null = FORK_EXTENSION_ID;

  // The plugins this build carries (allowed origins only).
  readonly builtInPlugins: ReadonlyArray<Readonly<{ id: string; sha256: string }>> =
    FORK_BUILTIN_PLUGINS;

  /**
   * Run one of the extension's BUILT-IN
   * plugins with this run's values. The page never sends code (the stock
   * page-code entry point is removed); the extension runs its own packaged
   * copy, only for the embedding pages (allowed origins, top frame) and only the
   * fingerprint it carries. Progress events (`TLSN_PLUGIN_PROGRESS`,
   * `TLSN_PROVE_PROGRESS`) carry `requestId`.
   */
  async runBuiltIn(options: RunBuiltInOptions): Promise<unknown> {
    if (!options || typeof options !== 'object') throw new Error('BAD_VALUES');
    const requestId =
      typeof options.requestId === 'string' && options.requestId
        ? options.requestId
        : `run_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    return new Promise((resolve, reject) => {
      const privateRun = options.pluginId === 'gcp-work' || options.pluginId === 'aws-private-work';
      let startTimer: ReturnType<typeof setTimeout> | undefined;
      let runTimer: ReturnType<typeof setTimeout> | undefined;
      const cleanup = () => {
        clearTimeout(startTimer); clearTimeout(runTimer);
        window.removeEventListener('message', handleMessage);
      };
      const handleMessage = (event: MessageEvent) => {
        if (event.source !== window || event.origin !== window.location.origin || event.data?.requestId !== requestId) return;
        if (privateRun && event.data?.type === 'TLSN_RUN_BUILTIN_ACK') {
          clearTimeout(startTimer);
          return;
        }
        if (event.data?.type !== 'TLSN_RUN_BUILTIN_RESPONSE') return;
        cleanup();
        if (event.data.success) resolve(event.data.result);
        else reject(new Error(event.data.error || 'Code execution failed'));
      };
      // Reloading an extension leaves this page API behind but removes its content-script connection.
      if (privateRun) {
        startTimer = setTimeout(() => { cleanup(); reject(new Error('EXTENSION_CONNECTION_LOST')); }, 10_000);
        runTimer = setTimeout(() => { cleanup(); reject(new Error('Private verification timed out')); }, 13 * 60 * 1000);
      }
      window.addEventListener('message', handleMessage);
      window.postMessage(
        {
          type: 'TLSN_RUN_BUILTIN',
          payload: {
            pluginId: options.pluginId,
            fingerprint: options.fingerprint,
            verifierUrl: options.verifierUrl,
            proxyUrl: options.proxyUrl,
            params: options.params,
            methodUrls: options.methodUrls,
            requestId,
            sessionData: options.sessionData,
          },
        },
        window.location.origin,
      );
    });
  }
}

// Expose API to the page. On an allowed origin (our
// extension ID announced) window.tlsn stays ours whichever extension's page
// script runs first (pageApiLock.ts); elsewhere assigned as upstream.
installPageApi(window, new ExtensionAPI(), FORK_EXTENSION_ID !== null);

// Dispatch event to notify page that extension is loaded
window.dispatchEvent(new CustomEvent('tlsn_loaded'));
