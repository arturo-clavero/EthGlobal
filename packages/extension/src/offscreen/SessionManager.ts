import Host, { canonicalizeHandler } from '@tlsn/plugin-sdk';
import { ProveManager } from './ProveManager';
import type { RevealRangeWithHandler } from './ProveManager';
import type { Method } from 'tlsn-wasm';
import type {
  CanonicalHandler,
  DomJson,
  Handler,
  OpenWindowResponse,
  PluginConfig,
  ProveProgressData,
  RevealRangeDescriptor,
  WindowMessage,
} from '@tlsn/plugin-sdk';
import { logger, bytesToBase64, base64ToBytes } from '@tlsn/common';

/**
 * Minimal interface for the Chrome runtime API surface used by SessionManager.
 * Avoids depending on the full `typeof chrome.runtime` which requires exact
 * callback signatures that conflict with our simplified listeners.
 */
interface ChromeRuntimeLike {
  id?: string;
  getURL?: (path: string) => string;
  sendMessage: (message: unknown) => Promise<unknown>;
  onMessage: {
    addListener: (listener: (...args: unknown[]) => void) => void;
    removeListener: (listener: (...args: unknown[]) => void) => void;
  };
}
import { validateProvePermission, validateOpenWindowPermission } from './permissionValidator';
import { sanitizePageProgress } from '../constants/pageProgress';
import { allowedNavigation } from '../constants/pluginNavigate';
import { proveSessionData } from './pluginHash';
import { GcpPrivateWitnessRun, PrivateWitnessRun, clearGcpOpenings } from './gcpPrivateWitness';
import type { GcpPrivateProofModule } from './gcpPrivateWitness';
import { AwsPrivateWitnessRun } from './awsPrivateWitness';
import type { AwsCapture } from '../aws-private/browser-client.mjs';
import type { RevealOutput } from 'tlsn-wasm';

/** Maximum number of preview characters shown per reveal range. */
const PREVIEW_MAX_CHARS = 256;

// Rewrite a proxy URL's origin (protocol + host) to `base`, keeping its path +
// `?token=<host>`. Lets the host page relay the prover↔server TCP through a
// reachable proxy without rebuilding plugins. No-op if base is unset/invalid.
function applyProxyBase(proxyUrl: string, base?: string): string {
  if (!base) return proxyUrl;
  try {
    const u = new URL(proxyUrl);
    // Use the base's origin (protocol + host, incl. its default port handling)
    // and keep the original path + ?token=<host>. Rebuilding from origin avoids
    // the URL.host setter retaining a stale port (e.g. :7047).
    return `${new URL(base).origin}${u.pathname}${u.search}`;
  } catch {
    return proxyUrl;
  }
}

function buildLabel(handler: CanonicalHandler): string {
  const part =
    handler.part.charAt(0).toUpperCase() + handler.part.slice(1).toLowerCase().replace(/_/g, ' ');
  if ('params' in handler && handler.params && 'path' in handler.params && handler.params.path) {
    return `${part}: ${handler.params.path}`;
  }
  if (
    'params' in handler &&
    handler.params &&
    'key' in handler.params &&
    typeof handler.params.key === 'string'
  ) {
    return `${part}: ${handler.params.key}`;
  }
  return part;
}

function makeDescriptor(
  direction: 'SENT' | 'RECV',
  range: RevealRangeWithHandler,
  bytes: Uint8Array,
  decoder: TextDecoder,
): RevealRangeDescriptor {
  const canonical = canonicalizeHandler(range.handler);
  const safeStart = Math.max(0, Math.min(range.start, bytes.length));
  const safeEnd = Math.max(safeStart, Math.min(range.end, bytes.length));
  const slice = bytes.subarray(safeStart, safeEnd);
  const action: 'REVEAL' | 'HASH' = canonical.action.kind === 'HASH' ? 'HASH' : 'REVEAL';
  const algorithm = canonical.action.kind === 'HASH' ? canonical.action.algorithm : undefined;

  let preview: string;
  if (action === 'HASH') {
    // Blinder is generated inside WASM during proving — we cannot compute the
    // actual commitment hash ahead of time. Show the algorithm name instead.
    preview = algorithm ?? 'SHA-256';
  } else {
    const raw = decoder.decode(slice);
    preview = raw.length > PREVIEW_MAX_CHARS ? raw.slice(0, PREVIEW_MAX_CHARS) + '…' : raw;
  }

  return {
    direction,
    label: buildLabel(canonical),
    action,
    algorithm,
    preview,
    length: safeEnd - safeStart,
  };
}

export class SessionManager {
  /** Shared Host instance — only used for config extraction (stateless). */
  private configHost: Host;
  private proveManager: ProveManager;
  private initPromise: Promise<void>;

  constructor() {
    // Lightweight Host for config extraction only (no execution-scoped state)
    this.configHost = new Host({
      onProve: async () => {
        throw new Error('Config host should not be used for proving');
      },
      onRenderPluginUi: () => {},
      onCloseWindow: () => {},
      onOpenWindow: async () => {
        throw new Error('Config host should not be used for opening windows');
      },
    });
    this.proveManager = new ProveManager();
    this.initPromise = this.proveManager.init();
  }

  private static getChromeRuntime(): ChromeRuntimeLike {
    const chromeRuntime = (global as unknown as { chrome?: { runtime?: ChromeRuntimeLike } }).chrome
      ?.runtime;
    if (!chromeRuntime?.sendMessage) {
      throw new Error('Chrome runtime not available');
    }
    return chromeRuntime;
  }

  /**
   * Relay: deliver an inbound MPC chunk (relayed by the page from the
   * verifier's data channel) to the active prover.
   */
  handleRelayIn(b64: string): void {
    this.proveManager.deliverRelayData(base64ToBytes(b64));
  }

  /** Relay: signal the data channel closed. */
  handleRelayClosed(): void {
    this.proveManager.signalRelayClosed();
  }

  /**
   * Create a per-execution Host with callbacks that close over execution-scoped
   * state (config, requestId, sessionData). This prevents concurrent plugin
   * executions from contaminating each other's permission validation.
   */
  private createExecutionHost(
    pluginConfig: PluginConfig | null,
    requestId: string | null,
    execSessionData: Record<string, string> | null,
    privateRun?: PrivateWitnessRun,
  ): Host {
    const proveManager = this.proveManager;
    let hostRef: Host | null = null;
    // Tracks the active managed window for this execution. Captured from
    // openWindow() / renderPluginUi callbacks so the approval gate can render
    // its overlay into the same window without a separate lookup.
    let activeWindowId = 0;

    const emitProgress = (step: string, progress: number, message: string, source = 'js') => {
      if (!requestId) return;
      const chromeRuntime = SessionManager.getChromeRuntime();
      chromeRuntime
        .sendMessage({
          type: 'PROVE_PROGRESS',
          requestId,
          step,
          progress,
          message,
          source,
        })
        .catch((err: unknown) => logger.warn('[SessionManager] emitProgress failed:', err));
    };

    // Relay an outbound MPC chunk to the page (which owns the data channel).
    const emitRelayOut = (bytes: Uint8Array) => {
      if (!requestId) return;
      SessionManager.getChromeRuntime()
        .sendMessage({ type: 'RELAY_OUT', requestId, data: bytesToBase64(bytes) })
        .catch((err: unknown) => logger.warn('[SessionManager] emitRelayOut failed:', err));
    };

    const host = new Host({
      onProve: async (
        requestOptions: {
          url: string;
          method: string;
          headers: Record<string, string>;
          body?: string;
        },
        proverOptions: {
          verifierUrl: string;
          proxyUrl: string;
          maxRecvData?: number;
          maxSentData?: number;
          handlers: Handler[];
          sessionData?: Record<string, string>;
        },
        onProgress?: (data: ProveProgressData) => void,
      ) => {
        let url;

        try {
          url = new URL(requestOptions.url);
        } catch (_error) {
          throw new Error('Invalid URL');
        }

        // Validate permissions using this execution's config (not shared state)
        validateProvePermission(requestOptions, proverOptions, pluginConfig);

        // Build sessionData with defaults + execCode-level data + plugin-provided data;
        // the runner's plugin sha256 last, never the plugin's.
        const sessionData: Record<string, string> = proveSessionData(
          execSessionData,
          proverOptions.sessionData,
        );

        // Helper: emit to both the page (via background) and the plugin UI
        const emitBoth = (step: string, progress: number, message: string) => {
          emitProgress(step, progress, message);
          onProgress?.({ step, progress, message });
        };

        // Relayed verifier mode: the verifier runs in another browser. The MPC byte
        // stream is relayed through the host page (which owns the transport
        // connection) — selected by `relay: '1'` in sessionData.
        const isRelay = sessionData.relay === '1';

        // Mode is a user/platform decision, not a plugin decision.
        // Read from sessionData provided by the caller of execCode(). Relay mode
        // supports both: in Proxy mode the verifier browser opens the server TCP
        // (through its own proxy) and the prover tunnels through the verifier.
        const mode = (sessionData.mode as 'Mpc' | 'Proxy') ?? 'Mpc';
        if (privateRun && [proverOptions.maxSentData ?? 4096, proverOptions.maxRecvData ?? 16384]
          .some(limit => !Number.isSafeInteger(limit) || limit <= 0 || limit > 16384)) {
          throw new Error('GCP_PRIVATE_PROOF_INVALID');
        }
        privateRun?.begin(sessionData, url.hostname, isRelay);
        let privateOpenings: RevealOutput | undefined;
        const modeLabel = isRelay ? `relay (${mode})` : mode === 'Proxy' ? 'Proxy' : 'MPC';
        logger.debug('[SessionManager] Prove mode:', mode, 'relay:', isRelay);

        emitBoth('CONNECTING', 0.0, `Connecting to verifier (${modeLabel} mode)...`);

        // Relay mode: tell the verifier (in the other browser) which limits to
        // commit to — same model as the verifier server, which adopts the
        // prover's maxSentData/maxRecvData from its register message. This is a
        // control frame the host page consumes (and never displays), so it goes
        // to the page only (emitProgress) — NOT emitBoth, which would render the
        // raw JSON as the plugin UI's progress text. The plugin stays on the
        // preceding "Connecting to verifier…" message.
        if (isRelay) {
          const maxSentData = proverOptions.maxSentData ?? 4096;
          const maxRecvData = proverOptions.maxRecvData ?? 16384;
          emitProgress('RELAY_LIMITS', 0.02, JSON.stringify({ maxSentData, maxRecvData, mode }));
        }

        const proverId = isRelay
          ? await proveManager.createProverRelay(
              url.hostname,
              (bytes) => emitRelayOut(bytes),
              proverOptions.maxRecvData,
              proverOptions.maxSentData,
              mode,
            )
          : await proveManager.createProver(
              url.hostname,
              proverOptions.verifierUrl,
              proverOptions.maxRecvData,
              proverOptions.maxSentData,
              sessionData,
              mode,
            ).catch(error => {
              if (privateRun) throw new Error('GCP_PRIVATE_PROOF_FAILED');
              throw error;
            });

        // Register per-prover WASM progress callback
        if (requestId) {
          proveManager.setProgressCallbackForProver(proverId, (data) => {
            emitProgress(data.step, data.progress, data.message, data.source);
          });
        }

        try {
          emitBoth('SESSION_SETUP', 0.15, `${modeLabel} session established`);

          // In Proxy mode the prover↔server traffic is tunneled through the
          // verifier session multiplexer, so no separate WebSocket to the
          // websockify proxy is opened. In MPC mode we pass the websockify URL
          // through to the worker, which will create a JsIo channel for it.
          // `proxyBase` (sessionData) overrides the plugin's build-time proxy
          // origin — used by the host page to relay through a reachable proxy
          // (e.g. wss://demo.tlsnotary.org) while keeping the ?token=<host>.
          const workerProxyUrl =
            mode === 'Proxy'
              ? undefined
              : applyProxyBase(proverOptions.proxyUrl, sessionData.proxyBase);

          // Send request via ProveManager which handles IoChannel creation in the worker.
          emitBoth('SENDING_REQUEST', 0.3, 'Sending request...');
          await this.proveManager.sendRequest(proverId, workerProxyUrl, {
            url: requestOptions.url,
            method: requestOptions.method as Method,
            headers: requestOptions.headers,
            body: requestOptions.body,
          });

          // Compute reveal ranges via WASM (parses HTTP transcripts + maps handlers to byte ranges)
          emitBoth('PROCESSING_TRANSCRIPT', 0.5, 'Processing transcript...');
          const { sentRanges, recvRanges, sentRangesWithHandlers, recvRangesWithHandlers, commit } =
            privateRun ? await privateRun.selectRanges(
              proveManager.getSessionId(proverId), url.hostname,
              proveManager.getSentBytes(proverId), proveManager.getRecvBytes(proverId),
              () => proveManager.computeReveal(proverId, proverOptions.handlers),
            ) : await proveManager.computeReveal(proverId, proverOptions.handlers);

          if (!privateRun) {
            logger.debug('sentRanges', sentRanges);
            logger.debug('recvRanges', recvRanges);
            if (commit) logger.debug('commitRanges', commit);
          }

          // Approval gate: in any mode other than 'all-session', show the user
          // exactly which byte ranges will leave the device before they do.
          const approvalMode = execSessionData?._approvalMode ?? 'manual';
          if (approvalMode !== 'all-session') {
            const decoder = new TextDecoder('utf-8', { fatal: false });
            const sentBytes = proveManager.getSentBytes(proverId);
            const recvBytes = proveManager.getRecvBytes(proverId);
            const descriptors: RevealRangeDescriptor[] = [
              ...sentRangesWithHandlers.map((r) => makeDescriptor('SENT', r, sentBytes, decoder)),
              ...recvRangesWithHandlers.map((r) => makeDescriptor('RECV', r, recvBytes, decoder)),
            ];

            emitBoth('WAITING_FOR_REVEAL_APPROVAL', 0.55, 'Awaiting reveal approval...');

            const explicitWindowId = parseInt(execSessionData?._windowId ?? '0', 10);
            const targetWindowId = explicitWindowId > 0 ? explicitWindowId : activeWindowId;
            logger.debug(
              '[SessionManager] reveal approval: targetWindowId=%d activeWindowId=%d descriptors=%d',
              targetWindowId,
              activeWindowId,
              descriptors.length,
            );

            await new Promise<void>((resolve, reject) => {
              if (!hostRef) {
                reject(new Error('Host not initialized for reveal approval'));
                return;
              }
              hostRef.registerRevealApproval(resolve, (err: Error) => reject(err), descriptors);
            });
          }

          // Send reveal config (ranges + handlers) to verifier BEFORE calling reveal().
          // Relay mode has no server control channel — the WASM verifier in the
          // other browser learns the revealed ranges directly through the MPC.
          if (!isRelay) {
            emitBoth('SENDING_REVEAL_CONFIG', 0.6, 'Configuring selective disclosure...');
            await proveManager.sendRevealConfig(proverId, {
              sent: sentRangesWithHandlers,
              recv: recvRangesWithHandlers,
            });
          }

          // Reveal the ranges (and hash-commit ranges if any handlers use action: HASH).
          // openings.sent[i] / openings.recv[i] expose { hash, blinder } for each
          // hash-committed range, so callers can later prove H(plaintext || blinder)
          // == hash without rerunning MPC-TLS. Empty when no commit was supplied.
          emitBoth('GENERATING_PROOF', 0.7, 'Generating proof...');
          const openings = await proveManager.reveal(
            proverId,
            { sent: sentRanges, recv: recvRanges },
            commit,
          );
          if (privateRun) privateOpenings = openings;

          // Get structured response from verifier. In relay mode the result lives
          // on the verifying browser (its own verify() output) — there is no
          // server response to wait for, so the prover just completes.
          emitBoth('WAITING_FOR_VERIFICATION', 0.85, 'Waiting for verification...');
          const response = isRelay
            ? { results: [], relay: true }
            : await proveManager.getResponse(proverId);

          emitBoth('COMPLETE', 1.0, 'Complete');

          if (privateRun) return await privateRun.accept(
            proveManager.getSessionId(proverId), url.hostname,
            proveManager.getSentBytes(proverId), proveManager.getRecvBytes(proverId), openings, response,
          );
          return response;
        } catch (error) {
          if (privateRun) {
            privateRun.clear();
            throw new Error('GCP_PRIVATE_PROOF_FAILED');
          }
          throw error;
        } finally {
          if (privateRun) {
            clearGcpOpenings(privateOpenings);
            proveManager.getSentBytes(proverId).fill(0);
            proveManager.getRecvBytes(proverId).fill(0);
          }
          // Always clean up prover resources to prevent memory leaks
          await proveManager.cleanupProver(proverId);
        }
      },
      onRenderPluginUi: (windowId: number, result: DomJson) => {
        if (windowId > 0) {
          activeWindowId = windowId;
        }
        const chromeRuntime = SessionManager.getChromeRuntime();
        chromeRuntime.sendMessage({
          type: 'RENDER_PLUGIN_UI',
          json: result,
          windowId: windowId,
        });
      },
      onCloseWindow: (windowId: number) => {
        // SDK done() closes immediately; private proving still needs its cancel window.
        if (privateRun) return Promise.resolve(undefined);
        const chromeRuntime = SessionManager.getChromeRuntime();
        logger.debug('onCloseWindow', windowId);
        return chromeRuntime.sendMessage({
          type: 'CLOSE_WINDOW',
          windowId,
        });
      },
      onOpenWindow: async (
        url: string,
        options?: { width?: number; height?: number; showOverlay?: boolean },
      ) => {
        // Validate permissions using this execution's config (not shared state)
        validateOpenWindowPermission(url, pluginConfig);

        const chromeRuntime = SessionManager.getChromeRuntime();
        const response = (await chromeRuntime.sendMessage({
          type: 'OPEN_WINDOW',
          url,
          width: options?.width,
          height: options?.height,
          showOverlay: options?.showOverlay,
          ...(privateRun instanceof AwsPrivateWitnessRun ? { awsPrivateRequestId: requestId } : {}),
        })) as OpenWindowResponse;

        if (response?.type === 'WINDOW_OPENED' && response.payload?.windowId) {
          activeWindowId = response.payload.windowId;
          this.runWindows.set(host, activeWindowId); // For navigate()
        }

        return response;
      },
    });
    hostRef = host;
    return host;
  }

  /**
   * `reportProgress` only for a run the background
   * auto-approved (an allowlisted plugin on an allowed-origin page; it writes
   * _autoApproved after the page's sessionData) that the page can match (a
   * requestId). Checked fields only (constants/pageProgress.ts). Other runs
   * have no such capability.
   */
  private addPageProgress(
    host: Host,
    requestId: string | null,
    execSessionData: Record<string, string> | null,
  ): void {
    if (execSessionData?._autoApproved !== '1' || !requestId) return;
    host.addCapability('reportProgress', (raw: unknown) => {
      const progress = sanitizePageProgress(raw);
      if (!progress) return;
      SessionManager.getChromeRuntime()
        .sendMessage({ type: 'PLUGIN_PROGRESS', requestId, progress })
        .catch((err: unknown) => logger.warn('[SessionManager] reportProgress failed:', err));
    });
  }

  /** The window each run opened (navigate() may only move that one). */
  private runWindows = new WeakMap<Host, number>();

  /**
   * `navigate(url)` sends the run's own window to GitHub's
   * logout/login/account switcher (constants/pluginNavigate.ts, exact URLs) so a wrong account can be switched without
   * leaving the run. Only for a run the background auto-approved (as reportProgress) with a requestId (the background
   * finds the run by it and checks it again). Returns false when refused; never throws into the plugin.
   */
  private addNavigate(
    host: Host,
    requestId: string | null,
    execSessionData: Record<string, string> | null,
  ): void {
    if (execSessionData?._autoApproved !== '1' || !requestId) return;
    host.addCapability('navigate', (raw: unknown) => {
      const url = allowedNavigation(raw);
      const windowId = this.runWindows.get(host);
      if (!url || !windowId) return false;
      SessionManager.getChromeRuntime()
        .sendMessage({ type: 'PLUGIN_NAVIGATE', requestId, windowId, url })
        .catch((err: unknown) => logger.warn('[SessionManager] navigate failed:', err));
      return true;
    });
  }

  async awaitInit(): Promise<SessionManager> {
    await this.initPromise;
    return this;
  }

  async executePlugin(
    code: string,
    requestId?: string,
    sessionData?: Record<string, string>,
    // Supplied only by a compiled offscreen caller after prepareBuiltInRun(), never a message field.
    privateProof?: GcpPrivateProofModule | PrivateWitnessRun,
  ): Promise<unknown> {
    const chromeRuntime = SessionManager.getChromeRuntime();
    if (!chromeRuntime.onMessage) {
      throw new Error('Chrome runtime not available');
    }

    const execRequestId = requestId || null;

    // Extract plugin config for permission validation (scoped to this execution)
    const pluginConfig = await this.extractConfig(code);
    if (!privateProof) logger.debug('[SessionManager] Extracted plugin config:', pluginConfig);

    // Create a per-execution Host with callbacks that close over this execution's state
    const privateRun = privateProof instanceof PrivateWitnessRun ? privateProof :
      privateProof ? new GcpPrivateWitnessRun(sessionData || {}, execRequestId, privateProof) : undefined;
    const host = this.createExecutionHost(pluginConfig, execRequestId, sessionData || null, privateRun);
    this.addPageProgress(host, execRequestId, sessionData || null);
    this.addNavigate(host, execRequestId, sessionData || null);
    if (privateRun instanceof AwsPrivateWitnessRun) host.addCapability('collectAwsPrivate', (captureId: unknown) => {
      const windowId = this.runWindows.get(host);
      if (!windowId || typeof captureId !== 'string' || !/^[A-Za-z0-9._-]{1,256}$/.test(captureId)) throw new Error('AWS_PRIVATE_COLLECTION_FAILED');
      return privateRun.collect(async () => await chromeRuntime.sendMessage({ type: 'AWS_PRIVATE_CREDENTIALS',
        requestId: execRequestId, windowId, captureId }) as AwsCapture);
    });

    // Wrap the plugin's event listener so it does NOT return a Promise to
    // Chrome's messaging API. The plugin listener (makeOpenWindow's onMessage)
    // is async, so it always returns a Promise. If added directly to
    // chrome.runtime.onMessage, Chrome may use its Promise<undefined> as the
    // response to unrelated messages (e.g. GET_PLUGIN_STATS_OFFSCREEN), racing with the
    // offscreen's main listener that returns the actual result.
    const listenerWrappers = new Map<
      (message: WindowMessage) => void,
      (message: unknown) => void
    >();
    // SDK done() ends its window listener before local ZK proving finishes.
    // Keep cancellation scoped to this run's real window through the final proof.
    const cancelPrivateOnClose = (raw: unknown, source: unknown) => {
      if (!privateRun || !chromeRuntime.id || !chromeRuntime.getURL || !raw || typeof raw !== 'object' ||
          !source || typeof source !== 'object') return;
      const message = raw as { type?: unknown; windowId?: unknown };
      const sender = source as { id?: unknown; url?: unknown; tab?: unknown };
      if (message.type === 'WINDOW_CLOSED' && typeof message.windowId === 'number' &&
          message.windowId === this.runWindows.get(host) && sender.id === chromeRuntime.id && sender.tab === undefined &&
          (sender.url === undefined || sender.url === chromeRuntime.getURL('background.bundle.js'))) privateRun.clear();
    };
    if (privateRun) chromeRuntime.onMessage.addListener(cancelPrivateOnClose);

    try {
      const result = await host.executePlugin(code, {
        eventEmitter: {
          addListener: (listener: (message: WindowMessage) => void) => {
            const wrapper = (message: unknown) => {
              // Fire-and-forget: don't return the Promise so Chrome doesn't
              // treat it as a messaging response.
              listener(message as WindowMessage);
            };
            listenerWrappers.set(listener, wrapper);
            chromeRuntime.onMessage.addListener(wrapper);
          },
          removeListener: (listener: (message: WindowMessage) => void) => {
            const wrapper = listenerWrappers.get(listener);
            if (wrapper) {
              chromeRuntime.onMessage.removeListener(wrapper);
              listenerWrappers.delete(listener);
            }
          },
          emit: (message: WindowMessage) => {
            chromeRuntime.sendMessage(message);
          },
        },
      });
      // Ignore done() data for private runs: only the compiled proof module may cross the page boundary.
      if (privateRun) this.proveManager.releaseIdleWorker();
      return privateRun ? await privateRun.finish() : result;
    } catch (error) {
      if (privateRun) throw new Error('GCP_PRIVATE_PROOF_FAILED');
      throw error;
    } finally {
      if (privateRun) chromeRuntime.onMessage.removeListener(cancelPrivateOnClose);
      privateRun?.clear();
      const windowId = privateRun ? this.runWindows.get(host) : undefined;
      if (windowId !== undefined) {
        this.runWindows.delete(host);
        await chromeRuntime.sendMessage({ type: 'CLOSE_WINDOW', windowId }).catch(() => {});
      }
    }
  }

  /**
   * Extract plugin config using QuickJS sandbox (more reliable than regex)
   */
  async extractConfig(code: string): Promise<PluginConfig | null> {
    return (await this.configHost.getPluginConfig(code)) ?? null;
  }
}
