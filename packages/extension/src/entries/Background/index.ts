import browser from 'webextension-polyfill';
import { WindowManager } from '../../background/WindowManager';
// The PLUGIN_NAVIGATE gate (kept apart from the helper set's import lines).
import { pluginNavigateTarget } from '../../constants/pluginNavigate';
import { confirmationManager } from '../../background/ConfirmationManager';
import type { InterceptedRequest, InterceptedRequestHeader } from '../../types/window-manager';
import { validateUrl } from '../../utils/url-validator';
import { autoApprovalFor, offscreenSessionData } from '../../background/autoApproval';
import { logger } from '@tlsn/common';
import { getStoredLogLevel } from '../../utils/logLevelStorage';
import type { BackgroundMessage } from '../../types/messages';
import { GCP_PRIVATE_ROUTE_TTL_MS, liveGcpPrivateRoute, takeGcpPrivateCompletion } from '../../background/gcpPrivateCompletion';
import { waitForOffscreenReady } from '../../background/offscreenReady';

const chrome = (global as typeof globalThis).chrome;

// Initialize logger with stored log level
getStoredLogLevel().then((level) => {
  logger.init(level);
  logger.info('Background script loaded');
});

// Initialize WindowManager for multi-window support
const windowManager = new WindowManager();

// Track requestId → tabId for routing progress events back to the originating tab.
// Entries have a TTL to prevent leaks if the offscreen document crashes before cleanup.
const PROGRESS_ROUTE_TTL_MS = 5 * 60 * 1000; // 5 minutes
// `pageProgress` marks a route whose run was
// auto-approved (a trusted plugin on an allowed origin); only those get PLUGIN_PROGRESS.
const progressRoutes: Map<string, { tabId: number; createdAt: number; pageProgress?: boolean; gcpPrivate?: boolean }> =
  new Map();

// Handle extension install/update
browser.runtime.onInstalled.addListener((details) => {
  logger.info('Extension installed/updated:', details.reason);
});

// Set up webRequest listener to intercept all requests
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Check if this tab belongs to a managed window
    const managedWindow = windowManager.getWindowByTabId(details.tabId);

    if (managedWindow && details.tabId !== undefined) {
      const request: InterceptedRequest = {
        id: `${details.requestId}`,
        method: details.method,
        url: details.url,
        timestamp: Date.now(),
        tabId: details.tabId,
        requestBody: details.requestBody,
      };

      // if (details.requestBody) {
      //   console.log(details.requestBody);
      // }

      // Add request to window's request history
      windowManager.addRequest(managedWindow.id, request);
    }
  },
  { urls: ['<all_urls>'] },
  ['requestBody', 'extraHeaders'],
);

browser.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    // Check if this tab belongs to a managed window
    const managedWindow = windowManager.getWindowByTabId(details.tabId);

    if (managedWindow && details.tabId !== undefined) {
      const header: InterceptedRequestHeader = {
        id: `${details.requestId}`,
        method: details.method,
        url: details.url,
        timestamp: details.timeStamp,
        type: details.type,
        requestHeaders: details.requestHeaders || [],
        tabId: details.tabId,
      };

      // Add request to window's request history
      windowManager.addHeader(managedWindow.id, header);
    }
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders', 'extraHeaders'],
);

// Listen for window removal
browser.windows.onRemoved.addListener(async (windowId) => {
  const managedWindow = windowManager.getWindow(windowId);
  if (managedWindow) {
    logger.debug(`Managed window closed: ${managedWindow.uuid} (ID: ${windowId})`);
    await windowManager.closeWindow(windowId);
  }
});

// Listen for tab updates to show overlay when tab is ready (Task 3.4)
browser.tabs.onUpdated.addListener(async (tabId, changeInfo, _tab) => {
  // Only act when tab becomes complete
  if (changeInfo.status !== 'complete') {
    return;
  }

  // Check if this tab belongs to a managed window
  const managedWindow = windowManager.getWindowByTabId(tabId);
  if (!managedWindow) {
    return;
  }

  // If overlay should be shown but isn't visible yet, show it now
  if (managedWindow.showOverlayWhenReady && !managedWindow.overlayVisible) {
    logger.debug(`Tab ${tabId} complete, showing overlay for window ${managedWindow.id}`);
    await windowManager.showOverlay(managedWindow.id);
  }
});

// Basic message handler
browser.runtime.onMessage.addListener((msg: unknown, sender: browser.Runtime.MessageSender) => {
  const privateMessage = msg as { type?: string; requestId?: unknown };
  const privateDeps = { extensionId: browser.runtime.id, offscreenUrl: browser.runtime.getURL('offscreen.html'), now: Date.now() };
  if (privateMessage?.type === 'GCP_PRIVATE_HEARTBEAT') {
    return Promise.resolve({ ok: !!liveGcpPrivateRoute(privateMessage.requestId, sender, progressRoutes, privateDeps) });
  }
  if (privateMessage?.type === 'GCP_PRIVATE_COMPLETE') {
    const completion = takeGcpPrivateCompletion(msg, sender, progressRoutes, privateDeps);
    if (!completion) return Promise.resolve({ ok: false });
    return browser.tabs.sendMessage(completion.tabId, { type: 'RUN_BUILTIN_COMPLETE',
      requestId: completion.requestId, ...completion.response }).then(() => ({ ok: true })).catch(() => ({ ok: false }));
  }
  const request = msg as BackgroundMessage;
  logger.debug('Message received:', request.type);

  if (request.type === 'CONTENT_SCRIPT_READY') {
    if (!sender.tab?.windowId) {
      return;
    }
    windowManager.reRenderPluginUI(sender.tab.windowId as number);
    return; // No response needed
  }

  // Example response
  if (request.type === 'PING') {
    return Promise.resolve({ type: 'PONG' });
  }

  if (request.type === 'RENDER_PLUGIN_UI') {
    logger.debug('RENDER_PLUGIN_UI request received, windowId=%d', request.windowId);
    windowManager.showPluginUI(request.windowId, request.json);
    return; // No response needed
  }

  // Handle plugin code request from confirmation popup
  if (request.type === 'GET_PLUGIN_CODE') {
    const code = confirmationManager.getPluginCode(request.requestId);
    return Promise.resolve({ code: code || null });
  }

  // Handle plugin confirmation responses from popup
  if (request.type === 'PLUGIN_CONFIRM_RESPONSE') {
    logger.debug('PLUGIN_CONFIRM_RESPONSE received:', request);
    confirmationManager.handleConfirmationResponse(request.requestId, request.mode);
    return; // No response needed
  }

  // Route PROVE_PROGRESS from offscreen to the originating tab
  if (request.type === 'PROVE_PROGRESS') {
    const route = progressRoutes.get(request.requestId);
    if (route) {
      browser.tabs.sendMessage(route.tabId, {
        type: 'PROVE_PROGRESS',
        requestId: request.requestId,
        step: request.step,
        progress: request.progress,
        message: request.message,
        source: request.source,
      });
    }
    return; // No response needed
  }

  // A trusted plugin's progress → the tab that started
  // the run, only when that run was auto-approved. The fields were checked
  // where the report was made (offscreen) and are checked again where it is
  // posted to the page (content script, allowed origins only).
  // A trusted plugin's "Switch account" → its own window to
  // GitHub's logout/login/switcher only (exact URLs), for an auto-approved run,
  // from our offscreen document; any doubt refuses (constants/pluginNavigate.ts).
  if (request.type === 'PLUGIN_NAVIGATE') {
    const target = pluginNavigateTarget(request, sender, {
      extensionId: browser.runtime.id,
      offscreenUrl: browser.runtime.getURL('offscreen.html'),
      isAutoApprovedRun: (requestId) => progressRoutes.get(requestId)?.pageProgress === true,
      tabOfWindow: (windowId) => windowManager.getWindow(windowId)?.tabId,
    });
    if (!target) {
      logger.warn('PLUGIN_NAVIGATE refused');
      return Promise.resolve({ ok: false });
    }
    return browser.tabs
      .update(target.tabId, { url: target.url })
      .then(() => ({ ok: true }))
      .catch(() => ({ ok: false }));
  }

  if (request.type === 'PLUGIN_PROGRESS') {
    const route = progressRoutes.get(request.requestId);
    if (route?.gcpPrivate && !liveGcpPrivateRoute(request.requestId, sender, progressRoutes, privateDeps)) return;
    if (route?.pageProgress) {
      browser.tabs
        .sendMessage(route.tabId, {
          type: 'PLUGIN_PROGRESS',
          requestId: request.requestId,
          progress: request.progress,
        })
        .catch(() => {});
    }
    return; // No response needed
  }

  // Relay: outbound MPC bytes from offscreen → originating tab (→ page → data channel)
  if (request.type === 'RELAY_OUT') {
    const route = progressRoutes.get(request.requestId);
    if (route) {
      browser.tabs.sendMessage(route.tabId, {
        type: 'RELAY_OUT',
        requestId: request.requestId,
        data: request.data,
      });
    }
    return; // No response needed
  }

  // Relay: inbound MPC bytes from the page (via content script) → offscreen.
  // Forward under a DISTINCT type the offscreen handles, so it delivers each
  // chunk once (the content script's runtime.sendMessage is also broadcast
  // directly to the offscreen — handling the raw type there would double it).
  if (request.type === 'RELAY_IN') {
    chrome.runtime.sendMessage({ type: 'RELAY_DELIVER', data: request.data }).catch(() => {});
    return; // No response needed
  }
  if (request.type === 'RELAY_CLOSED') {
    chrome.runtime.sendMessage({ type: 'RELAY_DELIVER_CLOSED' }).catch(() => {});
    return; // No response needed
  }

  // Run one of the built-in plugins for the embedding
  // page. The page names the plugin (id + fingerprint) and the run's values; it
  // never sends code (the stock code-execution handler is gone). Top-frame
  // allowed-origin sender + built-in plugin + checked values, decided here from
  // Chrome's sender (background/autoApproval.ts); anything else is refused.
  if (request.type === 'RUN_BUILTIN') {
    const approval = autoApprovalFor(request, sender, browser.runtime.id);
    if (!approval.ok) {
      logger.warn('RUN_BUILTIN refused:', approval.error);
      return Promise.resolve({ success: false, error: approval.error });
    }
    logger.info(`Built-in plugin ${approval.plugin.id} on ${approval.origin}`);
    const requestId = approval.requestId;
    const privateGcp = approval.plugin.id === 'gcp-work';
    if ((privateGcp && (!requestId || sender.tab?.id === undefined || progressRoutes.has(requestId))) ||
        (requestId && progressRoutes.get(requestId)?.gcpPrivate)) {
      try { console.debug('GCP_PRIVATE_ROUTE_REFUSED'); } catch { /* Keep the original refusal. */ }
      return Promise.resolve({ success: false, error: 'GCP_PRIVATE_PROVING_FAILED' });
    }
    // The run's tab gets its progress; `pageProgress` marks the run as
    // auto-approved (PLUGIN_PROGRESS forwarding and PLUGIN_NAVIGATE read it).
    if (requestId && sender.tab?.id) {
      progressRoutes.set(requestId, {
        tabId: sender.tab.id,
        createdAt: Date.now(),
        pageProgress: true,
        ...(privateGcp ? { gcpPrivate: true } : {}),
      });
    }

    // Return a Promise so the polyfill keeps the message channel open
    // and resolves when the async work completes.
    return (async () => {
      let pendingPrivate = false;
      let stage: 'CREATE_OFFSCREEN' | 'WAIT_OFFSCREEN' | 'SEND_OFFSCREEN' = 'CREATE_OFFSCREEN';
      try {
        await createOffscreenDocument();
        stage = 'WAIT_OFFSCREEN';
        await waitForOffscreenReady(() => chrome.runtime.sendMessage({ type: 'PROCESS_DATA' }));
        stage = 'SEND_OFFSCREEN';
        const response = await chrome.runtime.sendMessage({
          type: 'RUN_BUILTIN_OFFSCREEN',
          pluginId: approval.plugin.id,
          fingerprint: approval.plugin.sha256,
          values: approval.values,
          requestId,
          // The page's checked keys first, then ours (so a page cannot set them).
          sessionData: offscreenSessionData(approval),
        });
        pendingPrivate = privateGcp && response?.success === true && response?.pending === true;
        if (!privateGcp) logger.debug('RUN_BUILTIN_OFFSCREEN response:', response);
        return response;
      } catch (error) {
        if (privateGcp) {
          try { console.debug(`GCP_PRIVATE_START_FAILED_${stage}`); } catch { /* Preserve failure and route cleanup. */ }
        }
        if (!privateGcp) logger.error('Error running built-in plugin:', error);
        return {
          success: false,
          error: privateGcp ? 'GCP_PRIVATE_PROVING_FAILED' : error instanceof Error ? error.message : 'Code execution failed',
        };
      } finally {
        if (requestId && !pendingPrivate) progressRoutes.delete(requestId);
      }
    })();
  }

  // Handle CLOSE_WINDOW requests
  if (request.type === 'CLOSE_WINDOW') {
    logger.debug('CLOSE_WINDOW request received:', request.windowId);

    if (!request.windowId) {
      logger.error('No windowId provided');
      return Promise.resolve({
        type: 'WINDOW_ERROR',
        payload: {
          error: 'No windowId provided',
          details: 'windowId is required to close a window',
        },
      });
    }

    // Close the window using WindowManager
    return windowManager
      .closeWindow(request.windowId)
      .then(() => {
        logger.debug(`Window ${request.windowId} closed`);
        return {
          type: 'WINDOW_CLOSED',
          payload: {
            windowId: request.windowId,
          },
        };
      })
      .catch((error) => {
        logger.error('Error closing window:', error);
        return {
          type: 'WINDOW_ERROR',
          payload: {
            error: 'Failed to close window',
            details: String(error),
          },
        };
      });
  }

  // Handle OPEN_WINDOW requests from content scripts
  if (request.type === 'OPEN_WINDOW') {

    // Validate URL using comprehensive validator
    const urlValidation = validateUrl(request.url);
    if (!urlValidation.valid) {
      logger.error('URL validation failed:', urlValidation.error);
      return Promise.resolve({
        type: 'WINDOW_ERROR',
        payload: {
          error: 'Invalid URL',
          details: urlValidation.error || 'URL validation failed',
        },
      });
    }

    // Calculate position to center on the active browser window, then open
    const popupWidth = request.width || 900;
    const popupHeight = request.height || 700;

    return browser.windows
      .getCurrent()
      .then((currentWindow) => {
        let left: number | undefined;
        let top: number | undefined;

        if (
          currentWindow.left != null &&
          currentWindow.top != null &&
          currentWindow.width != null &&
          currentWindow.height != null
        ) {
          left = Math.round(currentWindow.left + (currentWindow.width - popupWidth) / 2);
          top = Math.round(currentWindow.top + (currentWindow.height - popupHeight) / 2);
        }

        return { left, top };
      })
      .catch(() => ({
        left: undefined as number | undefined,
        top: undefined as number | undefined,
      }))
      .then(({ left, top }) =>
        browser.windows.create({
          url: request.url,
          type: 'popup',
          width: popupWidth,
          height: popupHeight,
          left,
          top,
        }),
      )
      .then(async (window) => {
        if (!window.id || !window.tabs || !window.tabs[0] || !window.tabs[0].id) {
          throw new Error('Failed to create window or get tab ID');
        }

        const windowId = window.id;
        const tabId = window.tabs[0].id;

        logger.info(`Window created: ${windowId}, Tab: ${tabId}`);

        try {
          // Register window with WindowManager
          const managedWindow = await windowManager.registerWindow({
            id: windowId,
            tabId: tabId,
            url: request.url,
            showOverlay: request.showOverlay !== false, // Default to true
          });

          logger.debug(`Window registered: ${managedWindow.uuid}`);

          return {
            type: 'WINDOW_OPENED',
            payload: {
              windowId: managedWindow.id,
              uuid: managedWindow.uuid,
              tabId: managedWindow.tabId,
            },
          };
        } catch (registrationError) {
          // Registration failed (e.g., window limit exceeded)
          // Close the window we just created
          logger.error('Window registration failed:', registrationError);
          await browser.windows.remove(windowId).catch(() => {
            // Ignore errors if window already closed
          });

          return {
            type: 'WINDOW_ERROR',
            payload: {
              error: 'Window registration failed',
              details: String(registrationError),
            },
          };
        }
      })
      .catch((error) => {
        logger.error('Error creating window:', error);
        return {
          type: 'WINDOW_ERROR',
          payload: {
            error: 'Failed to create window',
            details: String(error),
          },
        };
      });
  }

  if (request.type === 'TO_BG_RE_RENDER_PLUGIN_UI') {
    windowManager.reRenderPluginUI(request.windowId);
    return; // No response needed
  }

  // Unknown message type - no response needed
  return;
});

// Mutex for offscreen document creation to prevent race conditions
let offscreenDocumentCreationPromise: Promise<void> | null = null;

// Create offscreen document if needed (Chrome 109+)
// Uses mutex to prevent race conditions when multiple callers try to create simultaneously
async function createOffscreenDocument(): Promise<void> {
  // If creation is already in progress, wait for it
  if (offscreenDocumentCreationPromise) {
    return offscreenDocumentCreationPromise;
  }

  // Create the promise and store it for other callers to wait on
  offscreenDocumentCreationPromise = (async () => {
    try {
      // Check if we're in a Chrome environment that supports offscreen documents
      if (!chrome?.offscreen) {
        logger.debug('Offscreen API not available');
        return;
      }

      const offscreenUrl = browser.runtime.getURL('offscreen.html');

      // Check if offscreen document already exists
      const existingContexts = await chrome.runtime.getContexts({
        contextTypes: ['OFFSCREEN_DOCUMENT'],
        documentUrls: [offscreenUrl],
      });

      if (existingContexts.length > 0) {
        logger.debug('Offscreen document already exists');
        return;
      }

      // Create offscreen document
      logger.debug('Creating offscreen document...');
      await chrome.offscreen.createDocument({
        url: 'offscreen.html',
        reasons: ['WORKERS'],
        justification: 'Run QuickJS sandbox and TLS prover in a worker context',
      });
      logger.debug('Offscreen document created successfully');
    } finally {
      // Clear the promise so future calls can create if needed
      offscreenDocumentCreationPromise = null;
    }
  })();

  return offscreenDocumentCreationPromise;
}

// Initialize offscreen document
createOffscreenDocument().catch((err) => logger.error('Offscreen document error:', err));

// Periodic cleanup of invalid windows and stale progress routes (every 5 minutes)
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
setInterval(() => {
  logger.debug('Running periodic cleanup...');
  windowManager.cleanupInvalidWindows().catch((error) => {
    logger.error('Error during window cleanup:', error);
  });

  // Evict stale progress routes (TTL-based)
  const now = Date.now();
  for (const [requestId, route] of progressRoutes) {
    if (now - route.createdAt >= (route.gcpPrivate ? GCP_PRIVATE_ROUTE_TTL_MS : PROGRESS_ROUTE_TTL_MS)) {
      logger.debug('Evicting stale progress route:', requestId);
      progressRoutes.delete(requestId);
    }
  }
}, CLEANUP_INTERVAL_MS);

// Run initial cleanup after 10 seconds
setTimeout(() => {
  windowManager.cleanupInvalidWindows().catch((error) => {
    logger.error('Error during initial cleanup:', error);
  });
}, 10000);

export {};
