import browser from 'webextension-polyfill';
import type { DomJson } from '@tlsn/plugin-sdk';
import type { ContentMessage, ExecCodeResponse } from '../../types/messages';
import { logger, LogLevel } from '@tlsn/common';
import { isProductOrigin } from '../../constants/productOrigins';
import { sanitizePageProgress } from '../../constants/pageProgress';
import { BUILTIN_PLUGINS } from '../../constants/builtinPlugins';
import { readConsoleCredentials } from './awsPrivateCredentials';

// Initialize logger at DEBUG level for content scripts (no IndexedDB access)
logger.init(LogLevel.DEBUG);
logger.debug('Content script loaded');

// Only allowed origins see our extension ID and get
// helperStatus answers (constants/productOrigins.ts, build-time list).
const PRODUCT_PAGE = isProductOrigin(window.location.origin);
const pendingPrivateRuns = new Map<string, { timer: ReturnType<typeof setTimeout>; error: string }>();
const finishPrivateRun = (requestId: string) => {
  const pending = pendingPrivateRuns.get(requestId);
  if (pending === undefined) return undefined;
  clearTimeout(pending.timer); pendingPrivateRuns.delete(requestId); return pending;
};

// Inject a script into the page if needed
function injectScript() {
  const script = document.createElement('script');
  script.src = browser.runtime.getURL('content.bundle.js');
  script.type = 'text/javascript';
  // The page script reads this as window.tlsn.extensionId
  // (pages cannot see an extension's ID otherwise; the stock build sets none).
  // Allowed origins only; elsewhere the fork looks like the stock build.
  if (PRODUCT_PAGE) script.dataset.extensionId = browser.runtime.id;
  // The built-in plugins (id + fingerprint) for window.tlsn.builtInPlugins,
  // so the embedding page can tell whether this build carries the plugin it expects.
  if (PRODUCT_PAGE) {
    script.dataset.builtinPlugins = JSON.stringify(
      BUILTIN_PLUGINS.map(({ id, sha256 }) => ({ id, sha256 })),
    );
  }
  (document.head || document.documentElement).appendChild(script);
  script.onload = () => script.remove();
}

function renderPluginUI(json: DomJson, windowId: number) {
  let container = document.getElementById('tlsn-plugin-container');

  if (!container) {
    const el = document.createElement('div');
    el.id = 'tlsn-plugin-container';
    document.body.appendChild(el);
    container = el;
  }

  // Preserve drag position across re-renders: if the user dragged the element,
  // its positioning was converted from bottom/right to top/left (bottom becomes 'auto').
  const prev = container.querySelector('[data-tlsn-draggable]') as HTMLElement | null;
  const savedPosition =
    prev && prev.style.bottom === 'auto' ? { top: prev.style.top, left: prev.style.left } : null;

  container.innerHTML = '';
  container.appendChild(createNode(json, windowId));

  if (savedPosition) {
    const el = container.querySelector('[data-tlsn-draggable]') as HTMLElement | null;
    if (el) {
      el.style.top = savedPosition.top;
      el.style.left = savedPosition.left;
      el.style.bottom = 'auto';
      el.style.right = 'auto';
    }
  }
}

function makeDraggable(el: HTMLElement) {
  // Use the first child as the drag handle (the header bar)
  const handle = el.firstElementChild as HTMLElement | null;

  if (!handle) return;

  handle.style.cursor = 'grab';

  let offsetX = 0;
  let offsetY = 0;

  const onMouseMove = (e: MouseEvent) => {
    const x = Math.max(0, Math.min(e.clientX - offsetX, window.innerWidth - el.offsetWidth));
    const y = Math.max(0, Math.min(e.clientY - offsetY, window.innerHeight - el.offsetHeight));

    el.style.left = x + 'px';
    el.style.top = y + 'px';
  };

  const onMouseUp = () => {
    handle.style.cursor = 'grab';
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
  };

  handle.addEventListener('mousedown', (e: MouseEvent) => {
    // Only drag on primary button, ignore clicks on buttons inside the handle
    if (e.button !== 0 || (e.target as HTMLElement).closest('button')) return;

    handle.style.cursor = 'grabbing';

    // Convert bottom/right positioning to top/left
    const rect = el.getBoundingClientRect();

    el.style.top = rect.top + 'px';
    el.style.left = rect.left + 'px';
    el.style.bottom = 'auto';
    el.style.right = 'auto';

    offsetX = e.clientX - rect.left;
    offsetY = e.clientY - rect.top;

    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseup', onMouseUp);

    e.preventDefault();
  });
}

const ALLOWED_ELEMENT_TYPES = new Set([
  'div',
  'span',
  'p',
  'button',
  'input',
  'label',
  'a',
  'img',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'ul',
  'ol',
  'li',
  'table',
  'tr',
  'td',
  'th',
  'thead',
  'tbody',
  'form',
  'select',
  'option',
  'textarea',
  'pre',
  'code',
  'strong',
  'em',
  'br',
  'hr',
]);

function createNode(json: DomJson, windowId: number): HTMLElement | Text {
  if (typeof json === 'string') {
    const node = document.createTextNode(json);
    return node;
  }

  if (!ALLOWED_ELEMENT_TYPES.has(json.type)) {
    logger.warn(`[Content] Blocked disallowed element type: ${json.type}`);
    return document.createTextNode('');
  }

  const node = document.createElement(json.type);

  if (json.options.className) {
    node.className = json.options.className;
  }

  if (json.options.id) {
    node.id = json.options.id;
  }

  if (json.options.style) {
    Object.entries(json.options.style).forEach(([key, value]) => {
      (node.style as unknown as Record<string, string>)[key] = value;
    });
  }

  if (json.options.inputType) (node as HTMLInputElement).type = json.options.inputType;
  if (json.options.checked !== undefined) (node as HTMLInputElement).checked = json.options.checked;
  if (json.options.value !== undefined) (node as HTMLInputElement).value = json.options.value;
  if (json.options.placeholder) (node as HTMLInputElement).placeholder = json.options.placeholder;
  if (json.options.disabled !== undefined)
    (node as HTMLInputElement).disabled = json.options.disabled;

  if (json.options.onclick) {
    node.addEventListener('click', () => {
      browser.runtime.sendMessage({
        type: 'PLUGIN_UI_CLICK',
        onclick: json.options.onclick,
        windowId,
      });
    });
  }

  json.children.forEach((child) => {
    node.appendChild(createNode(child, windowId));
  });

  if (json.options.draggable) {
    node.dataset.tlsnDraggable = '';
    makeDraggable(node);
  }

  return node;
}

// Listen for messages from the extension
browser.runtime.onMessage.addListener((msg: unknown, sender: browser.Runtime.MessageSender) => {
  if ((msg as { type?: unknown })?.type === 'AWS_PRIVATE_CONSOLE_CREDENTIALS') {
    return readConsoleCredentials(msg, sender, { extensionId: browser.runtime.id,
      backgroundUrl: browser.runtime.getURL('background.bundle.js'), origin: window.location.origin, top: window.top === window });
  }
  const completion = msg as { type?: string; requestId?: unknown; success?: unknown; result?: unknown };
  if (completion?.type === 'RUN_BUILTIN_COMPLETE') {
    if (!PRODUCT_PAGE || sender.id !== browser.runtime.id || sender.tab !== undefined ||
        (sender.url && sender.url !== browser.runtime.getURL('background.bundle.js')) ||
        typeof completion.requestId !== 'string') return;
    const pending = finishPrivateRun(completion.requestId);
    if (!pending) return;
    window.postMessage({ type: 'TLSN_RUN_BUILTIN_RESPONSE', requestId: completion.requestId,
      ...(completion.success === true ? { success: true, result: completion.result } :
        { success: false, error: pending.error }) }, window.location.origin);
    return;
  }
  const request = msg as ContentMessage;

  // Forward offscreen logs to page
  if (request.type === 'OFFSCREEN_LOG') {
    window.postMessage(
      {
        type: 'TLSN_OFFSCREEN_LOG',
        level: request.level,
        message: request.message,
      },
      window.location.origin,
    );
    return; // No response needed
  }

  // A trusted plugin's progress, on allowed origins only.
  if (request.type === 'PLUGIN_PROGRESS') {
    const progress = sanitizePageProgress(request.progress);
    if (PRODUCT_PAGE && progress && typeof request.requestId === 'string') {
      window.postMessage(
        { type: 'TLSN_PLUGIN_PROGRESS', requestId: request.requestId, ...progress },
        window.location.origin,
      );
    }
    return; // No response needed
  }

  // Forward progress events from background to page
  if (request.type === 'PROVE_PROGRESS') {
    window.postMessage(
      {
        type: 'TLSN_PROVE_PROGRESS',
        requestId: request.requestId,
        step: request.step,
        progress: request.progress,
        message: request.message,
        source: request.source,
      },
      window.location.origin,
    );
    return; // No response needed
  }

  // Relay: forward outbound MPC bytes from the extension to the page,
  // which sends them over its data channel to the verifier.
  if (request.type === 'RELAY_OUT') {
    window.postMessage(
      { type: 'TLSN_RELAY_OUT', requestId: request.requestId, data: request.data },
      window.location.origin,
    );
    return; // No response needed
  }

  if (request.type === 'GET_PAGE_INFO') {
    return Promise.resolve({
      title: document.title,
      url: window.location.href,
      domain: window.location.hostname,
    });
  }

  if (request.type === 'RENDER_PLUGIN_UI') {
    renderPluginUI(request.json, request.windowId);
    return Promise.resolve({ success: true });
  }

  // Unknown message type - no response needed
  return;
});

// Send a message to background script when ready
browser.runtime
  .sendMessage({
    type: 'CONTENT_SCRIPT_READY',
    url: window.location.href,
  })
  .catch((err) => logger.error('Failed to send CONTENT_SCRIPT_READY:', err));

// Listen for messages from the page
window.addEventListener('message', (event) => {
  // Only accept messages from the same origin
  if (event.origin !== window.location.origin) return;

  // Handle TLSN window.tlsn.open() calls
  if (event.data?.type === 'TLSN_OPEN_WINDOW') {

    // Forward to background script with OPEN_WINDOW type
    browser.runtime
      .sendMessage({
        type: 'OPEN_WINDOW',
        url: event.data.payload.url,
        width: event.data.payload.width,
        height: event.data.payload.height,
        showOverlay: event.data.payload.showOverlay,
      })
      .catch((error) => {
        logger.error('[Content Script] Failed to send OPEN_WINDOW message:', error);
      });
  }

  // Relay: inbound MPC bytes from the page's data channel → extension.
  if (event.data?.type === 'TLSN_RELAY_IN') {
    browser.runtime
      .sendMessage({
        type: 'RELAY_IN',
        requestId: event.data.requestId,
        data: event.data.data,
      })
      .catch(() => {
        /* extension context may be gone */
      });
    return;
  }
  if (event.data?.type === 'TLSN_RELAY_CLOSED') {
    browser.runtime
      .sendMessage({ type: 'RELAY_CLOSED', requestId: event.data.requestId })
      .catch(() => {});
    return;
  }

  // window.tlsn.runBuiltIn() → run one of the
  // extension's built-in plugins. Only named fields travel (no code); the
  // background decides from Chrome's sender (allowed origin, top frame) and
  // checks every value. The stock entry point for page-supplied code is gone.
  if (event.data?.type === 'TLSN_RUN_BUILTIN') {
    if (event.source !== window) return;
    const p = (event.data.payload ?? {}) as Record<string, unknown>;
    const requestId = typeof p.requestId === 'string' ? p.requestId.slice(0, 128) : '';
    const reply = (body: { success: boolean; result?: unknown; error?: string }) =>
      window.postMessage(
        { type: 'TLSN_RUN_BUILTIN_RESPONSE', requestId, ...body },
        window.location.origin,
      );
    const privateRun = p.pluginId === 'gcp-work' || p.pluginId === 'aws-private-work';
    const privateError = p.pluginId === 'aws-private-work' ? 'AWS_PRIVATE_PROVING_FAILED' : 'GCP_PRIVATE_PROVING_FAILED';
    if (privateRun && requestId && PRODUCT_PAGE) {
      if (pendingPrivateRuns.has(requestId)) return;
      pendingPrivateRuns.set(requestId, { error: privateError, timer: setTimeout(() => {
        if (finishPrivateRun(requestId)) reply({ success: false, error: privateError });
      }, 13 * 60 * 1000) });
    }
    browser.runtime
      .sendMessage({
        type: 'RUN_BUILTIN',
        pluginId: p.pluginId,
        fingerprint: p.fingerprint,
        verifierUrl: p.verifierUrl,
        proxyUrl: p.proxyUrl,
        params: p.params,
        methodUrls: p.methodUrls,
        requestId: p.requestId,
        sessionData: p.sessionData,
      })
      .then((msg) => {
        const response = msg as ExecCodeResponse & { pending?: boolean };
        if (privateRun && response?.success === true && response.pending === true) return;
        finishPrivateRun(requestId);
        if (response && response.success === true) {
          reply({ success: true, result: response.result });
        } else {
          reply({ success: false, error: response?.error || 'Code execution failed' });
        }
      })
      .catch((error) => {
        finishPrivateRun(requestId);
        if (p.pluginId === 'gcp-work') {
          try { console.debug('GCP_PRIVATE_CONTENT_SEND_FAILED'); } catch { /* Preserve the generic failure reply. */ }
        }
        if (!privateRun) logger.error('[Content Script] Failed to run the built-in plugin:', error);
        reply({ success: false, error: privateRun ? privateError : error?.message || 'Code execution failed' });
      });
    return;
  }

  // Handle legacy TLSN_CONTENT_SCRIPT_MESSAGE
  if (event.data?.type === 'TLSN_CONTENT_SCRIPT_MESSAGE') {
    // Forward to content script/extension
    browser.runtime.sendMessage({
      type: 'TLSN_CONTENT_TO_EXTENSION',
      payload: event.data.payload,
    });
  }
});

// Inject script if document is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectScript);
} else {
  injectScript();
}

export {};
