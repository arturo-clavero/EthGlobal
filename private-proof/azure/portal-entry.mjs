import { createPortalSelection } from './portal-selection.mjs';

// Loaded by the manifest as an ISOLATED content script, never by a page script tag.
export function installAzurePortalDiscovery(browser) {
  if (location.origin !== 'https://portal.azure.com' || window.top !== window) return;
  let nonce = null, selection, host, status, controls, pending = false, heartbeat, expiry;
  const trustedBackground = sender => sender.id === browser.runtime.id && sender.tab === undefined &&
    sender.url === browser.runtime.getURL('background.bundle.js');
  const report = state => browser.runtime.sendMessage({ type: 'AZURE_DISCOVERY_PORTAL_STATUS', nonce, status: state }).catch(() => {});
  const clear = () => { clearInterval(heartbeat); clearTimeout(expiry); selection?.clear(); selection = null; host?.remove(); host = null; nonce = null; pending = false; };
  const fail = () => { if (status) status.textContent = 'This session is unavailable. Return to the proof page and retry.'; report('unavailable'); selection?.clear(); };
  const button = (label, action) => {
    const value = document.createElement('button'); value.textContent = label; value.type = 'button';
    value.style.cssText = 'display:block;width:100%;margin:8px 0;padding:10px;text-align:left;cursor:pointer';
    value.addEventListener('click', async event => {
      if (!event.isTrusted || pending) return;
      const capturedNonce = nonce, capturedSelection = selection;
      const active = () => nonce === capturedNonce && selection === capturedSelection;
      pending = true; value.disabled = true;
      try { await action({ selection: capturedSelection, active }); }
      catch { if (active()) fail(); }
      finally { if (active()) { pending = false; value.disabled = false; } }
    });
    return value;
  };
  const showSessions = () => {
    const sessions = selection.listSessions(); controls.replaceChildren();
    status.textContent = sessions.length ? 'Choose the Azure account for this proof.'
      : 'Finish signing in to Azure, open your Azure profile, then refresh the available sessions.';
    for (const session of sessions) controls.append(button(session.label, async context => {
      status.textContent = 'Checking the selected session…';
      const subscriptions = await context.selection.selectSession(session.id);
      if (!context.active()) return;
      controls.replaceChildren();
      status.textContent = 'Choose a subscription. Source values stay on this device.';
      for (const subscription of subscriptions) controls.append(button('Use ' + subscription.label, async context => {
        controls.replaceChildren(); status.textContent = 'Searching recent Azure activity locally…';
        const result = await context.selection.selectSubscription(subscription.id);
        if (!context.active()) return;
        if (result.status !== 'ready') throw new Error();
        status.textContent = 'Evidence selected locally. Return to the proof page to create your private proof.';
        clearTimeout(expiry); expiry = setTimeout(() => { report('unavailable'); clear(); }, 300000);
        report('ready');
      }));
    }));
    controls.append(button('Refresh available sessions', showSessions));
  };
  browser.runtime.onMessage.addListener((message, sender) => {
    if (!trustedBackground(sender) || !message || typeof message !== 'object') return;
    if (message.type === 'AZURE_DISCOVERY_PORTAL_START') {
      if (typeof message.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(message.nonce)) return Promise.resolve({ ok: false });
      if (nonce === message.nonce) return Promise.resolve({ ok: true });
      clear(); nonce = message.nonce; selection = createPortalSelection();
      const capturedNonce = nonce, capturedSelection = selection;
      expiry = setTimeout(() => { report('unavailable'); clear(); }, 900000);
      heartbeat = setInterval(async () => {
        let deadline;
        try {
          if (!selection?.valid()) throw new Error();
          const result = await Promise.race([
            browser.runtime.sendMessage({ type: 'AZURE_DISCOVERY_PORTAL_HEARTBEAT', nonce: capturedNonce }),
            new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error()), 5000); }),
          ]);
          if (result?.ok !== true) throw new Error();
        } catch { if (nonce === capturedNonce && selection === capturedSelection) { report('unavailable'); clear(); } }
        finally { clearTimeout(deadline); }
      }, 5000);
      host = document.createElement('div');
      host.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483647;width:380px;max-width:calc(100vw - 32px)';
      const shadow = host.attachShadow({ mode: 'closed' }), panel = document.createElement('section');
      panel.style.cssText = 'background:white;color:#172033;padding:18px;border:1px solid #c9d2df;border-radius:8px;font:14px/1.5 sans-serif;max-height:80vh;overflow:auto';
      panel.setAttribute('aria-label', 'Private Azure evidence selection');
      status = document.createElement('p'); status.setAttribute('role', 'status'); controls = document.createElement('div');
      const cancel = document.createElement('button'); cancel.textContent = 'Cancel'; cancel.type = 'button';
      cancel.addEventListener('click', event => { if (event.isTrusted) { report('unavailable'); clear(); } });
      panel.append(status, controls, cancel);
      shadow.append(panel); document.documentElement.append(host);
      try { showSessions(); } catch { fail(); }
      return Promise.resolve({ ok: true });
    }
    if (message.nonce !== nonce) return Promise.resolve({ ok: false });
    if (message.type === 'AZURE_DISCOVERY_PORTAL_CANCEL') { clear(); return Promise.resolve({ ok: true }); }
    if (message.type === 'AZURE_DISCOVERY_PORTAL_PREPARE') {
      if (pending || !selection) return Promise.resolve({ ok: false });
      clearTimeout(expiry); expiry = setTimeout(() => { report('unavailable'); clear(); }, 90000);
      pending = true; status.textContent = 'Rechecking your selection for the fresh proof attempt…';
      const capturedNonce = nonce, capturedSelection = selection;
      const active = () => nonce === capturedNonce && selection === capturedSelection;
      return capturedSelection.prepare(message.attempt).then(value => active() ? { ok: true, selection: value } : { ok: false })
        .catch(() => ({ ok: false })).finally(() => { if (active()) clear(); });
    }
  });
  window.addEventListener('pagehide', clear, { once: true });
}
