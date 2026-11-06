// Note: This file runs in page context (bundled into content.bundle.js).

/**
 * Who owns `window.tlsn` on the allowed origins.
 *
 * Every TLSNotary-based extension injects its page script (`content.bundle.js`)
 * with a `<script src>` from its content script, and that script does
 * `window.tlsn = new ExtensionAPI()`. Injected scripts run in whatever order
 * they finish loading, so with the stock TLSNotary extension enabled next to
 * this extension the last one to run won; when the stock object won, the embedding page
 * found no `runBuiltIn` and asked for the extension.
 *
 * On an allowed origin our script therefore defines `window.tlsn` as a
 * non-configurable accessor:
 * - runs second: it replaces the stock object (a plain assignment leaves a
 *   configurable property, so `defineProperty` may redefine it);
 * - runs first: the stock assignment goes to our setter, which ignores any
 *   object that is not ours. No throw in strict mode (the stock bundle is
 *   `"use strict"`) or sloppy mode, so the stock script carries on harmlessly
 *   (it still dispatches `tlsn_loaded`, after which the page reads ours);
 * - our own script again in the same window (a second injection): its object
 *   carries `FORK_API_MARK`, so it goes in through the same setter and the
 *   newest one wins, without redefining the locked property.
 *
 * Elsewhere (provider sites, where the page API is not needed) `window.tlsn` is
 * assigned exactly as upstream does, so the stock extension keeps working there.
 *
 * Not a security boundary: any main-world script can still wrap or replace the
 * object's methods. Every check stays where it was (the content script, the
 * background's sender/origin/fingerprint checks and the offscreen sha256 check).
 */
export const FORK_API_MARK: unique symbol = Symbol.for('tlsn-extension-fork/window.tlsn');

export function installPageApi(target: object, api: object, lock: boolean): void {
  const slot = target as { tlsn?: unknown };
  if (!lock) {
    slot.tlsn = api;
    return;
  }
  Object.defineProperty(api, FORK_API_MARK, { value: true });
  const existing = Object.getOwnPropertyDescriptor(target, 'tlsn');
  if (existing && !existing.configurable) {
    // Locked already: ours from an earlier injection takes the new object
    // through its setter; anything else cannot be replaced (and must not throw).
    try {
      slot.tlsn = api;
    } catch {
      /* someone else's non-writable property */
    }
    return;
  }
  let current: object = api;
  Object.defineProperty(target, 'tlsn', {
    configurable: false,
    enumerable: true,
    get: () => current,
    set: (value: unknown) => {
      if (
        value !== null &&
        typeof value === 'object' &&
        (value as { [FORK_API_MARK]?: unknown })[FORK_API_MARK] === true
      ) {
        current = value;
      }
    },
  });
}
