/**
 * window.tlsn stays ours on an allowed origin, whichever
 * extension's page script runs first (src/entries/Content/pageApiLock.ts).
 *
 * The stock statement is the one in TLSNotary 0.1.0.1501's published
 * content.bundle.js: `(()=>{"use strict";window.tlsn=new class{version=…;
 * async execCode(…){…}};…window.dispatchEvent(new CustomEvent("tlsn_loaded"))})()`.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Window } from 'happy-dom';
import { FORK_API_MARK, installPageApi } from '../../src/entries/Content/pageApiLock';

type Api = {
  version?: string;
  extensionId?: string | null;
  runBuiltIn?: unknown;
  execCode?: unknown;
};
type Win = { tlsn?: Api };

const STOCK_BODY =
  'window.tlsn = new (class { version = "0.1.0.1501"; async execCode() { return null; } })();';
/** The stock page script, as built (strict). */
const stockStrict = new Function('window', `"use strict"; ${STOCK_BODY}`) as (w: object) => void;
/** The same assignment in sloppy mode (an older or differently built stock script). */
const stockSloppy = new Function('window', STOCK_BODY) as (w: object) => void;

const ID = 'djikndclbfiillgjioganlljdlhfepkd';
function forkApi(extensionId: string | null = ID): Api {
  return {
    version: '0.1.0.1501',
    extensionId,
    runBuiltIn: async () => null,
  };
}

describe('installPageApi: allowed origin (lock)', () => {
  for (const [mode, stock] of [
    ['strict', stockStrict],
    ['sloppy', stockSloppy],
  ] as const) {
    it(`stock first (${mode}), then ours: ours replaces it and stays`, () => {
      const win: Win = {};
      stock(win);
      expect(typeof win.tlsn?.execCode).toBe('function');
      const ours = forkApi();
      installPageApi(win, ours, true);
      expect(win.tlsn).toBe(ours);
      expect(() => stock(win)).not.toThrow(); // a late second stock run
      expect(win.tlsn).toBe(ours);
    });

    it(`ours first, then stock assigns (${mode}): no throw, ours stays`, () => {
      const win: Win = {};
      const ours = forkApi();
      installPageApi(win, ours, true);
      expect(() => stock(win)).not.toThrow();
      expect(win.tlsn).toBe(ours);
      expect(win.tlsn?.extensionId).toBe(ID);
      expect(typeof win.tlsn?.runBuiltIn).toBe('function');
      expect(win.tlsn?.execCode).toBeUndefined();
    });
  }

  it('the property cannot be deleted or redefined by someone else', () => {
    const win: Win = {};
    const ours = forkApi();
    installPageApi(win, ours, true);
    const d = Object.getOwnPropertyDescriptor(win, 'tlsn')!;
    expect(d.configurable).toBe(false);
    expect(d.enumerable).toBe(true);
    // Test modules are strict: delete of a non-configurable property throws.
    expect(() => delete (win as { tlsn?: unknown }).tlsn).toThrow(TypeError);
    expect(() => Object.defineProperty(win, 'tlsn', { value: {} })).toThrow(TypeError);
    expect(win.tlsn).toBe(ours);
  });

  it('only a marked object passes the setter (stock objects, plain objects, null ignored)', () => {
    const win: Win = {};
    const ours = forkApi();
    installPageApi(win, ours, true);
    for (const v of [null, undefined, 1, 'x', {}, { runBuiltIn: () => null }, forkApi()]) {
      (win as { tlsn?: unknown }).tlsn = v;
      expect(win.tlsn).toBe(ours);
    }
    expect((ours as Record<symbol, unknown>)[FORK_API_MARK]).toBe(true);
    // The mark is not enumerable and not writable.
    expect(Object.keys(ours)).not.toContain(String(FORK_API_MARK));
    expect(Object.getOwnPropertyDescriptor(ours, FORK_API_MARK)).toMatchObject({
      enumerable: false,
      writable: false,
      configurable: false,
    });
  });

  it('re-injection of ours: no throw, the newest of ours wins, stock still cannot take over', () => {
    const win: Win = {};
    const first = forkApi();
    installPageApi(win, first, true);
    stockStrict(win);
    const second = forkApi();
    expect(() => installPageApi(win, second, true)).not.toThrow();
    expect(win.tlsn).toBe(second);
    stockStrict(win);
    expect(win.tlsn).toBe(second);
    const third = forkApi();
    expect(() => installPageApi(win, third, true)).not.toThrow();
    expect(win.tlsn).toBe(third);
  });

  it("someone else's non-configurable property: ours gives up quietly (never throws)", () => {
    const foreign = { other: true };
    const ro: Win = {};
    Object.defineProperty(ro, 'tlsn', { value: foreign, configurable: false, writable: false });
    expect(() => installPageApi(ro, forkApi(), true)).not.toThrow();
    expect(ro.tlsn).toBe(foreign);
    const acc: Win = {};
    Object.defineProperty(acc, 'tlsn', { get: () => foreign, configurable: false });
    expect(() => installPageApi(acc, forkApi(), true)).not.toThrow();
    expect(acc.tlsn).toBe(foreign);
  });
});

describe('installPageApi: elsewhere (no lock, as upstream)', () => {
  it('plain assignment: last one wins, stock keeps working on github.com', () => {
    const win: Win = {};
    const ours = forkApi(null);
    installPageApi(win, ours, false);
    expect(Object.getOwnPropertyDescriptor(win, 'tlsn')).toMatchObject({
      value: ours,
      writable: true,
      configurable: true,
    });
    stockStrict(win);
    expect(typeof win.tlsn?.execCode).toBe('function');
    expect((ours as Record<symbol, unknown>)[FORK_API_MARK]).toBeUndefined();
  });
});

/**
 * The real page script (content.ts), run in a fresh happy-dom window per test,
 * as Chrome runs it: document.currentScript is the injected <script> with the
 * data-* attributes our content script sets.
 */
describe('content.ts (the injected page script)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  function freshWindow(): Window {
    const win = new Window({ url: 'http://localhost:5173/' });
    vi.stubGlobal('window', win);
    vi.stubGlobal('document', win.document);
    vi.stubGlobal('CustomEvent', win.CustomEvent);
    vi.stubGlobal('__EXTENSION_VERSION__', '0.1.0.1501');
    return win;
  }

  async function injectFork(win: Window, productOrigin: boolean): Promise<void> {
    const el = win.document.createElement('script');
    if (productOrigin) {
      el.dataset.extensionId = ID;
      el.dataset.builtinPlugins = JSON.stringify([
        { id: 'github-pr-work', sha256: 'a'.repeat(64) },
      ]);
    }
    Object.defineProperty(win.document, 'currentScript', { configurable: true, get: () => el });
    vi.resetModules();
    await import('../../src/entries/Content/content');
  }

  const tlsnOf = (win: Window) => (win as unknown as Win).tlsn;

  it('stock first, then ours: window.tlsn is ours', async () => {
    const win = freshWindow();
    stockStrict(win);
    await injectFork(win, true);
    expect(tlsnOf(win)?.extensionId).toBe(ID);
    expect(typeof tlsnOf(win)?.runBuiltIn).toBe('function');
  });

  it('ours first, then stock: window.tlsn stays ours and stock does not throw', async () => {
    const win = freshWindow();
    await injectFork(win, true);
    const ours = tlsnOf(win);
    expect(() => stockStrict(win)).not.toThrow();
    expect(() => stockSloppy(win)).not.toThrow();
    expect(tlsnOf(win)).toBe(ours);
    expect(tlsnOf(win)?.extensionId).toBe(ID);
  });

  it('re-injection of the extension page script: no throw, still ours, tlsn_loaded fires each time', async () => {
    const win = freshWindow();
    const loaded = vi.fn();
    win.addEventListener('tlsn_loaded', loaded);
    await injectFork(win, true);
    stockStrict(win);
    await expect(injectFork(win, true)).resolves.toBeUndefined();
    expect(tlsnOf(win)?.extensionId).toBe(ID);
    expect(typeof tlsnOf(win)?.runBuiltIn).toBe('function');
    expect(loaded).toHaveBeenCalledTimes(2);
  });

  it('not an allowed origin (no extension ID tagged): plain property as upstream', async () => {
    const win = freshWindow();
    await injectFork(win, false);
    expect(Object.getOwnPropertyDescriptor(win, 'tlsn')).toMatchObject({ configurable: true });
    stockStrict(win);
    expect(typeof tlsnOf(win)?.execCode).toBe('function');
  });

  it('source pin: content.ts installs window.tlsn only through installPageApi', () => {
    const src = readFileSync(resolve(__dirname, '../../src/entries/Content/content.ts'), 'utf8');
    expect(src).toContain(
      'installPageApi(window, new ExtensionAPI(), FORK_EXTENSION_ID !== null);',
    );
    expect(src).not.toMatch(/\.tlsn\s*=/);
  });
});
