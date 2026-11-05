/**
 * The QuickJS sandbox runs queued
 * jobs (promise reactions) only while code is evaluated or when a host promise
 * it awaits settles. Two stalls followed from that:
 *  (a) a plugin that starts its run from main() with `Promise.resolve().then(run)`
 *      (a deferred start, never re-entrant) waited for the next host call into the
 *      sandbox, possibly minutes later (e.g. the next button click);
 *  (b) a button handler that finished (done()) left its own promise unresolved,
 *      so done() waited the 30 s drain timeout before the page got the result.
 * The host now runs the sandbox's pending jobs after every main() and every
 * button handler call, and done() delivers the result at once (cleanup waits).
 */
import { describe, it, expect, vi } from 'vitest';
import { Host } from '../src/index';
import type { WindowMessage } from '../src/types';

const WINDOW_ID = 7;

function emitter() {
  const listeners: Array<(m: WindowMessage) => void> = [];
  return {
    emit: (m: WindowMessage) => [...listeners].forEach((l) => l(m)),
    addListener: (l: (m: WindowMessage) => void) => listeners.push(l),
    removeListener: (l: (m: WindowMessage) => void) => {
      const i = listeners.indexOf(l);
      if (i >= 0) listeners.splice(i, 1);
    },
  };
}

const newHost = (onProve = vi.fn().mockResolvedValue({ ok: true })) =>
  new Host({
    onProve,
    onRenderPluginUi: vi.fn(),
    onCloseWindow: vi.fn(),
    onOpenWindow: vi.fn().mockResolvedValue({
      type: 'WINDOW_OPENED',
      payload: { windowId: WINDOW_ID, uuid: 'u', tabId: 1 },
    }),
  });

const header = (n: number) =>
  ({
    type: 'HEADER_INTERCEPTED',
    windowId: WINDOW_ID,
    header: {
      id: `h${n}`,
      method: 'GET',
      url: 'https://github.com/',
      timestamp: n,
      type: 'main_frame',
      requestHeaders: [{ name: 'Cookie', value: 'user_session=x' }],
    },
  }) as unknown as WindowMessage;

/** A common plugin pattern: a deferred start from main(), and a button with the same handler. */
const AUTO_START = `
export const config = { name: 'Wake probe' };
export async function run() {
  if (useState('running', false)) return;
  setState('running', true);
  done('auto');
}
export function main() {
  const [h] = useHeaders((hs) => hs.slice(-1));
  useEffect(() => { openWindow('https://github.com/login'); }, []);
  useEffect(() => {
    if (!h) return;
    Promise.resolve().then(run);
  }, [h ? 'session' : 'none']);
  return div({}, [button({ onclick: 'run' }, ['Start verification'])]);
}
`.trim();

/** A "back to the page" button (reportAccount): the handler finishes without awaiting the host. */
const BUTTON_DONE = `
export const config = { name: 'Button probe' };
export async function run() {
  done('clicked');
}
export function main() {
  useEffect(() => { openWindow('https://github.com/login'); }, []);
  return div({}, [button({ onclick: 'run' }, ['Start verification'])]);
}
`.trim();

/** A handler that only queues the work (no host promise involved). */
const BUTTON_QUEUES = `
export const config = { name: 'Queue probe' };
export function go() {
  Promise.resolve().then(() => done('queued'));
}
export function main() {
  useEffect(() => { openWindow('https://github.com/login'); }, []);
  return div({}, [button({ onclick: 'go' }, ['Go'])]);
}
`.trim();

/** done() while the handler still awaits a proof that never settles (window closing, slow verifier). */
const DONE_THEN_HANG = `
export const config = { name: 'Hang probe' };
export async function run() {
  done('early');
  await prove({ url: 'https://github.com/', method: 'GET', headers: {} }, { verifierUrl: 'x', proxyUrl: 'y', handlers: [] });
}
export function main() {
  useEffect(() => { openWindow('https://github.com/login'); }, []);
  return div({}, [button({ onclick: 'run' }, ['Start verification'])]);
}
`.trim();

const raceMs = <T>(p: Promise<T>, ms: number) =>
  Promise.race([p, new Promise<'timeout'>((r) => setTimeout(() => r('timeout'), ms))]);

describe.skipIf(typeof window !== 'undefined')(
  'wake-up: queued sandbox jobs run without a further host call',
  () => {
    it('(a) a deferred start from main() runs as soon as the header arrives (no click)', async () => {
      const ev = emitter();
      const host = newHost();
      const result = host.executePlugin(AUTO_START, { eventEmitter: ev });
      await new Promise((r) => setTimeout(r, 300)); // evaluate + openWindow
      ev.emit(header(1));
      expect(await raceMs(result, 2_000)).toBe('auto');
    }, 15_000);

    it('(b) done() in a button handler reaches the caller at once (not after the 30 s drain)', async () => {
      const ev = emitter();
      const host = newHost();
      const result = host.executePlugin(BUTTON_DONE, { eventEmitter: ev });
      await new Promise((r) => setTimeout(r, 300));
      ev.emit({
        type: 'PLUGIN_UI_CLICK',
        windowId: WINDOW_ID,
        onclick: 'run',
      } as unknown as WindowMessage);
      const t0 = Date.now();
      expect(await raceMs(result, 2_000)).toBe('clicked');
      expect(Date.now() - t0).toBeLessThan(1_000);
    }, 15_000);

    it('(c) work a button handler queued runs at once', async () => {
      const ev = emitter();
      const result = newHost().executePlugin(BUTTON_QUEUES, { eventEmitter: ev });
      await new Promise((r) => setTimeout(r, 300));
      ev.emit({
        type: 'PLUGIN_UI_CLICK',
        windowId: WINDOW_ID,
        onclick: 'go',
      } as unknown as WindowMessage);
      expect(await raceMs(result, 2_000)).toBe('queued');
    }, 15_000);

    it('(d) done() delivers the result at once even while its handler is still in flight', async () => {
      const ev = emitter();
      const host = newHost(vi.fn(() => new Promise(() => {})));
      const result = host.executePlugin(DONE_THEN_HANG, { eventEmitter: ev });
      await new Promise((r) => setTimeout(r, 300));
      ev.emit({
        type: 'PLUGIN_UI_CLICK',
        windowId: WINDOW_ID,
        onclick: 'run',
      } as unknown as WindowMessage);
      expect(await raceMs(result, 2_000)).toBe('early');
    }, 15_000);
  },
);
