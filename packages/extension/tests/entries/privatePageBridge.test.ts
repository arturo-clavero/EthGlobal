import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { Window } from 'happy-dom';

let win: Window;
let run: (options: object) => Promise<unknown>;
const options = { pluginId: 'gcp-work', requestId: 'gcp-run' };
function reply(type: string, extra: object = {}, origin = win.location.origin, source: unknown = win) {
  win.dispatchEvent(new win.MessageEvent('message', { origin, source, data: { type, requestId: 'gcp-run', ...extra } }));
}
beforeEach(async () => {
  vi.useFakeTimers(); vi.resetModules();
  win = new Window({ url: 'http://localhost:5173/' });
  vi.stubGlobal('window', win); vi.stubGlobal('document', win.document);
  vi.stubGlobal('CustomEvent', win.CustomEvent); vi.stubGlobal('__EXTENSION_VERSION__', '0.1.0.1503');
  const script = win.document.createElement('script');
  script.dataset.extensionId = 'a'.repeat(32);
  Object.defineProperty(win.document, 'currentScript', { configurable: true, get: () => script });
  vi.spyOn(win, 'postMessage').mockImplementation(() => {});
  await import('../../src/entries/Content/content');
  run = (win as unknown as { tlsn: { runBuiltIn: typeof run } }).tlsn.runBuiltIn;
});
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('fails promptly when an extension reload left only the page API alive', async () => {
  let failure: string | undefined;
  void run(options).catch(error => { failure = error.message; });
  await vi.advanceTimersByTimeAsync(10_000);
  expect(failure).toBe('EXTENSION_CONNECTION_LOST');
  expect(vi.getTimerCount()).toBe(0);
});

it('keeps acknowledged work alive and removes timers after its final result', async () => {
  const pending = run(options);
  reply('TLSN_RUN_BUILTIN_ACK');
  await vi.advanceTimersByTimeAsync(6 * 60 * 1000);
  reply('TLSN_RUN_BUILTIN_RESPONSE', { success: true, result: 'finished' });
  await expect(pending).resolves.toBe('finished');
  expect(vi.getTimerCount()).toBe(0);
});

it('bounds a private run even if the content script disappears after acknowledgement', async () => {
  let failure: string | undefined;
  void run(options).catch(error => { failure = error.message; });
  reply('TLSN_RUN_BUILTIN_ACK');
  await vi.advanceTimersByTimeAsync(13 * 60 * 1000);
  expect(failure).toBe('Private verification timed out');
  expect(vi.getTimerCount()).toBe(0);
});

it('ignores acknowledgements from another origin, window, or request', async () => {
  let failure: string | undefined;
  void run(options).catch(error => { failure = error.message; });
  reply('TLSN_RUN_BUILTIN_ACK', {}, 'https://untrusted.invalid');
  reply('TLSN_RUN_BUILTIN_ACK', {}, win.location.origin, null);
  reply('TLSN_RUN_BUILTIN_ACK', { requestId: 'different-run' });
  await vi.advanceTimersByTimeAsync(10_000);
  expect(failure).toBe('EXTENSION_CONNECTION_LOST');
});

it('cleans up an immediate refusal and preserves the non-private bridge', async () => {
  const refused = run(options);
  reply('TLSN_RUN_BUILTIN_RESPONSE', { success: false, error: 'BAD_VALUES' });
  await expect(refused).rejects.toThrow('BAD_VALUES');
  expect(vi.getTimerCount()).toBe(0);
  const other = run({ ...options, pluginId: 'example-work' });
  await vi.advanceTimersByTimeAsync(20_000);
  reply('TLSN_RUN_BUILTIN_RESPONSE', { success: true, result: 'github-result' });
  await expect(other).resolves.toBe('github-result');
});
