import { expect, it, vi } from 'vitest';
import browser from 'webextension-polyfill';

vi.mock('../../src/constants/productOrigins', () => ({ isProductOrigin: () => true }));
vi.mock('../../src/constants/builtinPlugins', () => ({ BUILTIN_PLUGINS: [] }));
vi.mock('@tlsn/common', () => ({ LogLevel: { DEBUG: 0 }, logger: { init: vi.fn(), debug: vi.fn(), error: vi.fn() } }));

it('keeps the real AWS page bridge alive past five minutes and expires AWS/GCP at their own deadlines', async () => {
  vi.useFakeTimers();
  vi.mocked(browser.runtime.sendMessage).mockResolvedValue({ success: true, pending: true });
  const listeners = vi.spyOn(window, 'addEventListener');
  const replies = vi.spyOn(window, 'postMessage').mockImplementation(() => {});
  vi.spyOn(document.head, 'appendChild').mockImplementation(node => node);
  let handler: EventListener | undefined;
  try {
    await import('../../src/entries/Content/index');
    handler = listeners.mock.calls.find(([type]) => type === 'message')?.[1] as EventListener;
    expect(handler).toBeTypeOf('function');
    for (const [pluginId, requestId] of [['aws-private-work', 'aws-run'], ['gcp-work', 'gcp-run']]) {
      handler(new MessageEvent('message', { source: window, origin: window.location.origin,
        data: { type: 'TLSN_RUN_BUILTIN', payload: { pluginId, requestId } } }));
    }
    await Promise.resolve();
    vi.advanceTimersByTime(5 * 60 * 1000);
    expect(replies).not.toHaveBeenCalled();
    // GCP's route lifetime is thirteen minutes, longer than AWS's twelve,
    // so neither provider has expired yet.
    vi.advanceTimersByTime(7 * 60 * 1000);
    expect(replies).not.toHaveBeenCalled();
    vi.advanceTimersByTime(60 * 1000);
    expect(replies.mock.calls.map(([message]) => message)).toEqual([
      { type: 'TLSN_RUN_BUILTIN_RESPONSE', requestId: 'aws-run', success: false, error: 'AWS_PRIVATE_PROVING_FAILED' },
      { type: 'TLSN_RUN_BUILTIN_RESPONSE', requestId: 'gcp-run', success: false, error: 'GCP_PRIVATE_PROVING_FAILED' },
    ]);
  } finally {
    if (handler) window.removeEventListener('message', handler);
    vi.useRealTimers(); vi.restoreAllMocks();
  }
});
