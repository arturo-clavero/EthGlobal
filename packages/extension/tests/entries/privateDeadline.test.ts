import { expect, it, vi } from 'vitest';
import browser from 'webextension-polyfill';

vi.mock('../../src/constants/productOrigins', () => ({ isProductOrigin: () => true }));
vi.mock('../../src/constants/builtinPlugins', () => ({ BUILTIN_PLUGINS: [] }));
vi.mock('@tlsn/common', () => ({ LogLevel: { DEBUG: 0 }, logger: { init: vi.fn(), debug: vi.fn(), error: vi.fn() } }));

it('keeps the real AWS page bridge alive past five minutes and expires AWS/GCP at their own deadlines', async () => {
  vi.useFakeTimers();
  vi.mocked(browser.runtime.sendMessage).mockImplementation(async message =>
    message.type === 'PING' ? { type: 'PONG' } : { success: true, pending: true });
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
    await vi.advanceTimersByTimeAsync(0);
    expect(replies.mock.calls.map(([message]) => message)).toEqual([
      { type: 'TLSN_RUN_BUILTIN_ACK', requestId: 'aws-run' },
      { type: 'TLSN_RUN_BUILTIN_ACK', requestId: 'gcp-run' },
    ]);
    replies.mockClear();
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

it('reports an invalidated Chrome context before acknowledging a private run', async () => {
  vi.resetModules();
  vi.useFakeTimers();
  vi.mocked(browser.runtime.sendMessage).mockImplementation(message => {
    if (message.type === 'PING') throw new Error('Extension context invalidated.');
    return Promise.resolve(undefined);
  });
  const listeners = vi.spyOn(window, 'addEventListener');
  const replies = vi.spyOn(window, 'postMessage').mockImplementation(() => {});
  vi.spyOn(document.head, 'appendChild').mockImplementation(node => node);
  let handler: EventListener | undefined;
  try {
    await import('../../src/entries/Content/index');
    handler = listeners.mock.calls.find(([type]) => type === 'message')?.[1] as EventListener;
    handler(new MessageEvent('message', { source: window, origin: window.location.origin,
      data: { type: 'TLSN_RUN_BUILTIN', payload: { pluginId: 'gcp-work', requestId: 'gcp-run' } } }));
    await vi.advanceTimersByTimeAsync(0);
    expect(replies.mock.calls.map(([message]) => message)).toEqual([
      { type: 'TLSN_RUN_BUILTIN_RESPONSE', requestId: 'gcp-run', success: false, error: 'EXTENSION_CONNECTION_LOST' },
    ]);
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    if (handler) window.removeEventListener('message', handler);
    vi.useRealTimers(); vi.restoreAllMocks();
  }
});


it('passes a fixed AWS permission failure only from the background and keeps GCP errors generic', async () => {
  vi.resetModules(); vi.useFakeTimers();
  vi.mocked(browser.runtime.sendMessage).mockImplementation(async message => message.type === 'PING' ? { type: 'PONG' } : { success: true, pending: true });
  const listeners = vi.spyOn(window, 'addEventListener');
  const runtimeListeners = vi.spyOn(browser.runtime.onMessage, 'addListener');
  const replies = vi.spyOn(window, 'postMessage').mockImplementation(() => {});
  vi.spyOn(document.head, 'appendChild').mockImplementation(node => node);
  let handler: EventListener | undefined;
  let runtimeHandler: Parameters<typeof browser.runtime.onMessage.addListener>[0] | undefined;
  try {
    await import('../../src/entries/Content/index');
    handler = listeners.mock.calls.find(([type]) => type === 'message')?.[1] as EventListener;
    runtimeHandler = runtimeListeners.mock.calls.at(-1)?.[0];
    expect(runtimeHandler).toBeTypeOf('function');
    for (const [pluginId, requestId] of [['aws-private-work', 'denied'], ['aws-private-work', 'raw-error'], ['gcp-work', 'gcp-denied']]) {
      handler(new MessageEvent('message', { source: window, origin: window.location.origin,
        data: { type: 'TLSN_RUN_BUILTIN', payload: { pluginId, requestId } } }));
    }
    await vi.advanceTimersByTimeAsync(0); replies.mockClear();
    const sender = { id: browser.runtime.id, url: browser.runtime.getURL('background.bundle.js') };
    const failure = { type: 'RUN_BUILTIN_COMPLETE', requestId: 'denied', success: false, error: 'AWS_ACTIVITY_ACCESS_REQUIRED' };
    runtimeHandler!(failure, { ...sender, url: sender.url + '?forged' });
    expect(replies).not.toHaveBeenCalled();
    runtimeHandler!(failure, sender);
    runtimeHandler!({ ...failure, requestId: 'raw-error', error: 'PRIVATE_ARN_SENTINEL' }, sender);
    runtimeHandler!({ ...failure, requestId: 'gcp-denied' }, sender);
    expect(replies.mock.calls.map(([message]) => message)).toEqual([
      { type: 'TLSN_RUN_BUILTIN_RESPONSE', requestId: 'denied', success: false, error: 'AWS_ACTIVITY_ACCESS_REQUIRED' },
      { type: 'TLSN_RUN_BUILTIN_RESPONSE', requestId: 'raw-error', success: false, error: 'AWS_PRIVATE_PROVING_FAILED' },
      { type: 'TLSN_RUN_BUILTIN_RESPONSE', requestId: 'gcp-denied', success: false, error: 'GCP_PRIVATE_PROVING_FAILED' },
    ]);
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    if (handler) window.removeEventListener('message', handler);
    if (runtimeHandler) browser.runtime.onMessage.removeListener(runtimeHandler);
    vi.clearAllTimers(); vi.useRealTimers(); vi.restoreAllMocks();
  }
});
