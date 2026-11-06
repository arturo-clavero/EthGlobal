/* eslint-disable @typescript-eslint/no-explicit-any -- mocks of the offscreen entry boundary */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ listener: null as any, execute: vi.fn(), clear: vi.fn(), send: vi.fn(), factory: vi.fn() }));
vi.mock('react', async () => ({ ...await vi.importActual('react'), useEffect: (effect: () => void) => effect() }));
vi.mock('react-dom/client', () => ({ createRoot: () => ({ render: (element: any) => element.type() }) }));
vi.mock('webextension-polyfill', () => ({ default: { runtime: {
  id: 'extension', getURL: (file: string) => `chrome-extension://extension/${file}`,
  onMessage: { addListener: (listener: unknown) => { state.listener = listener; } }, sendMessage: state.send,
} } }));
vi.mock('@tlsn/common', () => ({ logger: { init: vi.fn(), info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() } }));
vi.mock('@tlsn/plugin-sdk', () => ({ canonicalizeHandler: (handler: unknown) => handler }));
vi.mock('../../src/utils/logLevelStorage', () => ({ getStoredLogLevel: async () => 'Info' }));
vi.mock('../../src/offscreen/SessionManager', () => ({ SessionManager: class {
  async awaitInit() { return this; }
  executePlugin(...args: unknown[]) { return state.execute(...args); }
} }));
vi.mock('../../src/offscreen/builtinRun', () => ({ prepareBuiltInRun: async () => ({ code: 'packaged', sha256: 'a'.repeat(64) }),
  readPackagedFile: vi.fn() }));
vi.mock('../../src/offscreen/pluginHash', () => ({ runSessionData: () => ({}) }));
vi.mock('../../src/gcp-private/browser-client.mjs', () => ({ createGcpPrivateModule: state.factory }));

beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks(); vi.useFakeTimers();
  vi.spyOn(console, 'debug').mockImplementation(() => {});
  state.execute.mockImplementation(() => new Promise(() => {}));
  state.factory.mockImplementation(() => ({ clear: state.clear }));
  state.send.mockImplementation(async () => ({ ok: true }));
  document.body.innerHTML = '<div id="app-container"></div>';
});
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); vi.restoreAllMocks(); document.body.innerHTML = ''; });

async function start() {
  await import('../../src/entries/Offscreen/index');
  const reply = await state.listener({ type: 'RUN_BUILTIN_OFFSCREEN', pluginId: 'gcp-work', requestId: 'request',
    values: { params: JSON.stringify({ privateInput: { projectId: 'private-project' }, cutoff: 0, windowDays: 30 }) } }, {});
  expect(reply).toEqual({ success: true, pending: true, requestId: 'request' });
  await vi.advanceTimersByTimeAsync(0);
}

it.each(['ok', 'not-ok', 'rejected'] as const)('heartbeat %s emits only its fixed failure code and preserves clearing', async kind => {
  state.send.mockImplementation(async () => {
    if (kind === 'rejected') throw new Error('private heartbeat detail');
    return { ok: kind === 'ok' };
  });
  await start();
  await vi.advanceTimersByTimeAsync(20_000);
  expect(vi.mocked(console.debug).mock.calls).toEqual(kind === 'ok' ? [] : [
    [kind === 'not-ok' ? 'GCP_PRIVATE_HEARTBEAT_NOT_OK' : 'GCP_PRIVATE_HEARTBEAT_REJECTED'],
  ]);
  expect(state.clear).toHaveBeenCalledTimes(kind === 'ok' ? 0 : 1);
});

it('execute failure keeps the existing generic completion and clears the heartbeat', async () => {
  state.execute.mockRejectedValue(new Error('private execution detail'));
  await start();
  expect(vi.mocked(console.debug).mock.calls).toEqual([['GCP_PRIVATE_EXECUTE_FAILED']]);
  expect(state.send).toHaveBeenCalledWith({ type: 'GCP_PRIVATE_COMPLETE', requestId: 'request',
    success: false, error: 'GCP_PRIVATE_PROVING_FAILED' });
  expect(state.clear).toHaveBeenCalledOnce();
  await vi.advanceTimersByTimeAsync(20_000);
  expect(state.send).toHaveBeenCalledOnce();
});

it.each(['missing-id', 'bad-params', 'factory'] as const)('pre-ack %s emits only a fixed code without starting execution', async kind => {
  await import('../../src/entries/Offscreen/index');
  if (kind === 'factory') state.factory.mockImplementation(() => { throw new Error('private factory detail'); });
  const reply = await state.listener({ type: 'RUN_BUILTIN_OFFSCREEN', pluginId: 'gcp-work',
    requestId: kind === 'missing-id' ? undefined : 'private-request',
    values: { params: kind === 'bad-params' ? 'private malformed params' :
      JSON.stringify({ privateInput: { projectId: 'private-project' }, cutoff: 0, windowDays: 30 }) } }, {});
  expect(reply).toEqual({ success: false, error: 'GCP_PRIVATE_PROVING_FAILED' });
  expect(vi.mocked(console.debug).mock.calls).toEqual([
    [kind === 'missing-id' ? 'GCP_PRIVATE_RUN_ID_MISSING' : 'GCP_PRIVATE_MODULE_FAILED'],
  ]);
  expect(state.execute).not.toHaveBeenCalled();
  expect(state.send).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

it('refuses a second run before constructing another module and preserves the active run', async () => {
  await start();
  const reply = await state.listener({ type: 'RUN_BUILTIN_OFFSCREEN', pluginId: 'gcp-work',
    requestId: 'private-second-request', values: { params: 'private second params' } }, {});
  expect(reply).toEqual({ success: false, error: 'GCP_PRIVATE_PROVING_FAILED' });
  expect(vi.mocked(console.debug).mock.calls).toEqual([['GCP_PRIVATE_RUN_BUSY']]);
  expect(state.factory).toHaveBeenCalledOnce();
  expect(state.execute).toHaveBeenCalledOnce();
  expect(state.clear).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(1);
});

it('a diagnostic console failure cannot change the generic pre-ack refusal', async () => {
  await import('../../src/entries/Offscreen/index');
  vi.mocked(console.debug).mockImplementation(() => { throw new Error('private console detail'); });
  state.factory.mockImplementation(() => { throw new Error('private factory detail'); });
  const reply = await state.listener({ type: 'RUN_BUILTIN_OFFSCREEN', pluginId: 'gcp-work', requestId: 'private-request',
    values: { params: JSON.stringify({ privateInput: { projectId: 'private-project' } }) } }, {});
  expect(reply).toEqual({ success: false, error: 'GCP_PRIVATE_PROVING_FAILED' });
  expect(state.execute).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});
