import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({
  listener: undefined as undefined | ((message: unknown, sender: unknown) => Promise<unknown>),
  sendMessage: vi.fn(), clear: vi.fn(), moduleClear: vi.fn(), cancel: vi.fn(),
  awaitInit: vi.fn(), execute: vi.fn(),
}));
vi.mock('react', () => ({ useEffect: (effect: () => void) => effect() }));
vi.mock('react/jsx-runtime', () => ({
  jsx: (type: unknown) => ({ type }), jsxs: (type: unknown) => ({ type }),
}));
vi.mock('react-dom/client', () => ({ createRoot: () => ({ render: (element: { type: () => void }) => element.type() }) }));
vi.mock('webextension-polyfill', () => ({ default: { runtime: {
  id: 'test-extension', getURL: (path: string) => `chrome-extension://test-extension/${path}`,
  sendMessage: state.sendMessage,
  onMessage: { addListener: (listener: typeof state.listener) => { state.listener = listener; } },
} } }));
vi.mock('@tlsn/common', () => ({ logger: { init: vi.fn(), info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() } }));
vi.mock('../../src/utils/logLevelStorage', () => ({ getStoredLogLevel: async () => 'error' }));
vi.mock('../../src/offscreen/SessionManager', () => ({ SessionManager: class {
  awaitInit() { return state.awaitInit().then(() => this); }
  executePlugin = state.execute;
  cancelAzurePrivateRun = state.cancel;
} }));
vi.mock('../../src/offscreen/builtinRun', () => ({
  prepareBuiltInRun: async () => ({ code: 'packaged-code', sha256: 'a'.repeat(64) }), readPackagedFile: vi.fn(),
}));
vi.mock('../../src/offscreen/pluginHash', () => ({ runSessionData: (value: unknown) => value }));
vi.mock('../../src/azure-private/browser-client.mjs', () => ({ createAzurePrivateModule: () => ({ clear: state.moduleClear }) }));
vi.mock('../../src/offscreen/azurePrivateWitness', () => ({ createAzurePrivateRun: () => ({ clear: state.clear }) }));
vi.mock('../../src/offscreen/gcpPrivateWitness', () => ({ PrivateWitnessRun: class {} }));
vi.mock('../../src/gcp-private/browser-client.mjs', () => ({ createGcpPrivateModule: vi.fn() }));

const requestId = '11111111-1111-4111-8111-111111111111';
let releaseInit: (() => void) | undefined, releaseExecution: (() => void) | undefined;

beforeEach(async () => {
  vi.useFakeTimers(); vi.clearAllMocks(); vi.resetModules();
  releaseInit = undefined; releaseExecution = undefined;
  state.listener = undefined;
  state.sendMessage.mockResolvedValue({ ok: true }); state.cancel.mockResolvedValue(true);
  state.awaitInit.mockImplementation(() => new Promise<void>(resolve => { releaseInit = resolve; }));
  state.execute.mockImplementation(() => new Promise<void>(resolve => { releaseExecution = resolve; }));
  vi.stubGlobal('document', { getElementById: () => ({}) });
  await import('../../src/entries/Offscreen/index');
  const reply = await state.listener!({ type: 'RUN_BUILTIN_OFFSCREEN', pluginId: 'azure-private-work', requestId,
    values: { params: JSON.stringify({ privateAttempt: {
      proofId: requestId, pluginSha256: 'a'.repeat(64), nonceMac: 'b'.repeat(43), challenge: 'c'.repeat(64),
      issuedAt: Date.now(), cutoffMs: Date.now(), expiresAt: Date.now() + 3600000,
    } }) }, azureDiscoverySelection: {
      proofId: requestId, nonceMac: 'b'.repeat(43), cutoffMs: Date.now(), graph: 'Bearer GRAPH_SYNTHETIC', arm: 'Bearer ARM_SYNTHETIC',
      subscription: '22222222-2222-4222-8222-222222222222', correlation: '33333333-3333-4333-8333-333333333333',
    }, sessionData: { method: 'AZURE_WORK_PRIVATE' } }, {});
  expect(reply).toEqual({ success: true, pending: true, requestId });
});

afterEach(async () => {
  releaseInit?.(); await vi.advanceTimersByTimeAsync(0);
  releaseExecution?.(); await vi.advanceTimersByTimeAsync(0);
  vi.useRealTimers(); vi.unstubAllGlobals();
});

describe('Azure offscreen heartbeat cancellation wiring', () => {
  for (const phase of ['initialization', 'execution']) {
    for (const response of ['denied', 'rejected']) {
      it(`clears and cancels the exact run on a ${response} heartbeat during ${phase}`, async () => {
        if (phase === 'execution') { releaseInit?.(); await vi.advanceTimersByTimeAsync(0); }
        if (response === 'denied') state.sendMessage.mockResolvedValue({ ok: false });
        else state.sendMessage.mockRejectedValue(new Error('TRANSPORT_CLOSED'));
        // A failed close-window delivery must not become an unhandled rejection.
        state.cancel.mockRejectedValue(new Error('WINDOW_CLOSED'));
        await vi.advanceTimersByTimeAsync(20_000);
        expect(state.sendMessage).toHaveBeenCalledWith({ type: 'AZURE_PRIVATE_HEARTBEAT', requestId });
        expect(state.clear).toHaveBeenCalled();
        expect(state.cancel).toHaveBeenCalledExactlyOnceWith(requestId);
      });
    }
  }

  it('keeps the active run on an authenticated positive heartbeat', async () => {
    releaseInit?.(); await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(state.sendMessage).toHaveBeenCalledWith({ type: 'AZURE_PRIVATE_HEARTBEAT', requestId });
    expect(state.clear).not.toHaveBeenCalled(); expect(state.cancel).not.toHaveBeenCalled();
  });
});
