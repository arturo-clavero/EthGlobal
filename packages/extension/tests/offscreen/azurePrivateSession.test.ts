/* eslint-disable @typescript-eslint/no-explicit-any -- compiled host/worker boundary mocks */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, webcrypto } from 'node:crypto';

const state = vi.hoisted(() => ({ managers: [] as any[], gate: '' as '' | 'init' | 'config',
  entered: undefined as (() => void) | undefined, release: undefined as (() => void) | undefined,
  openWindow: false, hosts: 0, snapshots: [] as Uint8Array[], capabilities: new Map<string, () => any>(), consumeDiscovery: false, skipProve: false, selection: null as any }));
const runData = { _autoApproved: '1', method: 'AZURE_WORK_PRIVATE', mode: 'Proxy',
  proofId: '11111111-1111-4111-8111-111111111111', pluginSha256: 'a'.repeat(64) };
const steps = ['identity', 'tenant', 'activity'];
const handler = (type: string) => ({ type, part: 'ALL', action: { kind: 'HASH', algorithm: 'SHA256' } });

vi.mock('@tlsn/plugin-sdk', () => ({ canonicalizeHandler: (value: unknown) => value,
  default: class {
    constructor(readonly callbacks: any) { state.hosts++; }
    getPluginConfig() { return {}; }
    addCapability(name: string, handler: () => any) { state.capabilities.set(name, handler); }
    async executePlugin() {
      if (state.skipProve) return {};
      if (state.consumeDiscovery) {
        const take = state.capabilities.get('takeAzureDiscovery')!;
        state.selection = take(); expect(() => take()).toThrow('AZURE_DISCOVERY_UNAVAILABLE');
      }
      if (state.openWindow) await this.callbacks.onOpenWindow('https://portal.azure.com/');
      for (const step of steps) {
        const host = step === 'identity' ? 'graph.microsoft.com' : 'management.azure.com';
        await this.callbacks.onProve({ url: `https://${host}/`, method: 'GET', headers: {} }, {
          verifierUrl: 'https://verifier.test', proxyUrl: 'wss://proxy.test', handlers: [],
          maxSentData: 16384, maxRecvData: 16384,
          sessionData: { ...runData, nonceMac: 'b'.repeat(43), step },
        });
      }
      return { ignoredPluginPayload: true };
    }
  },
}));
vi.mock('../../src/offscreen/permissionValidator', () => ({ validateProvePermission: vi.fn(), validateOpenWindowPermission: vi.fn() }));
vi.mock('../../src/offscreen/ProveManager', () => ({ ProveManager: class {
  seq = 0; disposed = false; sent = new Uint8Array(); recv = new Uint8Array();
  rejectInit: undefined | ((error: Error) => void);
  openings: any;
  constructor(readonly initializationThreads?: number) { state.managers.push(this); }
  init = vi.fn(async () => {
    if (state.gate === 'init') await new Promise<void>((resolve, reject) => {
      state.release = resolve; this.rejectInit = reject; state.entered?.();
    });
    if (this.disposed) throw new Error('DISPOSED');
  });
  dispose = vi.fn(() => {
    this.disposed = true; this.sent.fill(0); this.recv.fill(0);
    this.rejectInit?.(new Error('DISPOSED'));
  });
  createProver = vi.fn(async () => String(this.seq++));
  setProgressCallbackForProver() {}
  async sendRequest() {
    this.sent = new Uint8Array([1, 2, 3]); this.recv = new Uint8Array([4, 5, 6]);
    state.snapshots.push(this.sent, this.recv);
  }
  computeReveal() { return { sentRanges: [], recvRanges: [],
    sentRangesWithHandlers: [{ start: 0, end: 3, handler: handler('SENT') }],
    recvRangesWithHandlers: [{ start: 0, end: 3, handler: handler('RECV') }],
    commit: { sent: [{ start: 0, end: 3, algorithm: 'SHA256' }], recv: [{ start: 0, end: 3, algorithm: 'SHA256' }] } }; }
  getSentBytes() { return this.sent; }
  getRecvBytes() { return this.recv; }
  async sendRevealConfig() {
    if (state.gate === 'config') await new Promise<void>(resolve => { state.release = resolve; state.entered?.(); });
  }
  reveal = vi.fn(() => {
    const opening = (bytes: Uint8Array, n: number) => ({
      hash: Array.from(createHash('sha256').update(bytes).update(new Uint8Array(16).fill(n)).digest()),
      blinder: Array(16).fill(n),
    });
    return this.openings = { sent: [opening(this.sent, 2)], recv: [opening(this.recv, 4)] };
  });
  getResponse() { return { results: [
    { ...handler('SENT'), value: Buffer.from(this.openings.sent[0].hash).toString('hex') },
    { ...handler('RECV'), value: Buffer.from(this.openings.recv[0].hash).toString('hex') },
  ] }; }
  getSessionId(id: string) { return `22222222-2222-4222-8222-22222222222${id}`; }
  cleaned = 0;
  cleanupProver = vi.fn(async () => { await Promise.resolve(); this.cleaned++; });
  releaseIdleWorker = vi.fn(() => {
    expect(this.cleanupProver).toHaveBeenCalledTimes(this.seq);
    expect(this.cleaned).toBe(this.seq);
    return !this.disposed;
  });
} }));

import { SessionManager } from '../../src/offscreen/SessionManager';
import { PrivateWitnessRun } from '../../src/offscreen/gcpPrivateWitness';

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  state.hosts = 0; state.capabilities.clear(); state.consumeDiscovery = false; state.skipProve = false; state.selection = null;
  state.openWindow = false; state.managers = []; state.snapshots = []; state.gate = ''; state.entered = undefined; state.release = undefined;
  vi.stubGlobal('chrome', { runtime: { id: 'test-extension', getURL: (path: string) => `chrome-extension://test-extension/${path}`,
    sendMessage: vi.fn().mockResolvedValue(undefined), onMessage: { addListener: vi.fn(), removeListener: vi.fn() } } });
});
function privateRun(prove = vi.fn(async () => ({ verifiedLocally: true }))) {
  const module = { prove, clear: vi.fn() };
  return { module, run: new PrivateWitnessRun(runData, runData.proofId, module, {
    method: 'AZURE_WORK_PRIVATE', nonceMac: 'b'.repeat(43), proveTimeoutMs: 1000,
    steps: steps.map(step => ({ step, host: step === 'identity' ? 'graph.microsoft.com' : 'management.azure.com' })),
    finish: result => result,
  }) };
}
const start = (manager: SessionManager, run: PrivateWitnessRun) => manager.executePlugin('compiled', runData.proofId,
  { ...runData, _approvalMode: 'all-session' }, run, {
    proofId: runData.proofId, nonceMac: 'b'.repeat(43), cutoffMs: Date.now(),
    graph: 'Bearer GRAPH_SYNTHETIC', arm: 'Bearer ARM_SYNTHETIC',
    subscription: '11111111-1111-4111-8111-111111111111', correlation: '22222222-2222-4222-8222-222222222222',
  });

describe('Azure native lifecycle isolation', () => {
  it('retires the Azure native worker after each receipt before local proving', async () => {
    const manager = new SessionManager();
    const local = privateRun(vi.fn(async () => {
      expect(state.managers[1].cleanupProver).toHaveBeenCalledTimes(steps.length);
      expect(state.managers[1].releaseIdleWorker).toHaveBeenCalledTimes(steps.length);
      return { verifiedLocally: true };
    }));
    await start(manager, local.run);
    expect(state.managers[1].initializationThreads).toBe(2);
    expect(state.managers[0].initializationThreads).toBeUndefined();
    expect(state.managers[0].releaseIdleWorker).not.toHaveBeenCalled();
  });

  it('does not retire native workers for ordinary plugin receipts', async () => {
    await new SessionManager().executePlugin('compiled', runData.proofId,
      { ...runData, method: 'ORDINARY', _approvalMode: 'all-session' });
    expect(state.managers[0].cleanupProver).toHaveBeenCalledTimes(steps.length);
    expect(state.managers[0].releaseIdleWorker).not.toHaveBeenCalled();
  });

  it('does not expose Azure selection to an ordinary plugin', async () => {
    state.skipProve = true;
    await new SessionManager().executePlugin('compiled');
    expect(state.hosts).toBeGreaterThan(0);
    expect(state.capabilities.has('takeAzureDiscovery')).toBe(false);
  });
  it('does not expose Azure selection to the GCP private adapter', async () => {
    state.skipProve = true;
    const module = { prove: vi.fn(), clear: vi.fn() };
    try { await new SessionManager().executePlugin('compiled', runData.proofId,
      { ...runData, method: 'GCP_WORK' }, module as any); }
    catch { /* A run with no captures cannot finish, regardless of capability isolation. */ }
    expect(state.hosts).toBeGreaterThan(0);
    expect(state.capabilities.has('takeAzureDiscovery')).toBe(false);
    expect(state.managers).toHaveLength(1);
    expect(state.managers[0].initializationThreads).toBeUndefined();
  });
  it('exposes selected credentials only through a one-use Azure host capability', async () => {
    state.consumeDiscovery = true;
    const manager = new SessionManager(), local = privateRun();
    await start(manager, local.run);
    expect(state.selection.graph).toBe('Bearer GRAPH_SYNTHETIC');
    expect(() => state.capabilities.get('takeAzureDiscovery')!()).toThrow();
  });
  it('does not start native work after cancellation before registration', async () => {
    const manager = new SessionManager(), local = privateRun();
    local.run.clear();
    await expect(start(manager, local.run)).rejects.toThrow();
    expect(state.managers[1].disposed).toBe(true);
    expect(state.managers[1].init).not.toHaveBeenCalled();
    expect(state.managers[1].createProver).not.toHaveBeenCalled();
    expect(state.managers[0].dispose).not.toHaveBeenCalled();
    expect(local.module.prove).not.toHaveBeenCalled();
  });

  it('does not create a host after heartbeat loss during config extraction', async () => {
    const manager = new SessionManager(), local = privateRun();
    let release!: (config: object) => void;
    vi.spyOn(manager as any, 'extractConfig').mockImplementation(() => new Promise(resolve => { release = resolve; }));
    const host = vi.spyOn(manager as any, 'createExecutionHost');
    const pending = start(manager, local.run);
    const rejected = expect(pending).rejects.toThrow();
    local.run.clear(); release({}); await rejected;
    expect(host).not.toHaveBeenCalled();
    expect(state.managers[1].disposed).toBe(true);
    expect(state.managers[1].init).not.toHaveBeenCalled();
    expect(state.managers[0].dispose).not.toHaveBeenCalled();
  });

  it('cancels pending native initialization and does not initialize or dispose the shared manager', async () => {
    state.gate = 'init';
    const reached = new Promise<void>(resolve => { state.entered = resolve; });
    const manager = new SessionManager(), local = privateRun();
    const pending = start(manager, local.run);
    const rejected = expect(pending).rejects.toThrow('GCP_PRIVATE_PROOF_FAILED');
    await reached;
    expect(await manager.cancelAzurePrivateRun(runData.proofId)).toBe(true);
    await rejected;
    state.release?.();
    expect(state.managers[0].init).not.toHaveBeenCalled();
    expect(state.managers[0].dispose).not.toHaveBeenCalled();
    expect(state.managers[1].disposed).toBe(true);
    expect(state.managers[1].createProver).not.toHaveBeenCalled();
    expect(local.module.prove).not.toHaveBeenCalled();
  });

  it('cannot reveal after cancellation during an awaited reveal configuration', async () => {
    state.gate = 'config';
    const reached = new Promise<void>(resolve => { state.entered = resolve; });
    const manager = new SessionManager(), local = privateRun();
    const pending = start(manager, local.run);
    const rejected = expect(pending).rejects.toThrow('GCP_PRIVATE_PROOF_FAILED');
    await reached;
    await manager.cancelAzurePrivateRun(runData.proofId);
    state.release?.(); await rejected;
    expect(state.managers[1].reveal).not.toHaveBeenCalled();
    expect(local.module.prove).not.toHaveBeenCalled();
    expect(state.snapshots.every(bytes => bytes.every(byte => byte === 0))).toBe(true);
    expect(state.managers[0].dispose).not.toHaveBeenCalled();
  });

  it('disposes each dedicated native worker before proving and supports repeated Azure runs', async () => {
    const manager = new SessionManager();
    for (let i = 0; i < 2; i++) {
      const local = privateRun(vi.fn(async () => {
        expect(state.managers.at(-1).disposed).toBe(true);
        expect(state.snapshots.every(bytes => bytes.every(byte => byte === 0))).toBe(true);
        return { verifiedLocally: true };
      }));
      await expect(start(manager, local.run)).resolves.toEqual({ verifiedLocally: true });
    }
    expect(state.managers).toHaveLength(3);
    expect(state.managers[1]).not.toBe(state.managers[2]);
    expect(state.managers[0].init).not.toHaveBeenCalled();
    expect(state.managers[0].dispose).not.toHaveBeenCalled();
  });
});


describe('Azure popup lifetime across route loss', () => {
  it('uses the exact saved popup pair when cancelling native capture', async () => {
    state.openWindow = true; state.gate = 'init';
    const reached = new Promise<void>(resolve => { state.entered = resolve; });
    const send = vi.mocked(chrome.runtime.sendMessage);
    send.mockImplementation(async (message: any) => message.type === 'OPEN_WINDOW'
      ? { type: 'WINDOW_OPENED', payload: { windowId: 10, tabId: 11, uuid: 'owned' } } : { ok: true });
    const manager = new SessionManager(), local = privateRun();
    const pending = start(manager, local.run), rejected = expect(pending).rejects.toThrow('GCP_PRIVATE_PROOF_FAILED');
    await reached;
    expect(await manager.cancelAzurePrivateRun(runData.proofId)).toBe(true);
    await rejected;
    expect(send).toHaveBeenCalledWith({ type: 'CLOSE_AZURE_PRIVATE_WINDOW', requestId: runData.proofId, windowId: 10, tabId: 11 });
    expect(send.mock.calls.some(([message]: any[]) => message.type === 'CLOSE_WINDOW')).toBe(false);
    expect(state.managers[1].disposed).toBe(true);
  });

  it('closes a popup delivered after cancellation without starting native capture', async () => {
    state.openWindow = true;
    let opened!: () => void, release!: (value: unknown) => void;
    const reached = new Promise<void>(resolve => { opened = resolve; });
    const send = vi.mocked(chrome.runtime.sendMessage);
    send.mockImplementation((message: any) => message.type === 'OPEN_WINDOW'
      ? new Promise(resolve => { release = resolve; opened(); }) : Promise.resolve({ ok: true }));
    const manager = new SessionManager(), local = privateRun();
    const pending = start(manager, local.run), rejected = expect(pending).rejects.toThrow('GCP_PRIVATE_PROOF_FAILED');
    await reached; expect(await manager.cancelAzurePrivateRun(runData.proofId)).toBe(true);
    release({ type: 'WINDOW_OPENED', payload: { windowId: 10, tabId: 11, uuid: 'owned' } });
    await rejected;
    expect(send).toHaveBeenCalledWith({ type: 'CLOSE_AZURE_PRIVATE_WINDOW', requestId: runData.proofId, windowId: 10, tabId: 11 });
    expect(state.managers[1].init).not.toHaveBeenCalled();
    expect(local.module.prove).not.toHaveBeenCalled();
  });
});
