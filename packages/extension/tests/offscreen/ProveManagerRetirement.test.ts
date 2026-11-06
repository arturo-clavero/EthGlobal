import { beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ workers: [] as any[] }));
vi.mock('comlink', () => ({ wrap: (worker: any) => worker.api, proxy: (callback: unknown) => callback }));
vi.stubGlobal('WebSocket', { OPEN: 1 });
vi.stubGlobal('Worker', class {
  addEventListener = vi.fn();
  terminate = vi.fn();
  nextProverId = 0;
  api = {
    init: vi.fn().mockResolvedValue(undefined),
    createProver: vi.fn().mockImplementation(() => Promise.resolve(`prover-${this.nextProverId++}`)),
    setupProver: vi.fn().mockResolvedValue(undefined),
    setupProverRelay: vi.fn().mockResolvedValue(undefined),
    freeProver: vi.fn().mockResolvedValue(undefined),
    getTranscript: vi.fn().mockResolvedValue({ sent: [], recv: [] }),
  };
  constructor() { state.workers.push(this); }
});

const { ProveManager } = await import('../../src/offscreen/ProveManager/index');
beforeEach(() => { state.workers = []; });
function managerWithWorker() {
  const manager = new ProveManager();
  void (manager as any).workerApi;
  return manager;
}

describe('idle TLS worker retirement', () => {
  it('retains an explicit initialization thread count across retirement without changing the default', async () => {
    const originalNavigator = navigator;
    vi.stubGlobal('navigator', { hardwareConcurrency: 12 });
    try {
      const normal = new ProveManager(), azure = new ProveManager(2);
      await normal.init(); await azure.init();
      expect(state.workers[0].api.init).toHaveBeenCalledWith(expect.objectContaining({ hardwareConcurrency: 12 }));
      expect(state.workers[1].api.init).toHaveBeenCalledWith(expect.objectContaining({ hardwareConcurrency: 2 }));
      expect(azure.releaseIdleWorker()).toBe(true);
      await azure.init();
      expect(state.workers[2].api.init).toHaveBeenCalledWith(expect.objectContaining({ hardwareConcurrency: 2 }));
      expect(state.workers[0].terminate).not.toHaveBeenCalled();
      azure.dispose(); normal.dispose();
    } finally { vi.stubGlobal('navigator', originalNavigator); }
  });

  it('allows initialization to be retried after a failure', async () => {
    const manager = managerWithWorker(), worker = state.workers[0];
    worker.api.init.mockRejectedValueOnce(new Error('initialization failed'));
    await expect(manager.init()).rejects.toThrow('initialization failed');
    expect(manager.releaseIdleWorker()).toBe(false);
    await manager.init();
    expect(worker.api.init).toHaveBeenCalledTimes(2);
    expect(worker.addEventListener).toHaveBeenCalledTimes(1);
    expect(manager.releaseIdleWorker()).toBe(true);
  });

  it('preserves an active relay and pending cleanup, then initializes a fresh worker for a proxy run', async () => {
    const manager = managerWithWorker(), first = state.workers[0];
    const id = await manager.createProverRelay('provider.test', () => {});
    expect(manager.releaseIdleWorker()).toBe(false);
    let settle!: () => void;
    first.api.freeProver.mockReturnValueOnce(new Promise<void>(resolve => { settle = resolve; }));
    const cleanup = manager.cleanupProver(id);
    expect(manager.releaseIdleWorker()).toBe(false);
    expect(first.terminate).not.toHaveBeenCalled();
    settle(); await cleanup;
    expect(manager.releaseIdleWorker()).toBe(true);
    expect(first.terminate).toHaveBeenCalledTimes(1);
    expect(state.workers).toHaveLength(1);
    vi.spyOn(manager as any, 'createSession').mockResolvedValue('wss://verifier.test/session');
    const next = await manager.createProver('provider.test', 'https://verifier.test');
    const second = state.workers[1];
    expect(second.api.init).toHaveBeenCalledTimes(1);
    expect(second.api.setupProver).toHaveBeenCalledWith(next, 'wss://verifier.test/session');
    expect(first.api.createProver).toHaveBeenCalledTimes(1);
    expect(manager.releaseIdleWorker()).toBe(false);
    await manager.cleanupProver(next);
    expect(manager.releaseIdleWorker()).toBe(true);
  });

  it('does not retire during initialization or while a prover ID is being allocated', async () => {
    const manager = managerWithWorker(), worker = state.workers[0];
    let initialized!: () => void, allocated!: (id: string) => void;
    worker.api.init.mockReturnValueOnce(new Promise<void>(resolve => { initialized = resolve; }));
    worker.api.createProver.mockReturnValueOnce(new Promise<string>(resolve => { allocated = resolve; }));
    const creation = manager.createProverRelay('provider.test', () => {});
    expect(manager.releaseIdleWorker()).toBe(false);
    initialized();
    await vi.waitFor(() => expect(worker.api.createProver).toHaveBeenCalledTimes(1));
    expect(manager.releaseIdleWorker()).toBe(false);
    allocated('pending-prover');
    const id = await creation;
    expect(worker.terminate).not.toHaveBeenCalled();
    await manager.cleanupProver(id);
    expect(manager.releaseIdleWorker()).toBe(true);
  });

  it('waits for cleanup calls even when the caller no longer has a tracked session', async () => {
    const manager = managerWithWorker(), worker = state.workers[0];
    await manager.init();
    let settle!: () => void;
    worker.api.freeProver.mockReturnValueOnce(new Promise<void>(resolve => { settle = resolve; }));
    const cleanup = manager.cleanupProver('previous-prover');
    expect(manager.releaseIdleWorker()).toBe(false);
    settle(); await cleanup;
    expect(manager.releaseIdleWorker()).toBe(true);
  });

  it('does not retire a worker whose prover cleanup failed', async () => {
    const manager = managerWithWorker(), worker = state.workers[0];
    const id = await manager.createProverRelay('provider.test', () => {});
    worker.api.freeProver.mockRejectedValueOnce(new Error('cleanup incomplete'));
    await manager.cleanupProver(id);
    expect(manager.releaseIdleWorker()).toBe(false);
    expect(worker.terminate).not.toHaveBeenCalled();
  });

  it('keeps another manager and its active prover independent', async () => {
    const idle = new ProveManager(), active = new ProveManager();
    await idle.init();
    const id = await active.createProverRelay('provider.test', () => {});
    expect(idle.releaseIdleWorker()).toBe(true);
    expect(state.workers[0].terminate).toHaveBeenCalledTimes(1);
    expect(state.workers[1].terminate).not.toHaveBeenCalled();
    expect(active.releaseIdleWorker()).toBe(false);
    await active.cleanupProver(id);
    expect(active.releaseIdleWorker()).toBe(true);
  });

  it('cleans up a failed proxy setup before retirement and shares initialization across callers', async () => {
    const manager = managerWithWorker(), worker = state.workers[0];
    await Promise.all([manager.init(), manager.init()]);
    expect(worker.api.init).toHaveBeenCalledTimes(1);
    expect(worker.addEventListener).toHaveBeenCalledTimes(1);
    vi.spyOn(manager as any, 'createSession').mockResolvedValue('wss://verifier.test/session');
    worker.api.setupProver.mockRejectedValueOnce(new Error('setup rejected'));
    await expect(manager.createProver('provider.test', 'https://verifier.test')).rejects.toThrow('setup rejected');
    expect(worker.api.freeProver).toHaveBeenCalledTimes(1);
    expect(manager.releaseIdleWorker()).toBe(true);
  });

  it('refuses retirement while an otherwise idle worker has a pending RPC', async () => {
    const manager = managerWithWorker(), worker = state.workers[0];
    await manager.init();
    let settle!: (value: { sent: number[]; recv: number[] }) => void;
    worker.api.getTranscript.mockReturnValueOnce(new Promise(resolve => { settle = resolve; }));
    const transcript = manager.transcript('previous-prover');
    expect(manager.releaseIdleWorker()).toBe(false);
    settle({ sent: [], recv: [] }); await transcript;
    expect(manager.releaseIdleWorker()).toBe(true);
  });

  it('blocks retirement after failed cleanup even for an untracked prover', async () => {
    const manager = managerWithWorker(), worker = state.workers[0];
    await manager.init();
    worker.api.freeProver.mockRejectedValueOnce(new Error('cleanup incomplete'));
    await manager.cleanupProver('previous-prover');
    expect(manager.releaseIdleWorker()).toBe(false);
    expect(worker.terminate).not.toHaveBeenCalled();
    manager.dispose();
    expect(worker.terminate).toHaveBeenCalledTimes(1);
  });

  it('cannot revive a permanently disposed manager after idle retirement', async () => {
    const manager = managerWithWorker(), worker = state.workers[0];
    await manager.init();
    expect(manager.releaseIdleWorker()).toBe(true);
    manager.dispose();
    expect(manager.releaseIdleWorker()).toBe(false);
    await expect(manager.init()).rejects.toThrow('PRIVATE_PROVER_DISPOSED');
    await expect(manager.createProverRelay('provider.test', () => {})).rejects.toThrow('PRIVATE_PROVER_DISPOSED');
    expect(state.workers).toHaveLength(1);
    expect(worker.terminate).toHaveBeenCalledTimes(1);
  });

  it('cancellation settles held allocation and cannot revive on its late result', async () => {
    const manager = managerWithWorker(), worker = state.workers[0];
    await manager.init();
    let settle!: (id: string) => void;
    worker.api.createProver.mockReturnValueOnce(new Promise(resolve => { settle = resolve; }));
    const creation = manager.createProverRelay('provider.test', () => {});
    const outcome = expect(creation).rejects.toThrow('PRIVATE_PROVER_DISPOSED');
    await vi.waitFor(() => expect(worker.api.createProver).toHaveBeenCalledTimes(1));
    manager.dispose(); await outcome;
    settle('late-prover'); await Promise.resolve();
    expect(manager.releaseIdleWorker()).toBe(false);
    await expect(manager.init()).rejects.toThrow('PRIVATE_PROVER_DISPOSED');
    expect(worker.api.setupProverRelay).not.toHaveBeenCalled();
    expect(state.workers).toHaveLength(1);
  });

  it('cancellation settles held free and late completion cannot recreate a worker', async () => {
    const manager = managerWithWorker(), worker = state.workers[0];
    const id = await manager.createProverRelay('provider.test', () => {});
    let settle!: () => void;
    worker.api.freeProver.mockReturnValueOnce(new Promise<void>(resolve => { settle = resolve; }));
    const cleanup = manager.cleanupProver(id);
    expect(manager.releaseIdleWorker()).toBe(false);
    manager.dispose(); await cleanup;
    settle(); await Promise.resolve();
    expect(manager.releaseIdleWorker()).toBe(false);
    await expect(manager.init()).rejects.toThrow('PRIVATE_PROVER_DISPOSED');
    expect(state.workers).toHaveLength(1);
    expect(worker.terminate).toHaveBeenCalledTimes(1);
  });
});

it('rejects old socket and worker callbacks after the same prover ID is reused', async () => {
  const OriginalWebSocket = globalThis.WebSocket;
  const sockets: any[] = [];
  vi.stubGlobal('WebSocket', class {
    static OPEN = 1; static CONNECTING = 0;
    readyState = 1;
    onopen: any; onmessage: any; onerror: any; onclose: any;
    send = vi.fn(); close = vi.fn();
    constructor() { sockets.push(this); }
  });
  const manager = new ProveManager();
  try {
    const firstCapture = manager.createProver('provider.test', 'https://verifier.test');
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    const firstSocket = sockets[0], firstWorker = state.workers[0];
    const oldMessage = firstSocket.onmessage, oldOpen = firstSocket.onopen;
    const oldProgress = firstWorker.addEventListener.mock.calls[0][1];
    oldMessage({ data: JSON.stringify({ type: 'session_registered', sessionId: 'first-session' }) });
    const firstId = await firstCapture;
    firstWorker.api.sendRequest = vi.fn().mockResolvedValue(undefined);
    firstWorker.api.getTranscript.mockResolvedValueOnce({ sent: [1], recv: [2] });
    await manager.sendRequest(firstId, undefined, { url: 'https://provider.test/' });
    const sent = manager.getSentBytes(firstId), recv = manager.getRecvBytes(firstId);
    const oldCallback = vi.fn(); manager.setProgressCallbackForProver(firstId, oldCallback);
    await manager.cleanupProver(firstId);
    expect([...sent, ...recv]).toEqual([0, 0]);
    expect(manager.getActiveSessionCount()).toBe(0);
    expect(firstSocket.onmessage).toBeNull();
    expect(manager.releaseIdleWorker()).toBe(true);

    const secondCapture = manager.createProver('provider.test', 'https://verifier.test');
    await vi.waitFor(() => expect(sockets).toHaveLength(2));
    const secondSocket = sockets[1];
    secondSocket.onmessage({ data: JSON.stringify({ type: 'session_registered', sessionId: 'second-session' }) });
    const secondId = await secondCapture;
    expect(secondId).toBe(firstId);
    expect(manager.getSentBytes(secondId)).toHaveLength(0);
    expect(manager.getRecvBytes(secondId)).toHaveLength(0);
    const currentCallback = vi.fn(); manager.setProgressCallbackForProver(secondId, currentCallback);
    oldOpen();
    for (const data of [
      { type: 'session_registered', sessionId: 'stale-session' },
      { type: 'session_completed', results: ['stale'] },
      { type: 'error', message: 'stale' },
      { sessionId: 'legacy-stale' },
      { results: ['legacy-stale'] },
    ]) oldMessage({ data: JSON.stringify(data) });
    oldProgress({ data: { type: 'WASM_PROGRESS', step: 'COMPLETE' } });
    expect(firstSocket.send).not.toHaveBeenCalled();
    expect(manager.getSessionId(secondId)).toBe('second-session');
    expect((manager as any).sessions.get(secondId).responseReceived).toBe(false);
    expect((manager as any).sessions.get(secondId).error).toBeNull();
    expect(currentCallback).not.toHaveBeenCalled();
    state.workers[1].addEventListener.mock.calls[0][1]({ data: { type: 'WASM_PROGRESS', step: 'CURRENT' } });
    expect(currentCallback).toHaveBeenCalledOnce();
    expect(oldCallback).not.toHaveBeenCalled();
  } finally {
    manager.dispose(); vi.stubGlobal('WebSocket', OriginalWebSocket);
  }
});
