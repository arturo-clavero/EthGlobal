import { beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ workers: [] as any[] }));
vi.mock('comlink', () => ({ wrap: (worker: any) => worker.api, proxy: (callback: unknown) => callback }));
vi.stubGlobal('WebSocket', { OPEN: 1 });
vi.stubGlobal('Worker', class {
  addEventListener = vi.fn();
  terminate = vi.fn();
  api = {
    init: vi.fn().mockResolvedValue(undefined),
    createProver: vi.fn().mockResolvedValue(`prover-${state.workers.length}`),
    setupProver: vi.fn().mockResolvedValue(undefined),
    setupProverRelay: vi.fn().mockResolvedValue(undefined),
    freeProver: vi.fn().mockResolvedValue(undefined),
  };
  constructor() { state.workers.push(this); }
});

const { ProveManager } = await import('../../src/offscreen/ProveManager/index');
beforeEach(() => { state.workers = []; });

describe('idle TLS worker retirement', () => {
  it('allows initialization to be retried after a failure', async () => {
    const manager = new ProveManager(), worker = state.workers[0];
    worker.api.init.mockRejectedValueOnce(new Error('initialization failed'));
    await expect(manager.init()).rejects.toThrow('initialization failed');
    expect(manager.releaseIdleWorker()).toBe(false);
    await manager.init();
    expect(worker.api.init).toHaveBeenCalledTimes(2);
    expect(worker.addEventListener).toHaveBeenCalledTimes(1);
    expect(manager.releaseIdleWorker()).toBe(true);
  });

  it('preserves an active relay and pending cleanup, then initializes a fresh worker for a proxy run', async () => {
    const manager = new ProveManager(), first = state.workers[0];
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
    const second = state.workers[1];
    expect(second.api.init).not.toHaveBeenCalled();
    vi.spyOn(manager as any, 'createSession').mockResolvedValue('wss://verifier.test/session');
    const next = await manager.createProver('provider.test', 'https://verifier.test');
    expect(second.api.init).toHaveBeenCalledTimes(1);
    expect(second.api.setupProver).toHaveBeenCalledWith(next, 'wss://verifier.test/session');
    expect(first.api.createProver).toHaveBeenCalledTimes(1);
    expect(manager.releaseIdleWorker()).toBe(false);
    await manager.cleanupProver(next);
    expect(manager.releaseIdleWorker()).toBe(true);
  });

  it('does not retire during initialization or while a prover ID is being allocated', async () => {
    const manager = new ProveManager(), worker = state.workers[0];
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
    const manager = new ProveManager(), worker = state.workers[0];
    await manager.init();
    let settle!: () => void;
    worker.api.freeProver.mockReturnValueOnce(new Promise<void>(resolve => { settle = resolve; }));
    const cleanup = manager.cleanupProver('previous-prover');
    expect(manager.releaseIdleWorker()).toBe(false);
    settle(); await cleanup;
    expect(manager.releaseIdleWorker()).toBe(true);
  });

  it('does not retire a worker whose prover cleanup failed', async () => {
    const manager = new ProveManager(), worker = state.workers[0];
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
    const manager = new ProveManager(), worker = state.workers[0];
    await Promise.all([manager.init(), manager.init()]);
    expect(worker.api.init).toHaveBeenCalledTimes(1);
    expect(worker.addEventListener).toHaveBeenCalledTimes(1);
    vi.spyOn(manager as any, 'createSession').mockResolvedValue('wss://verifier.test/session');
    worker.api.setupProver.mockRejectedValueOnce(new Error('setup rejected'));
    await expect(manager.createProver('provider.test', 'https://verifier.test')).rejects.toThrow('setup rejected');
    expect(worker.api.freeProver).toHaveBeenCalledTimes(1);
    expect(manager.releaseIdleWorker()).toBe(true);
  });
});
