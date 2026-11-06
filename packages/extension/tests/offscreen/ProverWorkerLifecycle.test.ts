import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

interface Channel {
  read(): Promise<Uint8Array | null>;
  write(bytes: Uint8Array): Promise<void>;
  close(): Promise<void>;
}
interface MockProver {
  active: number;
  verifier: Channel;
  free: ReturnType<typeof vi.fn>;
}
const mocks = vi.hoisted(() => ({
  api: undefined as any,
  instances: [] as MockProver[],
  events: [] as string[],
  setup: undefined as undefined | ((prover: MockProver) => Promise<void>),
  send: undefined as undefined | ((prover: MockProver, io?: Channel) => Promise<void>),
  reveal: undefined as undefined | ((prover: MockProver) => Promise<void>),
}));
vi.mock('comlink', () => ({
  expose: (api: unknown) => {
    mocks.api = api;
  },
}));
vi.mock('tlsn-wasm', () => ({
  default: vi.fn(),
  initialize: vi.fn(),
  compute_reveal: vi.fn(),
  Prover: class {
    active = 0;
    verifier!: Channel;
    constructor() {
      mocks.instances.push(this);
    }
    set_progress_callback() {}
    async borrow(operation: () => Promise<void> | undefined) {
      this.active++;
      try {
        return await operation();
      } finally {
        this.active--;
        mocks.events.push('settled');
      }
    }
    setup(io: Channel) {
      this.verifier = io;
      return this.borrow(() => mocks.setup?.(this));
    }
    send_request(io?: Channel) {
      return this.borrow(() => mocks.send?.(this, io));
    }
    reveal() {
      return this.borrow(() => mocks.reveal?.(this));
    }
    free = vi.fn(() => {
      if (this.active) throw new Error('free while WASM is borrowed');
      mocks.events.push('free');
    });
  },
}));

// The worker installs progress interceptors at import time; do not keep them in
// the test process, where other suites share the console.
const originalConsole = { log: console.log, debug: console.debug, info: console.info };
await import('../../src/offscreen/ProveManager/worker');
Object.assign(console, originalConsole);
const api = mocks.api as {
  createProver(config: unknown): Promise<string>;
  setupProver(id: string, url: string): Promise<void>;
  setupProverRelay(id: string, send: (bytes: Uint8Array) => void): Promise<void>;
  sendRequest(id: string, url: string | undefined, request: unknown): Promise<void>;
  reveal(id: string, reveal: unknown): Promise<unknown>;
  freeProver(id: string): Promise<void>;
  deliverToWasm(bytes: Uint8Array): void;
};

class Socket {
  static instances: Socket[] = [];
  binaryType = '';
  onopen?: () => void;
  onclose?: () => void;
  onerror?: (event: unknown) => void;
  onmessage?: (event: { data: ArrayBuffer }) => void;
  send = vi.fn();
  // Deliberately do not emit onclose: local cancellation must wake reads itself.
  close = vi.fn();
  constructor(_url: string) {
    Socket.instances.push(this);
  }
  open() {
    this.onopen?.();
  }
  message(bytes: Uint8Array) {
    this.onmessage?.({ data: bytes.buffer as ArrayBuffer });
  }
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}
const flush = () => vi.advanceTimersByTimeAsync(0);
// alpha.15 JsIoAdapter::poll_write discards the returned Promise; only a
// synchronous throw reaches wasm-bindgen's catch import and Rust's Err branch.
function wasmPollWrite(channel: Channel, bytes: Uint8Array): number {
  channel.write(bytes);
  return bytes.length;
}
let ids: string[];
async function create() {
  const id = await api.createProver({});
  ids.push(id);
  return id;
}
async function setup(id: string) {
  const pending = api.setupProver(id, 'ws://verifier.invalid/verifier');
  await flush();
  Socket.instances.at(-1)!.open();
  await pending;
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal('WebSocket', Socket);
  Socket.instances = [];
  mocks.instances = [];
  mocks.events = [];
  mocks.setup = mocks.send = mocks.reveal = undefined;
  ids = [];
});
afterEach(async () => {
  for (const id of ids) await api.freeProver(id).catch(() => undefined);
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('prover worker operation lifetime', () => {
  it('clears successful timers, keeps verifier IO until cleanup, and frees only once', async () => {
    const id = await create();
    await setup(id);
    await api.sendRequest(id, undefined, {});
    await api.reveal(id, {});
    expect(vi.getTimerCount()).toBe(0);
    expect(Socket.instances[0].close).not.toHaveBeenCalled();
    await Promise.all([api.freeProver(id), api.freeProver(id)]);
    await api.freeProver(id);
    expect(Socket.instances[0].close).toHaveBeenCalledTimes(1);
    expect(mocks.instances[0].free).toHaveBeenCalledTimes(1);
    expect(mocks.events.at(-1)).toBe('free');
  });

  it.each([
    { mode: 'Proxy', url: undefined, timeout: 20_000 },
    { mode: 'MPC', url: 'ws://server.invalid/', timeout: 60_000 },
  ])('$mode timeout closes IO and awaits rejection before free', async ({ url, timeout }) => {
    const debug = vi.spyOn(console, 'debug').mockImplementation(() => {});
    const id = await create();
    await setup(id);
    const release = deferred();
    let sawEof = false;
    mocks.send = async (prover, server) => {
      expect(await (server ?? prover.verifier).read()).toBeNull();
      sawEof = true;
      await release.promise;
      throw new Error('transport ended');
    };
    const send = api.sendRequest(id, url, {});
    const outcome = expect(send).rejects.toThrow(`sendRequest timed out after ${timeout}ms`);
    await flush();
    if (url) {
      Socket.instances.at(-1)!.open();
      await flush();
    }
    await vi.advanceTimersByTimeAsync(timeout - 1);
    expect(Socket.instances.every((socket) => socket.close.mock.calls.length === 0)).toBe(true);
    expect(debug).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(sawEof).toBe(true);
    expect(Socket.instances.every((socket) => socket.close.mock.calls.length === 1)).toBe(true);
    expect(debug.mock.calls.map(([code]) => code)).toEqual([
      'TLSN_OPERATION_TIMEOUT_FIRED',
      'TLSN_TIMEOUT_IO_CLOSE_STARTED',
      'TLSN_TIMEOUT_IO_CLOSE_SETTLED',
    ]);
    const cleanup = api.freeProver(id);
    await flush();
    expect(mocks.instances[0].active).toBe(1);
    expect(mocks.instances[0].free).not.toHaveBeenCalled();
    release.resolve();
    await outcome;
    await cleanup;
    expect(mocks.instances[0].free).toHaveBeenCalledTimes(1);
    expect(mocks.events.slice(-2)).toEqual(['settled', 'free']);
    expect(vi.getTimerCount()).toBe(0);
    expect(debug.mock.calls.at(-1)?.[0]).toBe('TLSN_TIMEOUT_WASM_SETTLED');
    for (const args of debug.mock.calls) {
      expect(args).toHaveLength(2);
      expect(Number.isSafeInteger(args[1])).toBe(true);
      expect(args[1]).toBeGreaterThanOrEqual(0);
    }
  });

  it('does not classify an original error as timeout or emit a late timeout during cleanup', async () => {
    const debug = vi.spyOn(console, 'debug').mockImplementation(() => {});
    const id = await create();
    await setup(id);
    // Matching text must not substitute for the timeout error's identity.
    const original = new Error(`sendRequest timed out after 20000ms for ${id}`);
    mocks.send = async () => {
      throw original;
    };
    const release = deferred();
    const channel = mocks.instances[0].verifier;
    const close = channel.close.bind(channel);
    channel.close = async () => {
      await close();
      await release.promise;
    };
    const send = api.sendRequest(id, undefined, {});
    const outcome = expect(send).rejects.toBe(original);
    await flush();
    expect(Socket.instances[0].close).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(debug).not.toHaveBeenCalled();
    release.resolve();
    await outcome;
    await api.freeProver(id);
    expect(mocks.instances[0].free).toHaveBeenCalledTimes(1);
    expect(debug).not.toHaveBeenCalled();
  });

  it('cancels a CONNECTING socket and closes a late open without calling WASM setup', async () => {
    const id = await create();
    const pending = api.setupProver(id, 'ws://verifier.invalid/verifier');
    const outcome = expect(pending).rejects.toThrow('closed before opening');
    await flush();
    await api.freeProver(id);
    await outcome;
    expect(mocks.instances[0].verifier).toBeUndefined();
    expect(Socket.instances[0].close).toHaveBeenCalledTimes(1);
    Socket.instances[0].open();
    expect(Socket.instances[0].close).toHaveBeenCalledTimes(2);
    expect(mocks.instances[0].free).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('times out connection setup without leaving an opening socket', async () => {
    const id = await create();
    const pending = api.setupProver(id, 'ws://verifier.invalid/verifier');
    const outcome = expect(pending).rejects.toThrow('setupProver timed out after 30000ms');
    await vi.advanceTimersByTimeAsync(30_000);
    await outcome;
    expect(Socket.instances[0].close).toHaveBeenCalledTimes(1);
    expect(mocks.instances[0].active).toBe(0);
  });

  it('preserves the original setup failure if closing the socket also throws', async () => {
    const id = await create();
    const original = new Error('setup rejected');
    mocks.setup = async () => {
      throw original;
    };
    const pending = api.setupProver(id, 'ws://verifier.invalid/verifier');
    const outcome = expect(pending).rejects.toBe(original);
    await flush();
    Socket.instances[0].close.mockImplementationOnce(() => {
      throw new Error('close failed');
    });
    Socket.instances[0].open();
    await outcome;
    await api.freeProver(id);
    expect(mocks.events.slice(-2)).toEqual(['settled', 'free']);
  });

  it('cancels reveal by waking verifier IO and rejects a late successful completion', async () => {
    const id = await create();
    await setup(id);
    const release = deferred();
    mocks.reveal = async (prover) => {
      expect(await prover.verifier.read()).toBeNull();
      await release.promise;
    };
    const reveal = api.reveal(id, {});
    const outcome = expect(reveal).rejects.toThrow('Prover cancelled');
    await flush();
    const cleanup = api.freeProver(id);
    await flush();
    expect(mocks.instances[0].free).not.toHaveBeenCalled();
    release.resolve();
    await outcome;
    await cleanup;
    expect(mocks.events.slice(-2)).toEqual(['settled', 'free']);
  });

  it('retains queued frames on remote EOF, but wipes queued and late bytes on cancellation', async () => {
    const id = await create();
    await setup(id);
    const socket = Socket.instances[0];
    const first = new Uint8Array([1, 2]);
    socket.message(first);
    socket.onclose?.();
    expect(await mocks.instances[0].verifier.read()).toEqual(first);
    expect(await mocks.instances[0].verifier.read()).toBeNull();
    const secondId = await create();
    await setup(secondId);
    const second = new Uint8Array([3, 4]);
    Socket.instances[1].message(second);
    await api.freeProver(secondId);
    expect(second).toEqual(new Uint8Array(2));
    const late = new Uint8Array([5, 6]);
    Socket.instances[1].message(late);
    expect(late).toEqual(new Uint8Array(2));
  });

  it('wakes relay reads on cancellation and discards late inbound bytes', async () => {
    const id = await create();
    const sendOut = vi.fn();
    await api.setupProverRelay(id, sendOut);
    mocks.send = async (prover) => {
      expect(await prover.verifier.read()).toBeNull();
      throw new Error('relay ended');
    };
    const pending = api.sendRequest(id, undefined, {});
    const outcome = expect(pending).rejects.toThrow('relay ended');
    await flush();
    await api.freeProver(id);
    await outcome;
    expect(mocks.events.slice(-2)).toEqual(['settled', 'free']);
    const late = new Uint8Array([1]);
    api.deliverToWasm(late);
    expect(late[0]).toBe(0);
    expect(() => wasmPollWrite(mocks.instances[0].verifier, new Uint8Array([2]))).toThrow(
      'Relay is closed',
    );
    expect(sendOut).not.toHaveBeenCalled();
  });

  it('old relay rejection and repeated cleanup cannot read, close, or erase its replacement', async () => {
    const oldId = await create();
    await api.setupProverRelay(oldId, vi.fn());
    const release = deferred();
    mocks.send = async (prover) => {
      expect(await prover.verifier.read()).toBeNull();
      await release.promise;
      // An old future may poll once more while unwinding after EOF.
      expect(await prover.verifier.read()).toBeNull();
      throw new Error('old relay ended');
    };
    const oldSend = api.sendRequest(oldId, undefined, {});
    const outcome = expect(oldSend).rejects.toThrow('old relay ended');
    await flush();
    const oldCleanup = api.freeProver(oldId);
    await flush();
    const nextId = await create();
    const nextSend = vi.fn();
    await api.setupProverRelay(nextId, nextSend);
    const bytes = new Uint8Array([7, 8]);
    api.deliverToWasm(bytes);
    release.resolve();
    await outcome;
    await oldCleanup;
    await api.freeProver(oldId);
    expect(bytes).toEqual(new Uint8Array([7, 8]));
    expect(await mocks.instances[1].verifier.read()).toEqual(bytes);
    await mocks.instances[1].verifier.write(bytes);
    expect(nextSend).toHaveBeenCalledWith(bytes);
    expect(mocks.instances[1].free).not.toHaveBeenCalled();
  });

  it('propagates closed writes and WebSocket send failures through the synchronous WASM catch ABI', async () => {
    const id = await create();
    await setup(id);
    const channel = mocks.instances[0].verifier;
    const bytes = new Uint8Array([1]);
    expect(wasmPollWrite(channel, bytes)).toBe(1);
    expect(Socket.instances[0].send).toHaveBeenCalledWith(bytes);
    const failure = new Error('send failed');
    Socket.instances[0].send.mockImplementationOnce(() => {
      throw failure;
    });
    expect(() => wasmPollWrite(channel, bytes)).toThrow(failure);
    const closed = channel.close();
    expect(closed).toBeInstanceOf(Promise);
    await closed;
    expect(() => wasmPollWrite(channel, bytes)).toThrow('WebSocket is closed');
  });

  it('settles a timed-out setup when WASM tries to write after receiving EOF', async () => {
    const id = await create();
    mocks.setup = async (prover) => {
      expect(await prover.verifier.read()).toBeNull();
      wasmPollWrite(prover.verifier, new Uint8Array([1]));
    };
    const pending = api.setupProver(id, 'ws://verifier.invalid/verifier');
    const outcome = expect(pending).rejects.toThrow('setupProver timed out after 30000ms');
    await flush();
    Socket.instances[0].open();
    await flush();
    await vi.advanceTimersByTimeAsync(30_000);
    await outcome;
    await api.freeProver(id);
    expect(mocks.events.slice(-2)).toEqual(['settled', 'free']);
    expect(mocks.instances[0].free).toHaveBeenCalledTimes(1);
  });

  it('throws close failure synchronously after waking pending reads', async () => {
    const id = await create();
    await setup(id);
    const channel = mocks.instances[0].verifier;
    const pendingRead = channel.read();
    const failure = new Error('close failed');
    Socket.instances[0].close.mockImplementationOnce(() => {
      throw failure;
    });
    expect(() => channel.close()).toThrow(failure);
    expect(await pendingRead).toBeNull();
    expect(() => wasmPollWrite(channel, new Uint8Array([1]))).toThrow('WebSocket is closed');
  });

  it('closes every transport despite a synchronous close failure and preserves the operation error', async () => {
    const id = await create();
    await setup(id);
    const original = new Error('request failed');
    mocks.send = async () => {
      throw original;
    };
    const pending = api.sendRequest(id, 'ws://server.invalid/', {});
    const outcome = expect(pending).rejects.toBe(original);
    await flush();
    Socket.instances[0].close.mockImplementationOnce(() => {
      throw new Error('close failed');
    });
    Socket.instances[1].open();
    await outcome;
    expect(Socket.instances[0].close).toHaveBeenCalledTimes(1);
    expect(Socket.instances[1].close).toHaveBeenCalledTimes(1);
    await api.freeProver(id);
    expect(mocks.events.slice(-2)).toEqual(['settled', 'free']);
  });

  it('preserves connection errors when event-driven close fails and contains late-open close errors', async () => {
    const id = await create();
    const pending = api.setupProver(id, 'ws://verifier.invalid/verifier');
    const outcome = expect(pending).rejects.toThrow('WebSocket connection failed:');
    await flush();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const socket = Socket.instances[0];
    socket.close.mockImplementation(() => {
      throw new Error('close failed');
    });
    expect(() => socket.onerror?.({})).not.toThrow();
    await outcome;
    await flush();
    expect(() => socket.open()).not.toThrow();
    log.mockRestore();
    expect(mocks.instances[0].active).toBe(0);
  });

  it('propagates relay callback errors synchronously through the same ABI', async () => {
    const id = await create();
    const failure = new Error('relay send failed');
    await api.setupProverRelay(id, () => {
      throw failure;
    });
    const channel = mocks.instances[0].verifier;
    expect(() => wasmPollWrite(channel, new Uint8Array([1]))).toThrow(failure);
    expect(channel.close()).toBeInstanceOf(Promise);
    expect(() => wasmPollWrite(channel, new Uint8Array([1]))).toThrow('Relay is closed');
  });
});
