/* eslint-disable @typescript-eslint/no-explicit-any -- mocks of the offscreen-only host/worker boundary */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHash, webcrypto } from 'node:crypto';

const state = vi.hoisted(() => ({ snapshots: [] as Uint8Array[], openings: [] as any[],
  seen: [] as any[], fail: false, hosts: [] as any[], openWindow: false }));
const handler = (type: string) => ({ type, part: 'ALL', action: { kind: 'HASH', algorithm: 'SHA256' } });
const runData = { _autoApproved: '1', method: 'GCP_WORK', mode: 'Proxy',
  proofId: '11111111-1111-4111-8111-111111111111', pluginSha256: 'a'.repeat(64) };

vi.mock('@tlsn/plugin-sdk', () => ({ canonicalizeHandler: (h: unknown) => h,
  default: class {
    constructor(readonly opts: any) { state.hosts.push(opts); }
    getPluginConfig() { return {}; }
    addCapability() {}
    async executePlugin() {
      if (state.openWindow) await this.opts.onOpenWindow('https://accounts.google.com');
      for (let i = 0; i < 6; i++) {
        const host = i ? 'logging.clients6.google.com' : 'accounts.google.com';
        state.seen.push(await this.opts.onProve({ url: `https://${host}/`, method: 'POST', headers: {} }, {
          verifierUrl: 'https://verifier.test', proxyUrl: 'wss://proxy.test', handlers: [],
          maxSentData: 16384, maxRecvData: 16384,
          sessionData: { ...runData, nonceMac: 'b'.repeat(43), step: i ? `groups:${i - 1}` : 'identity' },
        }));
      }
      if (state.openWindow) await this.opts.onCloseWindow(7);
      return { secretDonePayload: 'must never reach the page' };
    }
  },
}));
vi.mock('../../src/offscreen/permissionValidator', () => ({ validateProvePermission: vi.fn(), validateOpenWindowPermission: vi.fn() }));
vi.mock('../../src/offscreen/ProveManager', () => ({ ProveManager: class {
  seq = 0;
  sent = new Uint8Array(); recv = new Uint8Array();
  init() { return Promise.resolve(); }
  createProver() { return Promise.resolve(String(this.seq++)); }
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
  sendRevealConfig() {}
  reveal() {
    const opening = (bytes: Uint8Array, n: number) => ({
      hash: Array.from(createHash('sha256').update(bytes).update(new Uint8Array(16).fill(n)).digest()),
      blinder: Array(16).fill(n),
    });
    const out = { sent: [opening(this.sent, 2)], recv: [opening(this.recv, 4)] };
    state.openings.push(out); return out;
  }
  getResponse() {
    if (state.fail) throw new Error('SECRET SERVER RESPONSE');
    const last = state.openings[state.openings.length - 1];
    return { results: [{ ...handler('SENT'), value: Buffer.from(last.sent[0].hash).toString('hex') },
      { ...handler('RECV'), value: Buffer.from(last.recv[0].hash).toString('hex') }] };
  }
  getSessionId(id: string) { return `22222222-2222-4222-8222-22222222222${id}`; }
  cleanupProver() {}
} }));

import { SessionManager } from '../../src/offscreen/SessionManager';

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  state.snapshots = []; state.openings = []; state.seen = []; state.fail = false; state.hosts = []; state.openWindow = false;
  vi.stubGlobal('chrome', { runtime: { id: 'test-extension', getURL: (path: string) => `chrome-extension://test-extension/${path}`,
    sendMessage: vi.fn().mockImplementation(async message => message.type === 'OPEN_WINDOW' ? { type: 'WINDOW_OPENED', payload: { windowId: 7 } } : undefined),
    onMessage: { addListener: vi.fn(), removeListener: vi.fn() } } });
});

describe('SessionManager private GCP capability', () => {
  it('a trusted close of this window cancels proving after SDK done; wrong senders/windows cannot', async () => {
    state.openWindow = true;
    const clear = vi.fn();
    await expect(new SessionManager().executePlugin('packaged code', runData.proofId,
      { ...runData, _approvalMode: 'all-session' }, {
        clear, identityEmail: () => 'candidate@example.test',
        prove: async (_witnesses, signal) => {
          expect(vi.mocked(chrome.runtime.sendMessage).mock.calls.some(([message]) => (message as any)?.type === 'CLOSE_WINDOW')).toBe(false);
          const listener = vi.mocked(chrome.runtime.onMessage.addListener).mock.calls[0][0] as (...args: unknown[]) => void;
          const sender = { id: 'test-extension', url: 'chrome-extension://test-extension/background.bundle.js' };
          for (const bad of [{ ...sender, id: 'other' }, { ...sender, tab: { id: 1 } },
            { ...sender, url: 'chrome-extension://test-extension/popup.html' }]) {
            listener({ type: 'WINDOW_CLOSED', windowId: 7 }, bad); expect(signal.aborted).toBe(false);
          }
          listener({ type: 'WINDOW_CLOSED', windowId: 8 }, sender); expect(signal.aborted).toBe(false);
          listener({ type: 'WINDOW_CLOSED', windowId: 7 }, sender); expect(signal.aborted).toBe(true);
          return new Promise(() => {});
        },
      })).rejects.toThrow('GCP_PRIVATE_PROOF_FAILED');
    expect(clear).toHaveBeenCalled();
    expect(chrome.runtime.onMessage.removeListener).toHaveBeenCalled();
    expect(chrome.runtime.sendMessage).toHaveBeenCalledWith({ type: 'CLOSE_WINDOW', windowId: 7 });
    expect(state.snapshots.every(bytes => bytes.every(byte => byte === 0))).toBe(true);
  });
  it('overrides plugin done() with a proof and zeroes original and retained witness buffers', async () => {
    let copies: Uint8Array[] = [];
    const result = await new SessionManager().executePlugin('packaged code', runData.proofId,
      { ...runData, _approvalMode: 'all-session' }, {
        identityEmail: () => 'candidate@example.test',
        prove: async witnesses => {
          copies = witnesses.flatMap(w => [w.sent, w.recv, ...w.openings.sent.map(o => o.blinder), ...w.openings.recv.map(o => o.blinder)]);
          expect(copies.every(b => b.some(n => n !== 0))).toBe(true);
          return { proofs: [{ circuitId: 'atom-v1', proof: 'AQID', publicInputs: ['1'] }] };
        },
      });
    expect(result).toMatchObject({ kind: 'GCP_PRIVATE_RESULT', proofs: [{ circuitId: 'atom-v1', proof: 'AQID', publicInputs: ['1'] }] });
    expect(JSON.stringify(result)).not.toMatch(/secretDonePayload|candidate@example/);
    expect(state.seen[0].privateAccountEmail).toBe('candidate@example.test');
    expect(state.seen.every(r => !('openings' in r) && !('sent' in r) && !('recv' in r))).toBe(true);
    expect([...copies, ...state.snapshots].every(b => b.every(n => n === 0))).toBe(true);
    expect(state.openings.every(o => [...o.sent, ...o.recv].every((v: any) => [...v.hash, ...v.blinder].every(n => n === 0)))).toBe(true);
  });

  it('sanitizes failures before the plugin/page and erases snapshots and openings', async () => {
    state.fail = true;
    const prove = vi.fn();
    await expect(new SessionManager().executePlugin('packaged code', runData.proofId,
      { ...runData, _approvalMode: 'all-session' }, { identityEmail: () => 'candidate@example.test', prove }))
      .rejects.toThrow('GCP_PRIVATE_PROOF_FAILED');
    expect(prove).not.toHaveBeenCalled();
    expect(state.snapshots.every(b => b.every(n => n === 0))).toBe(true);
    expect(state.openings.every(o => [...o.sent, ...o.recv].every((v: any) => v.blinder.every((n: number) => n === 0)))).toBe(true);
  });
});
