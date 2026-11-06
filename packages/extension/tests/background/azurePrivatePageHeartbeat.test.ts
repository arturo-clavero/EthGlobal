import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { startAzurePrivatePageHeartbeat } from '../../src/constants/azurePrivatePageHeartbeat';

const attempt = { proofId: '11111111-1111-4111-8111-111111111111', pluginSha256: 'a'.repeat(64), nonceMac: 'b'.repeat(43) };
beforeEach(() => vi.useFakeTimers());
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

describe('Azure pending-page heartbeat lifecycle', () => {
  it('polls only the captured tuple, stays active on success and clears its interval', async () => {
    const send = vi.fn(async () => ({ ok: true })), lost = vi.fn(), input = { ...attempt };
    const stop = startAzurePrivatePageHeartbeat(input, send, lost); input.nonceMac = 'changed';
    await vi.advanceTimersByTimeAsync(20_000);
    expect(send).toHaveBeenCalledExactlyOnceWith({ type: 'AZURE_PRIVATE_PAGE_HEARTBEAT', requestId: attempt.proofId,
      pluginSha256: attempt.pluginSha256, nonceMac: attempt.nonceMac });
    expect(lost).not.toHaveBeenCalled(); stop(); await vi.advanceTimersByTimeAsync(40_000);
    expect(send).toHaveBeenCalledTimes(1);
  });
  it.each(['denied', 'rejected', 'malformed', 'throwing'])('settles once for %s routes', async kind => {
    const lost = vi.fn(), send = vi.fn(() => {
      if (kind === 'throwing') throw new Error('CLOSED');
      return kind === 'rejected' ? Promise.reject(new Error('CLOSED')) : Promise.resolve(kind === 'denied' ? { ok: false } : null);
    });
    startAzurePrivatePageHeartbeat(attempt, send, lost);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(send).toHaveBeenCalledTimes(1); expect(lost).toHaveBeenCalledTimes(1);
  });
  it('bounds a never-settling message and ignores its late response', async () => {
    let release!: (value: unknown) => void;
    const lost = vi.fn(), send = vi.fn(() => new Promise(resolve => { release = resolve; }));
    startAzurePrivatePageHeartbeat(attempt, send, lost);
    await vi.advanceTimersByTimeAsync(24_999);
    expect(send).toHaveBeenCalledTimes(1); expect(lost).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1); expect(lost).toHaveBeenCalledTimes(1);
    release({ ok: true }); await vi.advanceTimersByTimeAsync(40_000);
    expect(send).toHaveBeenCalledTimes(1); expect(lost).toHaveBeenCalledTimes(1);
  });
  it('clears the response deadline on completion and cannot cancel a replacement', async () => {
    let release!: (value: unknown) => void;
    const lost = vi.fn(), send = vi.fn(() => new Promise(resolve => { release = resolve; }));
    const stop = startAzurePrivatePageHeartbeat(attempt, send, lost);
    await vi.advanceTimersByTimeAsync(20_000); expect(send).toHaveBeenCalledTimes(1); stop();
    const replacementLost = vi.fn(), replacementSend = vi.fn(async () => ({ ok: true }));
    const stopReplacement = startAzurePrivatePageHeartbeat({ ...attempt, proofId: '22222222-2222-4222-8222-222222222222' }, replacementSend, replacementLost);
    release({ ok: false }); await vi.advanceTimersByTimeAsync(20_000);
    expect(lost).not.toHaveBeenCalled(); expect(replacementLost).not.toHaveBeenCalled();
    expect(replacementSend).toHaveBeenCalledTimes(1); stopReplacement();
  });
});
