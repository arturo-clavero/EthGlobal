import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { waitForOffscreenReady } from '../../src/background/offscreenReady';

const ready = { success: true, data: 'Processed in offscreen' };

describe('cold offscreen readiness', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('accepts the installed listener immediately and clears the deadline', async () => {
    const probe = vi.fn().mockResolvedValue(ready);
    await waitForOffscreenReady(probe);
    expect(probe).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('waits through missing and malformed replies before executing the command once', async () => {
    const probe = vi.fn().mockRejectedValueOnce(new Error('No receiver'))
      .mockResolvedValueOnce(undefined).mockResolvedValueOnce({ success: true })
      .mockResolvedValueOnce({ ...ready, unexpected: true }).mockResolvedValue(ready);
    const command = vi.fn().mockRejectedValue(new Error('COMMAND_FAILED'));
    const run = waitForOffscreenReady(probe).then(command);
    const result = expect(run).rejects.toThrow('COMMAND_FAILED');
    await vi.advanceTimersByTimeAsync(399);
    expect(command).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await result;
    expect(probe).toHaveBeenCalledTimes(5);
    expect(command).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('stops polling at the five-second deadline and never sends the command', async () => {
    const probe = vi.fn().mockResolvedValue({ success: false });
    const command = vi.fn();
    const result = expect(waitForOffscreenReady(probe).then(command)).rejects.toThrow('OFFSCREEN_NOT_READY');
    await vi.advanceTimersByTimeAsync(5_000);
    await result;
    const calls = probe.mock.calls.length;
    expect(calls).toBe(50);
    expect(command).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(probe).toHaveBeenCalledTimes(calls);
  });

  it.each([ready, undefined])('bounds a hung probe and ignores its late reply: %j', async response => {
    let reply!: (value: unknown) => void;
    const probe = vi.fn(() => new Promise(resolve => { reply = resolve; }));
    const command = vi.fn();
    const result = expect(waitForOffscreenReady(probe).then(command)).rejects.toThrow('OFFSCREEN_NOT_READY');
    await vi.advanceTimersByTimeAsync(5_000);
    await result;
    reply(response);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(probe).toHaveBeenCalledTimes(1);
    expect(command).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
