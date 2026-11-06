import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import browser from 'webextension-polyfill';
import { gcpPrivateProgress } from '../../src/offscreen/gcpPrivateProgress';

let receive: (message: unknown, sender: { id: string }) => unknown;
const sender = { id: 'test-extension-id' };
const render = (count = 0) => receive({ type: 'RENDER_PLUGIN_UI', windowId: 4,
  json: gcpPrivateProgress(count, 2, 1) }, sender);

beforeEach(async () => {
  vi.useFakeTimers();
  vi.resetModules();
  document.body.innerHTML = '';
  vi.spyOn(document.head, 'appendChild').mockImplementation(node => node);
  vi.mocked(browser.runtime.sendMessage).mockResolvedValue(undefined);
  await import('../../src/entries/Content/index');
  receive = vi.mocked(browser.runtime.onMessage.addListener).mock.calls.at(-1)![0] as typeof receive;
});
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); vi.restoreAllMocks(); document.body.innerHTML = ''; });

it('reports missing offscreen updates independently without claiming a proof result', () => {
  render(3);
  vi.advanceTimersByTime(29_000);
  expect(document.body.textContent).toContain('Creating your private proof');
  vi.advanceTimersByTime(1_000);
  expect(document.body.textContent).toContain('Verification stopped responding');
  expect(document.body.textContent).toContain('3 proof parts completed');
  expect(document.body.textContent).toContain('Last update received 30 seconds ago');
  expect(document.body.textContent).toContain('cannot confirm whether verification finished');
  expect(document.body.textContent).not.toContain('1s ago');
  expect(document.querySelector('[role="status"]')?.textContent).toContain('Return to the page that started this proof');
  vi.advanceTimersByTime(5_000);
  expect(document.body.textContent).toContain('35 seconds ago');
});

it('resets the watchdog on real progress and recovers after updates resume', () => {
  render();
  vi.advanceTimersByTime(25_000);
  render(1);
  vi.advanceTimersByTime(25_000);
  expect(document.body.textContent).not.toContain('stopped responding');
  vi.advanceTimersByTime(5_000);
  expect(document.body.textContent).toContain('stopped responding');
  render(2);
  expect(document.body.textContent).toContain('Creating your private proof');
  expect(document.body.textContent).toContain('2 proof parts completed');
  expect(vi.getTimerCount()).toBe(1);
});

it('does not alter another plugin UI and cleans up when the panel disappears', () => {
  render();
  receive({ type: 'RENDER_PLUGIN_UI', windowId: 4,
    json: { type: 'div', options: {}, children: ['Another plugin'] } }, sender);
  vi.advanceTimersByTime(40_000);
  expect(document.body.textContent).toBe('Another plugin');
  expect(vi.getTimerCount()).toBe(0);
  render();
  document.body.innerHTML = '';
  vi.advanceTimersByTime(1000);
  expect(vi.getTimerCount()).toBe(0);
});
