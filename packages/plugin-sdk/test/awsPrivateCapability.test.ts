import { expect, it, vi } from 'vitest';
import { Host } from '../src/index';

const code = `export const config = { name: 'Private capability probe' };
export function main() {
  if (typeof collectAwsPrivate === 'function') collectAwsPrivate('synthetic').then(value => done(value));
  else done('unavailable');
  return div({}, ['probe']);
}`;
it('awaits the compiled AWS capability through real QuickJS and leaves it absent on other hosts', async () => {
  for (const enabled of [false, true]) {
    const host = new Host({ onProve: vi.fn(), onRenderPluginUi: vi.fn(), onCloseWindow: vi.fn(), onOpenWindow: vi.fn() });
    const collect = vi.fn(async id => { expect(id).toBe('synthetic'); return 'local-only'; });
    if (enabled) host.addCapability('collectAwsPrivate', collect);
    const result = await host.executePlugin(code, { eventEmitter: { emit() {}, addListener() {}, removeListener() {} } });
    expect(result).toBe(enabled ? 'local-only' : 'unavailable');
    expect(collect).toHaveBeenCalledTimes(enabled ? 1 : 0);
  }
}, 15000);
