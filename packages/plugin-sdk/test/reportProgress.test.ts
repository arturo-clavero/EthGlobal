/**
 * A host capability `reportProgress` reaches the
 * plugin as a global (like prove/done), and is simply undefined when the host
 * does not add it (every run except auto-approved plugins on the embedding pages).
 */
import { describe, it, expect, vi } from 'vitest';
import { Host } from '../src/index';
import type { WindowMessage } from '../src/types';

function emitter() {
  const listeners: Array<(m: WindowMessage) => void> = [];
  return {
    emit: (m: WindowMessage) => listeners.forEach((l) => l(m)),
    addListener: (l: (m: WindowMessage) => void) => listeners.push(l),
    removeListener: (l: (m: WindowMessage) => void) => {
      const i = listeners.indexOf(l);
      if (i >= 0) listeners.splice(i, 1);
    },
  };
}

const PLUGIN = `
export const config = { name: 'Progress probe' };
export function main() {
  if (typeof reportProgress === 'function') reportProgress({ method: 'EXAMPLE_WORK', status: 'running', index: 1, total: 0 });
  done(typeof reportProgress);
  return div({}, ['x']);
}
`.trim();

const newHost = () =>
  new Host({
    onProve: vi.fn(),
    onRenderPluginUi: vi.fn(),
    onCloseWindow: vi.fn(),
    onOpenWindow: vi.fn(),
  });

describe('reportProgress capability', () => {
  it('with the capability: the plugin sees a function and its report reaches the host', async () => {
    const host = newHost();
    const spy = vi.fn();
    host.addCapability('reportProgress', spy);
    const result = await host.executePlugin(PLUGIN, { eventEmitter: emitter() });
    expect(result).toBe('function');
    expect(spy).toHaveBeenCalledWith({
      method: 'EXAMPLE_WORK',
      status: 'running',
      index: 1,
      total: 0,
    });
  }, 15_000);

  it('without it (stock behaviour): typeof reportProgress is undefined and the plugin runs as before', async () => {
    const result = await newHost().executePlugin(PLUGIN, { eventEmitter: emitter() });
    expect(result).toBe('undefined');
  }, 15_000);
});
