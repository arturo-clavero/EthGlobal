/**
 * A host capability `navigate` reaches the plugin as a
 * global (as reportProgress), and is undefined when the host does not add it
 * (every run except auto-approved plugins on the embedding pages).
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
export const config = { name: 'Navigate probe' };
export function main() {
  if (typeof navigate === 'function') navigate('https://accounts.example.test/switch');
  done(typeof navigate);
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

describe('navigate capability', () => {
  it('with the capability: the plugin sees a function and its report reaches the host', async () => {
    const host = newHost();
    const spy = vi.fn();
    host.addCapability('navigate', spy);
    const result = await host.executePlugin(PLUGIN, { eventEmitter: emitter() });
    expect(result).toBe('function');
    expect(spy).toHaveBeenCalledWith('https://accounts.example.test/switch');
  }, 15_000);

  it('without it (stock behaviour): typeof navigate is undefined and the plugin runs as before', async () => {
    const result = await newHost().executePlugin(PLUGIN, { eventEmitter: emitter() });
    expect(result).toBe('undefined');
  }, 15_000);
});
