import { describe, expect, it, vi } from 'vitest';
import { Host, NativeFunctionEvaluator, preprocessPluginCode } from '../src/index';

const code = `function main(){return 'rendered'}function click(value){return value+1}
const $plugin={main,click,config:{name:'Bundled plugin',requests:[]}};export{$plugin as default};`;
const newHost = () => new Host({ onProve: vi.fn(), onRenderPluginUi: vi.fn(), onCloseWindow: vi.fn(), onOpenWindow: vi.fn() });

describe('bundled default exports', () => {
  it('extracts config and calls exported functions through real QuickJS without constructor cycles', async () => {
    const errors = vi.spyOn(console, 'error');
    const host = newHost();
    expect(await host.getPluginConfig(code)).toEqual({ name: 'Bundled plugin', requests: [] });
    await new Promise(resolve => setTimeout(resolve, 0));
    const sandbox = await host.createEvalCode();
    try {
      const { main, click } = await sandbox.eval(preprocessPluginCode(code)) as {
        main: () => string; click: (value: number) => number;
      };
      expect(main()).toBe('rendered');
      expect(click(41)).toBe(42);
    } finally {
      sandbox.dispose();
      await new Promise(resolve => setTimeout(resolve, 0));
      try { expect(errors).not.toHaveBeenCalled(); } finally { errors.mockRestore(); }
    }
  });

  it('preserves the shared native evaluator and rejects non-identifier alias expressions', async () => {
    const result = await new NativeFunctionEvaluator().evaluate(code, {});
    expect((result.exports.main as () => string)()).toBe('rendered');
    expect((result.exports.click as (value: number) => number)(2)).toBe(3);
    expect(result.exports.config).toEqual({ name: 'Bundled plugin', requests: [] });
    const invalid = 'export{steal() as default};';
    expect(preprocessPluginCode(invalid)).toBe(invalid);
  });
});
