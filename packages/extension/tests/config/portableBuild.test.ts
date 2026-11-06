/**
 * The bundles must not contain the build machine's
 * paths. webpack inlines a bare `import.meta.url` as `file:///<abs path>`;
 * QuickJS's emscripten module has one, rewritten by forkScriptNameLoader.
 */
import { describe, it, expect } from 'vitest';
import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { join } from 'path';

const require = createRequire(import.meta.url);
const root = join(__dirname, '..', '..');
const loader = require(join(root, 'utils', 'forkScriptNameLoader.js'));
const run = (source: string) => loader.call({ resourcePath: 'emscripten-module.browser.mjs' }, source);
// The installed module (hoisted to the repository root; the package's `exports` hide its dist path from resolve).
const emscripten = readFileSync(
  join(root, '..', '..', 'node_modules', '@jitl', 'quickjs-ng-wasmfile-release-sync', 'dist', 'emscripten-module.browser.mjs'),
  'utf8',
);

describe('portable build', () => {
  it('the QuickJS module loses its bare import.meta.url; asset URLs stay', () => {
    const out = run(emscripten);
    expect(out).toContain('var _scriptName = self.location.href;');
    expect(out).not.toMatch(/=\s*import\.meta\.url\s*;/);
    expect(out).toContain('new URL("emscripten-module.wasm",import.meta.url)');
    expect(out.length - emscripten.length).toBe('self.location.href'.length - 'import.meta.url'.length);
  });

  it('fails the build when the line is not there exactly once', () => {
    expect(() => run('var x = 1;')).toThrow(/expected exactly one/);
    expect(() => run('var _scriptName = import.meta.url;var _scriptName = import.meta.url;')).toThrow();
  });

  it('webpack applies the loader to that file only', () => {
    const config = require(join(root, 'webpack.config.js'));
    const rules = config.module.rules.filter(
      (r: { use?: unknown }) => typeof r.use === 'string' && r.use.endsWith('forkScriptNameLoader.js'),
    );
    expect(rules).toHaveLength(1);
    const file = '/x/node_modules/@jitl/quickjs-ng-wasmfile-release-sync/dist/emscripten-module.browser.mjs';
    expect(rules[0].test.test(file) && rules[0].include.test(file)).toBe(true);
    expect(rules[0].include.test('/x/node_modules/other/dist/emscripten-module.browser.mjs')).toBe(false);
  });

  it('no global DefinePlugin of import.meta.url (it would break new Worker(new URL(...)))', () => {
    const config = require(join(root, 'webpack.config.js'));
    for (const p of config.plugins.filter(Boolean)) {
      if (p.constructor.name === 'DefinePlugin') expect(p.definitions['import.meta.url']).toBeUndefined();
    }
  });
});
