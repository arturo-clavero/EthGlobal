// Load every built plugin bundle's configuration in the plugin SDK's QuickJS host, as the extension does, and fail
// on any QuickJS error (export bridge cycles). No provider requests or real account data are needed.
//   node fork/check-sandbox.mjs <plugin dir>     (default: $FORK_PLUGIN_DIR)
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Host } from '../packages/plugin-sdk/dist/index.js';

const dir = process.argv[2] || process.env.FORK_PLUGIN_DIR;
assert.ok(dir, 'usage: check-sandbox.mjs <plugin dir> (or set FORK_PLUGIN_DIR)');
const ids = (await readdir(dir)).filter(name => name.endsWith('.js')).map(name => name.slice(0, -3)).sort();
assert.ok(ids.length, `no plugin bundles (*.js) in ${dir}`);
const params = { proofId: '11111111-1111-4111-8111-111111111111', nonceMac: 'n'.repeat(43),
  windowDays: 7, cutoff: Date.parse('2026-01-01T00:00:00Z'), privateInput: { projectId: 'fixture-project' },
  membership: { org: 'fixture-org', login: 'fixture-user' } };
const errors = [], originalError = console.error;
console.error = (...args) => { errors.push(args); originalError(...args); };
try {
  const host = new Host({ onProve: () => { throw new Error('Unexpected proof during config extraction'); },
    onRenderPluginUi: () => {}, onCloseWindow: () => {}, onOpenWindow: () => {} });
  for (const id of ids) {
    const source = await readFile(join(dir, `${id}.js`), 'utf8');
    const code = source.replace(/(["'])__PLUGIN_PARAMS__\1/g, JSON.stringify(JSON.stringify(params)))
      .replace(/__(?:VERIFIER|PROXY)_URL_[A-Z_]+__/g, 'https://verifier.example.invalid/');
    const config = await host.getPluginConfig(code);
    assert.ok(config.name && config.requests.length);
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(errors.length, 0, `${id} emitted a QuickJS error`);
    console.log(`${id}: packaged configuration loaded without QuickJS errors`);
  }
} finally { console.error = originalError; }
