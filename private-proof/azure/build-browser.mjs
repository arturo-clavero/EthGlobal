import { buildAzureDiscovery } from './build-discovery.mjs';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { cp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';

// Reuse the extension's pinned Webpack toolchain; no second bundler dependency.
assert.ok(process.argv[2], 'Pass the patched upstream extension package directory.');
const require = createRequire(resolve(process.argv[2], 'package.json'));
const webpack = require('webpack');
const directory = fileURLToPath(new URL('.', import.meta.url));
const output = resolve(directory, 'dist/browser');
const compiler = webpack({
  mode: 'production', target: 'webworker', devtool: false,
  entry: { 'browser-worker': resolve(directory, 'browser-worker.mjs') },
  output: { path: output, filename: '[name].js', chunkFilename: '[contenthash].js',
    assetModuleFilename: '[contenthash][ext]', module: true, clean: true, publicPath: 'auto' },
  experiments: { outputModule: true, asyncWebAssembly: true },
  resolve: { extensions: ['.mjs', '.js', '.json'], conditionNames: ['browser', 'import', 'default'],
    mainFields: ['browser', 'module', 'main'] },
  module: { rules: [{ test: /\.wasm$/, type: 'asset/resource' }] },
  // Serial and unminified: avoiding parallel terser processes keeps this memory bounded.
  optimization: { minimize: false },
  performance: { hints: false },
});
const stats = await new Promise((accept, reject) => compiler.run((error, stats) => error ? reject(error) : accept(stats)));
await new Promise((accept, reject) => compiler.close(error => error ? reject(error) : accept()));
if (stats.hasErrors()) throw new Error(stats.toString({ all: false, errors: true }));
const discoveryStats = await buildAzureDiscovery({ webpack, directory, output, extensionDirectory: resolve(process.argv[2]) });
// Match the extension's notices collector, including concatenated modules and worker chunks.
const files = new Set();
const record = module => {
  if (module.modules) for (const inner of module.modules) record(inner);
  if (module.rootModule) record(module.rootModule);
  const path = module.resource || module.resourceResolveData?.path;
  if (path) files.add(path.split('?')[0]);
};
for (const compilation of [stats.compilation, discoveryStats.compilation])
  for (const chunk of compilation.chunks)
    for (const module of compilation.chunkGraph.getChunkModulesIterable(chunk)) record(module);
await writeFile(resolve(directory, 'dist/browser-modules.json'), JSON.stringify([...files].sort()) + '\n');
const manifest = JSON.parse(await readFile(new URL('./generated/artifacts.json', import.meta.url), 'utf8'));
await mkdir(resolve(output, 'artifacts'), { recursive: true });
for (const pin of Object.values(manifest.circuits)) {
  for (const file of [pin.artifactFile, pin.keyFile]) await cp(resolve(directory, 'dist', file), resolve(output, 'artifacts', file));
}
for (const file of await readdir(output)) {
  if (!file.endsWith('.js')) continue;
  const source = await readFile(resolve(output, file), 'utf8');
  assert.ok(!source.includes(directory) && !source.includes('file:///'), 'Browser build contains an absolute source path.');
}
console.log('Built packaged private proof worker and pinned artifacts.');

const clientRoot = resolve(process.argv[2], 'src/azure-private');
await mkdir(clientRoot, { recursive: true });
for (const name of ['browser-client', 'browser-result', 'browser-plan', 'source-receipt', 'identity-receipt',
  'tenant-structure', 'activity-structure', 'activity-bindings', 'claims-bindings', 'claims-plan',
  'discovery-background', 'discovery-selection']) {
  const source = await readFile(resolve(directory, `${name}.mjs`), 'utf8');
  await writeFile(resolve(clientRoot, `${name}.mjs`), source.replaceAll('../gcp/', '../gcp-private/'));
}

for (const name of ['discovery-background', 'discovery-selection']) {
  await cp(resolve(directory, `${name}.d.mts`), resolve(clientRoot, `${name}.d.mts`));
}
