import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { cp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';

// Reuse the extension's pinned Webpack toolchain; no second bundler dependency.
assert.ok(process.argv[2], 'Pass the patched upstream extension package directory.');
const require = createRequire(resolve(process.argv[2], 'package.json'));
const webpack = require('webpack');
const provider = process.argv[3] ?? 'gcp';
assert.ok(['gcp', 'aws'].includes(provider), 'Unknown private proof package.');
const directory = fileURLToPath(new URL(provider === 'aws' ? '../aws/' : '.', import.meta.url));
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
// Match the extension's notices collector, including concatenated modules and worker chunks.
const files = new Set();
if (provider === 'aws') {
  const client = await require('esbuild').build({
    entryPoints: [resolve(directory, 'browser-client.mjs')], bundle: true, format: 'esm', platform: 'browser',
    outfile: resolve(process.argv[2], 'src/aws-private/browser-client.mjs'), metafile: true,
  });
  for (const file of Object.keys(client.metafile.inputs)) files.add(resolve(file));
}
const record = module => {
  if (module.modules) for (const inner of module.modules) record(inner);
  if (module.rootModule) record(module.rootModule);
  const path = module.resource || module.resourceResolveData?.path;
  if (path) files.add(path.split('?')[0]);
};
for (const chunk of stats.compilation.chunks)
  for (const module of stats.compilation.chunkGraph.getChunkModulesIterable(chunk)) record(module);
await writeFile(resolve(directory, 'dist/browser-modules.json'), JSON.stringify([...files].sort()) + '\n');
const manifest = JSON.parse(await readFile(resolve(directory, 'generated', provider === 'aws' ? 'pins.json' : 'artifacts.json'), 'utf8'));
await mkdir(resolve(output, 'artifacts'), { recursive: true });
for (const pin of Object.values(manifest.circuits)) {
  await cp(resolve(directory, 'dist/artifacts', pin.file), resolve(output, 'artifacts', pin.file), { recursive: true });
  if (provider === 'aws') await cp(resolve(directory, 'dist/artifacts', pin.keyFile), resolve(output, 'artifacts', pin.keyFile));
}
for (const file of await readdir(output)) {
  if (!file.endsWith('.js')) continue;
  const source = await readFile(resolve(output, file), 'utf8');
  assert.ok(!source.includes(directory) && !source.includes('file:///'), 'Browser build contains an absolute source path.');
}
console.log('Built packaged private proof worker and pinned artifacts.');
