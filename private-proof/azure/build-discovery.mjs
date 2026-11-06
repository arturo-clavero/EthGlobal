import { resolve } from 'node:path';
import { createRequire } from 'node:module';

export async function buildAzureDiscovery({ webpack, directory, output, extensionDirectory }) {
  const require = createRequire(resolve(extensionDirectory, 'package.json'));
  const compiler = webpack({
    mode: 'production', target: 'web', context: directory, devtool: false,
    entry: resolve(directory, 'portal-bundle.mjs'),
    output: { path: output, filename: 'portal-discovery.bundle.js', clean: false },
    resolve: { extensions: ['.mjs', '.js', '.json'],
      alias: { 'webextension-polyfill': require.resolve('webextension-polyfill') } },
    plugins: [new webpack.NormalModuleReplacementPlugin(/^node:(?:util|net)$/, resource => {
      resource.request = resolve(directory, 'browser-discovery-platform.mjs');
    })],
    optimization: { minimize: false }, performance: { hints: false },
  });
  const stats = await new Promise((accept, reject) => compiler.run((error, stats) => error ? reject(error) : accept(stats)));
  await new Promise((accept, reject) => compiler.close(error => error ? reject(error) : accept()));
  if (stats.hasErrors()) throw new Error(stats.toString({ all: false, errors: true }));
  return stats;
}
