// Run the upstream extension build (packages/extension/utils/build.js, unchanged) and record which files ended up
// in the bundles, for THIRD_PARTY_NOTICES.txt (third-party-notices.mts).
//   cd packages/extension && NODE_ENV=production node ../../fork/webpack-build.cjs <modules.json>
// webpack is wrapped, not configured: the build and its output stay exactly upstream's. Every module webpack placed in
// a chunk (concatenated modules expanded) is written as an absolute resource path; build-time-only code (loaders,
// plugins, the HTML templates' child compilers) never reaches a chunk of the main compilation and is not listed.
"use strict";
const fs = require("fs");
const path = require("path");
const Module = require("module");

const out = process.argv[2];
if (!out) throw new Error("usage: webpack-build.cjs <modules.json>");
const extDir = process.cwd();
const req = Module.createRequire(path.join(extDir, "package.json"));
const webpackPath = req.resolve("webpack");
const webpack = req("webpack");

function resourcesOf(compilation) {
  const files = new Set();
  const add = (m) => {
    if (m.modules) for (const inner of m.modules) add(inner); // ConcatenatedModule
    if (m.rootModule) add(m.rootModule);
    const r = m.resource || (m.resourceResolveData && m.resourceResolveData.path);
    if (r) files.add(r.split("?")[0]);
  };
  for (const chunk of compilation.chunks) {
    for (const m of compilation.chunkGraph.getChunkModulesIterable(chunk)) add(m);
  }
  return files;
}

const wrapped = new Proxy(webpack, {
  apply(target, thisArg, [config, callback]) {
    return target.call(thisArg, config, (err, stats) => {
      if (!err && stats && !stats.hasErrors()) {
        const comps = stats.stats ? stats.stats.map((s) => s.compilation) : [stats.compilation];
        const files = new Set();
        for (const c of comps) for (const f of resourcesOf(c)) files.add(f);
        fs.writeFileSync(out, JSON.stringify([...files].sort(), null, 1) + "\n");
        console.log(`bundled modules recorded: ${files.size} files → ${out}`);
      }
      callback(err, stats);
    });
  },
});
require.cache[webpackPath].exports = wrapped;
req("./utils/build.js");
