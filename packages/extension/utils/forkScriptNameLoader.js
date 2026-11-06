// QuickJS's emscripten module sets `_scriptName` from a
// bare `import.meta.url`, which webpack inlines as the build machine's
// file://<absolute path>. Use the page's own URL at run time instead (what the
// module itself uses in a worker), so the bundles hold no build path and two
// checkouts build the same bytes. Scoped to this one file: a global
// DefinePlugin of import.meta.url would also turn `new Worker(new URL(...,
// import.meta.url))` into a plain asset. Fails the build if the line moved.
const NEEDLE = 'var _scriptName = import.meta.url;';

module.exports = function forkScriptNameLoader(source) {
  if (source.split(NEEDLE).length !== 2) {
    throw new Error(`${this.resourcePath}: expected exactly one "${NEEDLE}" (QuickJS emscripten module changed)`);
  }
  return source.replace(NEEDLE, 'var _scriptName = self.location.href;');
};
