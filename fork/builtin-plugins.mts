// The extension's built-in plugins: the only plugin code it runs; a page names one by id + sha256, never sends code.
//   node builtin-plugins.mts <repo>/packages/extension/src/constants/builtinPlugins.ts <stage dir> <plugin dir>
// <plugin dir>: the built plugin bundles (FORK_PLUGIN_DIR); every <id>.js there is packaged.
// Copies each bundle byte for byte to <stage dir>/<builtInPluginPath()> (build.sh puts it into the extension) and
// prints the index [{id, sha256, layout}] that webpack bakes in as __FORK_PLUGIN_ALLOWLIST__. The layout and the file
// name come from the extension's own module, so build and runtime share one parser. Fails on a bundle fetch() would
// not hand over byte for byte (BOM, invalid UTF-8) or whose placeholders are not whole string literals.
import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [modulePath, stageDir, pluginDir] = process.argv.slice(2);
if (!modulePath || !stageDir || !pluginDir) {
  throw new Error("usage: builtin-plugins.mts <builtinPlugins.ts> <stage dir> <plugin dir>");
}
const { pluginLayout, parseBuiltInPlugins, builtInPluginPath } = await import(pathToFileURL(resolve(modulePath)).href);

async function bundles(dir) {
  const out = [];
  for (const name of (await readdir(dir)).filter((n) => n.endsWith(".js")).sort()) {
    const bytes = await readFile(join(dir, name));
    const text = bytes.toString("utf8");
    // fetch().text() strips a BOM and replaces invalid UTF-8; either would change what the extension hashes.
    if (text.charCodeAt(0) === 0xfeff || !Buffer.from(text, "utf8").equals(bytes)) {
      throw new Error(`${dir}/${name}: not plain UTF-8 without BOM`);
    }
    out.push({ id: name.slice(0, -3), sha256: createHash("sha256").update(bytes).digest("hex"), layout: pluginLayout(text), bytes });
  }
  return out;
}

const all = await bundles(pluginDir);

await rm(stageDir, { recursive: true, force: true });
for (const b of all) {
  const file = join(stageDir, builtInPluginPath(b));
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, b.bytes);
}
const index = all.map(({ id, sha256, layout }) => ({ id, sha256, layout }));
const json = JSON.stringify(index);
// The extension's parser must accept exactly this index (else nothing could run).
if (parseBuiltInPlugins(json).length !== index.length) throw new Error("index rejected by parseBuiltInPlugins");
process.stdout.write(json);
