// THIRD_PARTY_NOTICES.txt of the shipped extension, written by build.sh after the webpack build.
//   node --no-warnings third-party-notices.mts --modules <bundled-modules.json> --upstream <repo root>
//     [--private-proof-root <private-proof/gcp>] [--aws-private-proof-root <private-proof/aws>]
//     [--azure-private-proof-root <private-proof/azure>]
//     --product "<name> <version>" --header <THIRD_PARTY_NOTICES.txt> --crates <third-party/wasm-crates.json> --out <file>
// Covers:
// - the upstream extension and its prover (the hand-written header: TLSNotary, MIT OR Apache-2.0);
// - every npm package with a file in the bundles (webpack-build.cjs lists them), plus packages a bundled file was itself
//   built from (its source map, e.g. @tlsn/plugin-sdk's dist inlines uuid and fast-deep-equal); the upstream
//   workspace packages (packages/*) are the upstream extension itself, and the private proof roots are application
//   code shipped with it;
// - the Rust crates compiled into tlsn_wasm_bg.wasm (wasm-crates.json, made by wasm-crates.mts for one tlsn-wasm
//   version; refused if the bundled tlsn-wasm is another version).
// For each: name, version, license; the license and NOTICE files are reproduced, identical texts once. Refuses (exit 1)
// a license that is not permissive (GPL, LGPL, MPL, unknown), a package without license text that is not MIT, and a
// module path outside the upstream tree.
import { existsSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve, sep } from "node:path";
import { isPermissive, MIT_TEMPLATE, pickLicenseFiles } from "./third-party-licenses.mts";

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i].replace(/^--/, ""), process.argv[i + 1]);
const need = (k: string) => {
  const v = args.get(k);
  if (!v) throw new Error(`missing --${k}`);
  return v;
};
const upstream = realpathSync(need("upstream"));
const privateProofRoot = args.has("private-proof-root") ? realpathSync(need("private-proof-root")) : null;
const awsPrivateProofRoot = args.has("aws-private-proof-root") ? realpathSync(need("aws-private-proof-root")) : null;
const azurePrivateProofRoot = args.has("azure-private-proof-root") ? realpathSync(need("azure-private-proof-root")) : null;
const modules: string[] = JSON.parse(readFileSync(need("modules"), "utf8"));
const header = readFileSync(need("header"), "utf8").trim();
const crates = JSON.parse(readFileSync(need("crates"), "utf8")) as {
  tlsnWasm: string;
  crates: { name: string; version: string; license: string; source: string | null; texts: string[]; note?: string }[];
  texts: Record<string, string>;
};
const product = need("product"); // "<name> <version>" of this build
const problems: string[] = [];
// The standard Apache-2.0 text (third-party/Apache-2.0.txt) for an Apache-2.0 package that ships no license file.
const APACHE_TEXT = readFileSync(new URL("./third-party/Apache-2.0.txt", import.meta.url), "utf8").trim();
/**
 * Not permissive, accepted by name after review, with what the license asks of us. MPL-2.0 (file-level copyleft): the
 * file is shipped unmodified; we keep its license text and say where its source is (MPL-2.0 §3.2).
 */
const REVIEWED: Record<string, { license: string; note: string }> = {
  "webextension-polyfill": {
    license: "MPL-2.0",
    note: "unmodified; source: https://github.com/mozilla/webextension-polyfill and the npm package webextension-polyfill",
  },
};

// ---- npm packages ----
type NpmPkg = { dir: string; name: string; version: string; license: string; files: { name: string; text: string }[]; note?: string };
const pkgs = new Map<string, NpmPkg>();
const workspaceFiles = new Set<string>();

function packageDirOf(file: string): string | null {
  const i = file.lastIndexOf(`${sep}node_modules${sep}`);
  if (i < 0) return null;
  const rest = file.slice(i + 14).split(sep);
  return file.slice(0, i + 14) + (rest[0].startsWith("@") ? `${rest[0]}${sep}${rest[1]}` : rest[0]);
}
function licenseOf(pj: { license?: unknown; licenses?: unknown }): string {
  const l = pj.license ?? pj.licenses;
  if (typeof l === "string") return l;
  if (l && typeof l === "object" && "type" in l) return String((l as { type: string }).type);
  if (Array.isArray(l)) return l.map((x) => (typeof x === "string" ? x : x.type)).join(" OR ");
  return "UNKNOWN";
}
function addPackage(dir: string) {
  if (pkgs.has(dir)) return;
  const pj = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const license = licenseOf(pj);
  const all = readdirSync(dir)
    .filter((f) => /^(licen[cs]e|copying|notice|unlicense)/i.test(f) && statSync(join(dir, f)).isFile())
    .map((f) => ({ name: f, text: readFileSync(join(dir, f), "utf8").trim() }));
  const pkg: NpmPkg = { dir, name: pj.name, version: pj.version, license, files: pickLicenseFiles(license, all) };
  const repo = typeof pj.repository === "string" ? pj.repository : (pj.repository?.url ?? "");
  const author = (typeof pj.author === "string" ? pj.author : pj.author?.name) ??
    (/github\.com\/tlsnotary\//.test(repo) ? "the TLSNotary contributors" : `the ${pj.name} authors`);
  if (!pkg.files.length) {
    if (/\bMIT\b/.test(license)) {
      pkg.files = [{ name: "LICENSE (standard text)", text: MIT_TEMPLATE.replace("<copyright holders>", author) }];
      pkg.note = "the package ships no license file; standard MIT text";
    } else if (license === "Apache-2.0") {
      pkg.files = [{ name: "LICENSE (standard text)", text: `Copyright ${author}\n\n${APACHE_TEXT}` }];
      pkg.note = "the package ships no license file; standard Apache-2.0 text";
    } else {
      problems.push(`${pj.name}@${pj.version} (${license}): no license file in the package`);
    }
  }
  const reviewed = REVIEWED[pj.name];
  if (reviewed && reviewed.license === license) pkg.note = [pkg.note, `${license}, ${reviewed.note}`].filter(Boolean).join("; ");
  else if (!isPermissive(license)) problems.push(`${pj.name}@${pj.version}: license "${license}" is not on the permissive list`);
  pkgs.set(dir, pkg);
}
function addFile(file: string) {
  const real = existsSync(file) ? realpathSync(file) : file;
  if (!real.startsWith(upstream + sep) &&
      !(privateProofRoot && real.startsWith(privateProofRoot + sep)) &&
      !(awsPrivateProofRoot && real.startsWith(awsPrivateProofRoot + sep)) &&
      !(azurePrivateProofRoot && real.startsWith(azurePrivateProofRoot + sep))) {
    problems.push(`bundled file outside the upstream tree: ${real}`);
    return;
  }
  const dir = packageDirOf(real);
  if (dir) addPackage(dir);
  else workspaceFiles.add(real);
  // A bundled file that was itself bundled from other packages: its source map names them.
  const map = `${real}.map`;
  if (existsSync(map)) {
    const { sources = [], sourceRoot = "" } = JSON.parse(readFileSync(map, "utf8"));
    for (const s of sources as string[]) {
      if (!s.includes("node_modules/")) continue;
      const abs = resolve(dirname(real), sourceRoot, s.replace(/^webpack:\/\/[^/]*\//, ""));
      if (existsSync(abs)) addFile(abs);
      else problems.push(`source map ${map} names a missing file: ${s}`);
    }
  }
}
for (const m of modules) addFile(m);
for (const f of workspaceFiles) {
  if (!f.startsWith(join(upstream, "packages") + sep) && !(privateProofRoot && f.startsWith(privateProofRoot + sep)) &&
      !(awsPrivateProofRoot && f.startsWith(awsPrivateProofRoot + sep)) &&
      !(azurePrivateProofRoot && f.startsWith(azurePrivateProofRoot + sep)))
    problems.push(`bundled file is neither a package nor approved application code: ${f}`);
}

// ---- Rust crates in tlsn-wasm ----
const wasmPkg = [...pkgs.values()].find((p) => p.name === "tlsn-wasm");
if (!wasmPkg) problems.push("tlsn-wasm is not among the bundled packages");
else if (wasmPkg.version !== crates.tlsnWasm)
  problems.push(`bundled tlsn-wasm ${wasmPkg.version} != wasm-crates.json ${crates.tlsnWasm} (re-run wasm-crates.mts)`);
for (const c of crates.crates) {
  if (!isPermissive(c.license)) problems.push(`crate ${c.name} ${c.version}: license "${c.license}" is not on the permissive list`);
  for (const t of c.texts) if (!crates.texts[t]) problems.push(`crate ${c.name}: missing text ${t}`);
}

if (problems.length) {
  console.error("THIRD_PARTY_NOTICES.txt refused:\n  " + problems.join("\n  "));
  process.exit(1);
}

// ---- write ----
const npm = [...pkgs.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
const textIds = new Map<string, { text: string; users: string[] }>();
const useText = (text: string, user: string) => {
  const id = createHash("sha256").update(text.trim()).digest("hex").slice(0, 12);
  const e = textIds.get(id) ?? { text: text.trim(), users: [] };
  if (!e.users.includes(user)) e.users.push(user);
  textIds.set(id, e);
  return id;
};
const out: string[] = [];
out.push(`THIRD-PARTY SOFTWARE NOTICES: ${product}`, "");
out.push(header, "");
out.push("=".repeat(118), "");
out.push(`1. JavaScript packages in this extension (${npm.length})`, "");
out.push(
  "Name, version, license, and the license text(s) in section 3 that apply ([n]). Dual-licensed packages and crates",
  "(\"MIT OR Apache-2.0\" and similar) are used under the MIT license where they offer it.",
  "",
);
const npmRows: [NpmPkg, string[]][] = npm.map((p) => [p, p.files.map((f) => useText(f.text, `${p.name} ${p.version}`))]);
const crateRows: [(typeof crates.crates)[number], string[]][] = crates.crates.map((c) => [
  c,
  c.texts.map((t) => useText(crates.texts[t], `${c.name} ${c.version}`)),
]);
// The Azure discovery bundle carries a small Node.js-derived adapter; its MIT notice is the file's leading comment.
const discoveryAdapter = modules.find((path) => path.endsWith("/browser-discovery-platform.mjs"));
const discoveryLicense = discoveryAdapter ? useText(readFileSync(discoveryAdapter, "utf8")
  .split("const RegExpPrototypeTest")[0].split("\n").filter((line) => line.startsWith("//"))
  .map((line) => line.replace(/^\/\/ ?/, "")).join("\n"), "Node.js internal/net.js browser adapter (MIT)") : null;
const order = [...textIds.keys()];
const ref = (ids: string[]) => ids.map((id) => `[${order.indexOf(id) + 1}]`).join(" ");
for (const [p, ids] of npmRows) out.push((`  ${p.name} ${p.version}  ${p.license}  ${ref(ids)}${p.note ? `  (${p.note})` : ""}`));
out.push("");
out.push(`2. Rust crates compiled into the WebAssembly prover tlsn_wasm_bg.wasm (tlsn-wasm ${crates.tlsnWasm}; ${crates.crates.length})`, "");
for (const [c, ids] of crateRows) out.push((`  ${c.name} ${c.version}  ${c.license}  ${ref(ids)}${c.note ? `  (${c.note})` : ""}`));
if (discoveryLicense) out.push("", `Node.js-derived browser IP validation: MIT ${ref([discoveryLicense])}`);
out.push("", "=".repeat(118), "", "3. License texts", "");
order.forEach((id, i) => {
  const e = textIds.get(id)!;
  out.push("-".repeat(118), `[${i + 1}] Applies to: ${e.users.join(", ")}`, "-".repeat(118), "", e.text, "");
});
const target = need("out");
writeFileSync(target, out.join("\n").replace(/\r\n/g, "\n") + "\n");
const licenses = new Map<string, number>();
for (const p of npm) licenses.set(p.license, (licenses.get(p.license) ?? 0) + 1);
console.log(
  `THIRD_PARTY_NOTICES.txt: ${npm.length} npm packages (${[...licenses].map(([l, n]) => `${l} ${n}`).join(", ")}), ` +
    `${crates.crates.length} Rust crates, ${order.length} license texts, ${statSync(target).size} bytes`,
);
const standard = (n?: string) => !!n && n.includes("standard");
const noted = [...npm.filter((p) => standard(p.note)).map((p) => `${p.name}@${p.version}`), ...crates.crates.filter((c) => standard(c.note)).map((c) => c.name)];
if (noted.length) console.log(`standard license text used (no license file shipped): ${noted.join(", ")}`);
