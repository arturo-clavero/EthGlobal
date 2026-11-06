// The Rust crates compiled into the shipped WebAssembly prover (npm `tlsn-wasm`), with their licenses and license
// texts, for THIRD_PARTY_NOTICES.txt. Regenerate against a prepared core checkout when the core pin changes:
//   bash core/prepare-core.sh /tmp/tlsn-core
//   node --no-warnings fork/wasm-crates.mts /tmp/tlsn-core > fork/third-party/wasm-crates.json
// Set = `cargo metadata --locked --filter-platform wasm32-unknown-unknown` of the tlsn workspace, walked from the
// `tlsn-wasm` crate over normal dependencies only (build and dev dependencies and proc-macro crates run at compile time
// and are not in the .wasm). Approximate in one direction only: cargo resolves features for the whole workspace, so a
// crate enabled only by another workspace member may be listed although tlsn-wasm does not link it (never the reverse).
// License texts are the crate's own LICENSE*/COPYING*/NOTICE* files (from the cargo registry or git checkout, the
// repository root for git workspaces); where a crate ships none, the standard text of its license is used with the
// crate's authors and marked so.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { MIT_TEMPLATE, pickLicenseFiles } from "./third-party-licenses.mts";

const src = process.argv[2];
if (!src) throw new Error("usage: wasm-crates.mts <tlsn checkout>");
const meta = JSON.parse(
  execFileSync("cargo", ["metadata", "--locked", "--format-version", "1", "--filter-platform", "wasm32-unknown-unknown"], {
    cwd: src,
    maxBuffer: 1 << 28,
  }).toString(),
);
type Pkg = { id: string; name: string; version: string; license: string | null; license_file: string | null; manifest_path: string;
  source: string | null; repository: string | null; authors: string[]; targets: { kind: string[] }[] };
const pkgs = new Map<string, Pkg>(meta.packages.map((p: Pkg) => [p.id, p]));
const nodes = new Map<string, { deps: { pkg: string; dep_kinds: { kind: string | null }[] }[] }>(
  meta.resolve.nodes.map((n: { id: string }) => [n.id, n]),
);
const root = [...pkgs.values()].find((p) => p.name === "tlsn-wasm");
if (!root) throw new Error("no tlsn-wasm crate in " + src);

const seen = new Set<string>();
const stack = [root.id];
while (stack.length) {
  const id = stack.pop()!;
  if (seen.has(id)) continue;
  const pkg = pkgs.get(id)!;
  if (pkg.targets.some((t) => t.kind.includes("proc-macro"))) continue; // runs in the compiler only
  seen.add(id);
  for (const d of nodes.get(id)!.deps) if (d.dep_kinds.some((k) => k.kind === null)) stack.push(d.pkg);
}

// Crates whose Cargo.toml has no `license`: the repositories' README says "MIT OR Apache-2.0" for all their crates.
const README_LICENSE: [RegExp, string, string][] = [
  [/github\.com\/privacy-ethereum\/mpz/, "MIT OR Apache-2.0", "the mpz contributors (https://github.com/privacy-ethereum/mpz)"],
  [/github\.com\/tlsnotary\//, "MIT OR Apache-2.0", "the TLSNotary contributors"],
];
const isWorkspace = (p: Pkg) => p.source === null;

const texts: Record<string, string> = {};
const keep = (text: string) => {
  const h = createHash("sha256").update(text).digest("hex").slice(0, 16);
  texts[h] = text;
  return h;
};
// License files of a crate: its own directory, else (git or workspace crates) the nearest parent with license files,
// up to the checkout root.
function licenseFiles(p: Pkg): string[] {
  const list = (dir: string) =>
    readdirSync(dir).filter((f) => /^(licen[cs]e|copying|notice|unlicense)/i.test(f) && statSync(join(dir, f)).isFile())
      .map((f) => join(dir, f));
  let dir = dirname(p.manifest_path);
  const stop = p.source?.startsWith("git+") || isWorkspace(p);
  for (let i = 0; i < 4; i++) {
    const found = list(dir);
    if (found.length || !stop || existsSync(join(dir, ".git")) || existsSync(join(dir, "Cargo.lock"))) return found;
    dir = dirname(dir);
  }
  return [];
}

const crates = [...seen].map((id) => pkgs.get(id)!).sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)).map((p) => {
  const repo = p.repository ?? p.source ?? "";
  const fallback = README_LICENSE.find(([re]) => re.test(repo) || re.test(p.source ?? ""));
  const license = p.license ?? (p.license_file ? `see ${p.license_file}` : fallback?.[1] ?? (isWorkspace(p) ? "MIT OR Apache-2.0" : null));
  if (!license) throw new Error(`${p.name} ${p.version}: no license`);
  const files = licenseFiles(p);
  const picked = pickLicenseFiles(license, files.map((f) => ({ name: f.split("/").pop()!, text: readFileSync(f, "utf8") })));
  let note: string | undefined;
  let textIds = picked.map((f) => keep(f.text.trim()));
  if (!textIds.length) {
    if (!/\bMIT\b/.test(license)) throw new Error(`${p.name} ${p.version}: ${license} and no license file`);
    const holder = fallback?.[2] ?? (p.authors.length ? p.authors.join(", ") : `the ${p.name} authors`);
    textIds = [keep(MIT_TEMPLATE.replace("<copyright holders>", holder))];
    note = "the crate ships no license file; standard MIT text";
  }
  return { name: p.name, version: p.version, license, source: p.source ?? p.repository ?? "tlsn workspace",
    repository: p.repository, texts: textIds, ...(note ? { note } : {}) };
});

const wasmVersion = root.version;
process.stdout.write(JSON.stringify({ tlsnWasm: wasmVersion, generatedBy: "fork/wasm-crates.mts",
  crates, texts }, null, 1) + "\n");
console.error(`tlsn-wasm ${wasmVersion}: ${crates.length} crates, ${Object.keys(texts).length} distinct license texts`);
