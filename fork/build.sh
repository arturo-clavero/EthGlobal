#!/usr/bin/env bash
# Build this repository (the upstream TLSNotary extension with this fork's changes) as an unpacked MV3 extension:
#   bash fork/build.sh        # -> fork/out/extension (+ fork/out/extension-id.txt with FORK_KEY_FILE)
# Builds the working tree in place: nothing is cloned, reset or patched. Steps: the GCP, AWS and Azure private proof
# circuits and browser workers (private-proof/), the pinned TLSNotary WASM prover (core/), the QuickJS handle
# repair, upstream's webpack build, the built-in plugins, THIRD_PARTY_NOTICES.txt and the manifest.
# Environment, all optional for a dev build:
#   FORK_NAME             manifest name (default "TLSN Extension (dev)", "TLSN Extension" with FORK_KEY_FILE)
#   FORK_DESCRIPTION      manifest description, at most 132 characters
#   FORK_ICON_DIR         directory with icon-16.png, icon-34.png, icon-48.png and icon-128.png (default: upstream's)
#   FORK_KEY_FILE         base64 DER public key, written as the manifest `key` (stable extension ID). Marks a
#                         production build: https FORK_PRODUCT_ORIGINS and at least one built-in plugin are required
#   FORK_PRODUCT_ORIGINS  comma-separated origins of the embedding pages allowed to use the page API
#                         (dev default: http://localhost:5173, http://127.0.0.1:5173 and the same on port 5175)
#   FORK_PLUGIN_DIR       directory of built plugin bundles <id>.js, packaged as the extension's built-in plugins
#                         (the only plugin code it runs); without it the extension has none
#   GCP_NOIR_NARGO        the pinned Noir compiler (default: nargo on PATH)
#   AZURE_NOIR_NARGO      the pinned Noir compiler for the Azure circuits (default: GCP_NOIR_NARGO)
# One heavy step at a time: npm ci only where node_modules is missing.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
GCP="$ROOT/private-proof/gcp"
AWS="$ROOT/private-proof/aws"
AZURE="$ROOT/private-proof/azure"
CORE="$ROOT/core"
WORK="$HERE/.work"; OUT="$HERE/out"

for f in "$HERE/THIRD_PARTY_NOTICES.txt" "$HERE/third-party/wasm-crates.json" "$HERE/third-party/Apache-2.0.txt" \
  "$CORE/VERSION" "$CORE/prepare-core.sh" "$GCP/package.json" "$AWS/package.json" "$AZURE/package.json"; do
  [ -s "$f" ] || { echo "missing $f: refusing to build" >&2; exit 1; }
done

# A keyed build is a production build: explicit https origins and a non-empty built-in plugin set.
if [ -n "${FORK_KEY_FILE:-}" ]; then
  # Resolved now: later steps run in other directories.
  [ -f "$FORK_KEY_FILE" ] || { echo "FORK_KEY_FILE not found: $FORK_KEY_FILE" >&2; exit 1; }
  KEY_FILE="$(realpath "$FORK_KEY_FILE")"; PRODUCTION=1; DEFAULT_NAME="TLSN Extension"
else
  KEY_FILE=""; PRODUCTION=0; DEFAULT_NAME="TLSN Extension (dev)"
fi
NAME="${FORK_NAME:-$DEFAULT_NAME}"
DESCRIPTION="${FORK_DESCRIPTION:-Creates TLSNotary proofs of web data in the browser, including private zero-knowledge proofs for GCP, AWS and Azure.}"
[ "${#DESCRIPTION}" -le 132 ] || { echo "manifest description is ${#DESCRIPTION} characters (max 132)" >&2; exit 1; }
ICON_DIR=""
if [ -n "${FORK_ICON_DIR:-}" ]; then
  ICON_DIR="$(realpath "$FORK_ICON_DIR")"
  for size in 16 34 48 128; do
    [ -f "$ICON_DIR/icon-$size.png" ] || { echo "FORK_ICON_DIR has no icon-$size.png: $ICON_DIR" >&2; exit 1; }
  done
fi
DEV_ORIGINS="http://localhost:5173,http://127.0.0.1:5173,http://localhost:5175,http://127.0.0.1:5175"
if [ "$PRODUCTION" = 0 ]; then
  PRODUCT_ORIGINS="${FORK_PRODUCT_ORIGINS:-$DEV_ORIGINS}"
else
  PRODUCT_ORIGINS="${FORK_PRODUCT_ORIGINS:?FORK_PRODUCT_ORIGINS is required with FORK_KEY_FILE (e.g. https://app.example.com)}"
  IFS=',' read -ra _origins <<<"$PRODUCT_ORIGINS"
  for o in "${_origins[@]}"; do
    [[ "$o" =~ ^https://[a-z0-9.-]+(:[0-9]+)?$ ]] || { echo "production origin must be https://host[:port]: '$o'" >&2; exit 1; }
    case "$o" in https://localhost|https://localhost:*|https://127.*|https://0.0.0.0*|*.localhost|*.localhost:*)
      echo "production origin must not be a loopback host: '$o'" >&2; exit 1 ;; esac
  done
fi
export FORK_PRODUCT_ORIGINS="$PRODUCT_ORIGINS"
PLUGIN_DIR=""
if [ -n "${FORK_PLUGIN_DIR:-}" ]; then
  PLUGIN_DIR="$(realpath "$FORK_PLUGIN_DIR")"
  ls "$PLUGIN_DIR"/*.js >/dev/null 2>&1 || { echo "warning: no plugin bundles (*.js) in $PLUGIN_DIR" >&2; PLUGIN_DIR=""; }
fi
if [ -z "$PLUGIN_DIR" ]; then
  [ "$PRODUCTION" = 0 ] || { echo "a production build needs its built-in plugins: set FORK_PLUGIN_DIR to the built bundles" >&2; exit 1; }
  echo "warning: no FORK_PLUGIN_DIR; the extension will have no built-in plugin (nothing can run)" >&2
fi

mkdir -p "$WORK"
cd "$ROOT"
[ -d node_modules ] || npm ci --no-audit --no-fund
# The AWS package resolves the proof runtime through the GCP package, so GCP is installed first.
for dir in "$GCP" "$AWS" "$AZURE"; do
  [ -d "$dir/node_modules" ] || (cd "$dir" && npm ci --ignore-scripts --no-audit --no-fund)
done

# Private proofs: application-pinned circuits (GCP compiles its own and checks the Noir compiler; the AWS circuits
# are compiled here with the same compiler, serially) and the modules the extension imports from src/gcp-private.
node "$GCP/build-artifacts.mjs"
for circuit in "$AWS"/circuits/*/; do
  [ "$(basename "$circuit")" = lib ] && continue
  (cd "$circuit" && "${GCP_NOIR_NARGO:-nargo}" compile)
done
node "$AWS/build-artifacts.mjs"
# Azure compiles its own circuits and the shared GCP ones it reuses, serially, and checks every pin and key.
AZURE_NOIR_NARGO="${AZURE_NOIR_NARGO:-${GCP_NOIR_NARGO:-nargo}}" node "$AZURE/build-artifacts.mjs"
PRIVATE_SOURCE="$ROOT/packages/extension/src/gcp-private"
mkdir -p "$PRIVATE_SOURCE/generated"
for module in browser-client client-plan authenticated-transcript gcp-structure http-structure json-structure policy verify-bundle; do
  cp "$GCP/$module.mjs" "$PRIVATE_SOURCE/$module.mjs"
done
cp "$GCP/generated/catalog.json" "$PRIVATE_SOURCE/generated/catalog.json"

# Built-in plugins, staged for packaging; their index (id, sha256, layout, parsed by the extension's own
# builtinPlugins.ts) is baked in as __FORK_PLUGIN_ALLOWLIST__.
STAGE="$WORK/builtin-stage"
rm -rf "$STAGE"
export FORK_PLUGIN_ALLOWLIST="[]"
if [ -n "$PLUGIN_DIR" ]; then
  FORK_PLUGIN_ALLOWLIST="$(node --no-warnings "$HERE/builtin-plugins.mts" "$ROOT/packages/extension/src/constants/builtinPlugins.ts" "$STAGE" "$PLUGIN_DIR")"
fi
if [ "$PRODUCTION" = 1 ] && [ "$FORK_PLUGIN_ALLOWLIST" = "[]" ]; then
  echo "no built-in plugins: a production build refuses (set FORK_PLUGIN_DIR to the built plugin bundles)" >&2; exit 1
fi

# Prover and verifier must use the same bounded mux/backpressure core. build-wasm.mjs prepares the pinned core
# (core/prepare-core.sh), pins the Rust toolchain, remaps build paths, verifies cached WASM provenance and stages the
# generated JS/WASM package before bundling.
node "$HERE/build-wasm.mjs" "$ROOT"
node "$HERE/fix-quickjs-handles.mjs" "$ROOT"
node "$GCP/build-browser.mjs" "$ROOT/packages/extension"
node "$GCP/build-browser.mjs" "$ROOT/packages/extension" aws
# Azure: proof worker, portal discovery bundle and the client modules the extension imports from src/azure-private.
node "$AZURE/build-browser.mjs" "$ROOT/packages/extension"
# Upstream's `npm run build` (build:deps, then the extension's utils/build.js), with the extension step run through
# webpack-build.cjs, which records the files webpack put into the bundles (for THIRD_PARTY_NOTICES.txt below).
EXT_VERSION="$(node -p 'require(process.argv[1]).version' "$ROOT/packages/extension/package.json")"
rm -f "$WORK/bundled-modules.json"
{ npm run build:deps && (cd packages/extension && NODE_ENV=production node "$HERE/webpack-build.cjs" "$WORK/bundled-modules.json"); } >"$WORK/build.log" 2>&1 \
  || { tail -40 "$WORK/build.log" >&2; echo "build failed, full log: $WORK/build.log" >&2; exit 1; }
[ -s "$WORK/bundled-modules.json" ] || { echo "the build recorded no bundled modules ($WORK/bundled-modules.json)" >&2; exit 1; }
node - "$WORK/bundled-modules.json" "$GCP/dist/browser-modules.json" "$AWS/dist/browser-modules.json" "$AZURE/dist/browser-modules.json" <<'NODE'
const fs = require('node:fs');
const [main, ...workers] = process.argv.slice(2);
const files = [...new Set([main, ...workers].flatMap(file => JSON.parse(fs.readFileSync(file))))].sort();
fs.writeFileSync(main, JSON.stringify(files) + '\n');
NODE

rm -rf "$OUT/extension"; mkdir -p "$OUT"
cp -R "$ROOT/packages/extension/build" "$OUT/extension"
cp -R "$GCP/dist/browser" "$OUT/extension/gcp-private"
cp -R "$AWS/dist/browser" "$OUT/extension/aws-private"
cp -R "$AZURE/dist/browser" "$OUT/extension/azure-private"
# The built-in plugins, byte for byte (builtin-plugins/<id>-<sha256>.js; not web-accessible).
if [ -d "$STAGE/builtin-plugins" ]; then cp -R "$STAGE/builtin-plugins" "$OUT/extension/builtin-plugins"; fi
# icon-34 and icon-128 are also web-accessible resources, so the replacements keep upstream's file names.
if [ -n "$ICON_DIR" ]; then
  for size in 16 34 48 128; do cp "$ICON_DIR/icon-$size.png" "$OUT/extension/icon-$size.png"; done
fi
# THIRD_PARTY_NOTICES.txt for everything shipped: the upstream attribution (THIRD_PARTY_NOTICES.txt here), every npm
# package in the bundles (name, version, license, license and NOTICE texts) and the Rust crates compiled into
# tlsn-wasm (third-party/wasm-crates.json, made by wasm-crates.mts). Refuses an unknown or copyleft license, a package
# without license text, or a tlsn-wasm version other than the one the crate list was made for.
node --no-warnings "$HERE/third-party-notices.mts" --modules "$WORK/bundled-modules.json" --upstream "$ROOT" \
  --private-proof-root "$GCP" --aws-private-proof-root "$AWS" --azure-private-proof-root "$AZURE" \
  --product "$NAME $EXT_VERSION" --header "$HERE/THIRD_PARTY_NOTICES.txt" --crates "$HERE/third-party/wasm-crates.json" \
  --out "$OUT/extension/THIRD_PARTY_NOTICES.txt"
[ -s "$OUT/extension/THIRD_PARTY_NOTICES.txt" ] || { echo "no THIRD_PARTY_NOTICES.txt in the extension: refusing to build" >&2; exit 1; }
rm -f "$OUT/extension-id.txt"
PRODUCT_ORIGINS="$PRODUCT_ORIGINS" EXT_VERSION="$EXT_VERSION" KEY_FILE="$KEY_FILE" ICONS="${ICON_DIR:+1}" NAME="$NAME" DESCRIPTION="$DESCRIPTION" OUT="$OUT" node -e '
const fs = require("fs"), crypto = require("crypto");
const p = process.env.OUT + "/extension/manifest.json";
const m = JSON.parse(fs.readFileSync(p, "utf8"));
m.version = process.env.EXT_VERSION; m.name = process.env.NAME; m.description = process.env.DESCRIPTION;
// Without isolation, the private prover silently falls back to single-threaded WASM.
m.cross_origin_embedder_policy = { value: "require-corp" };
m.cross_origin_opener_policy = { value: "same-origin" };
// The page bridge embeds packages/extension/package.json version; feature routing needs it to equal the manifest.
if (!fs.readFileSync(process.env.OUT + "/extension/content.bundle.js", "utf8").includes("version=" + JSON.stringify(m.version)))
  throw new Error("page bridge version does not match the manifest");
// Only the permissions the code needs. Upstream also asks for activeTab (no effect: the extension has no action,
// command or context menu), tabs (only unlocks tab URLs/titles, which the code never reads; tabs.sendMessage/onUpdated
// and windows.create/get/remove/onRemoved need no permission) and windows (not a Chrome permission).
const UNUSED = ["activeTab", "tabs", "windows"];
m.permissions = m.permissions.filter((p) => !UNUSED.includes(p));
const expected = ["offscreen", "webRequest"];
if (JSON.stringify([...m.permissions].sort()) !== JSON.stringify(expected))
  throw new Error("unexpected manifest permissions " + JSON.stringify(m.permissions) + " (expected " + JSON.stringify(expected) + ")");
if (process.env.ICONS === "1") m.icons = { "16": "icon-16.png", "48": "icon-48.png", "128": "icon-128.png" };
// Host access covers supported provider windows and product origins (the page API). The verifier and proxy are
// reached by WebSocket from the offscreen document, which needs no host permission, so no verifier host is listed.
// The AWS console region is fixed: the AWS private proof binds this region in its collection and circuits.
const GITHUB = ["https://github.com/*"];
const GCP = ["https://accounts.google.com/*", "https://console.cloud.google.com/*", "https://cloudconsole-pa.clients6.google.com/*", "https://logging.clients6.google.com/*"];
const AWS_CONSOLE = ["https://ap-southeast-2.console.aws.amazon.com/*", "https://*.ap-southeast-2.console.aws.amazon.com/*"];
const product = process.env.PRODUCT_ORIGINS.split(",").map((o) => {
  if (!/^https?:\/\/[a-z0-9.-]+(:[0-9]+)?$/.test(o)) throw new Error("product origin is not scheme://host[:port]: " + o);
  return o + "/*";
});
const AZURE = ["https://portal.azure.com/*", "https://graph.microsoft.com/*", "https://management.azure.com/*"];
const hosts = [...new Set([...GITHUB, ...GCP, ...AZURE, ...product])];
m.host_permissions = [...hosts, ...AWS_CONSOLE, "https://iam.amazonaws.com/*", "https://cloudtrail.us-east-1.amazonaws.com/*"];
if (m.content_scripts.length !== 1 || m.web_accessible_resources.length !== 1)
  throw new Error("upstream manifest changed: expected one content_scripts and one web_accessible_resources entry");
m.content_scripts[0].matches = hosts;
// AWS can request credentials before document_idle installs the capture receiver.
m.content_scripts.push({ ...m.content_scripts[0], matches: AWS_CONSOLE, run_at: "document_start" });
// Azure account discovery runs only in the portal, in the isolated world (never the page).
m.content_scripts.push({ matches: ["https://portal.azure.com/*"], js: ["azure-private/portal-discovery.bundle.js"], run_at: "document_idle", world: "ISOLATED" });
m.web_accessible_resources[0].matches = [...hosts, ...AWS_CONSOLE];
delete m.key;
if (process.env.KEY_FILE) {
  const key = fs.readFileSync(process.env.KEY_FILE, "utf8").trim();
  const der = Buffer.from(key, "base64");
  if (der.length < 200) throw new Error("FORK_KEY_FILE is not a base64 DER public key");
  const id = crypto.createHash("sha256").update(der).digest("hex").slice(0, 32)
    .replace(/[0-9a-f]/g, (c) => String.fromCharCode(97 + parseInt(c, 16)));
  m.key = key;
  fs.writeFileSync(process.env.OUT + "/extension-id.txt", id + "\n");
  console.log("extension id " + id);
} else {
  console.log("extension id: assigned by Chrome on load (no FORK_KEY_FILE, no key in the manifest)");
}
fs.writeFileSync(p, JSON.stringify(m, null, 2) + "\n");
'
if [ "$PRODUCTION" = 1 ]; then
  OUT="$OUT" node -e '
const m = JSON.parse(require("fs").readFileSync(process.env.OUT + "/extension/manifest.json", "utf8"));
// AWS multi-session Console hosts vary by account; permit only this regional suffix.
const all = JSON.stringify([m.host_permissions, m.content_scripts, m.web_accessible_resources])
  .replaceAll("https://*.ap-southeast-2.console.aws.amazon.com/*", "");
if (/<all_urls>|\*:\/\/|https?:\/\/\*|localhost|127\.0\.0\.1/.test(all)) throw new Error("production build: broad or loopback host access: " + all);
'
fi
# The origin list must be in the content script bundle (not the fail-closed empty list).
first_origin="${PRODUCT_ORIGINS%%,*}"
grep -qF "$first_origin" "$OUT/extension/contentScript.bundle.js" || { echo "product origins missing from contentScript.bundle.js" >&2; exit 1; }
echo "product origins: $PRODUCT_ORIGINS"
echo "host permissions: $(node -p 'require(process.argv[1]).host_permissions.join(" ")' "$OUT/extension/manifest.json")"
# The built-in index must be in the background and content bundles, and every packaged file must be exactly its entry
# (sha256); keep a readable copy next to the extension.
printf '%s\n' "$FORK_PLUGIN_ALLOWLIST" >"$OUT/builtin-plugins.json"
OUT="$OUT" node -e '
const fs = require("fs"), crypto = require("crypto");
const list = JSON.parse(fs.readFileSync(process.env.OUT + "/builtin-plugins.json", "utf8"));
const ext = process.env.OUT + "/extension/";
const bg = fs.readFileSync(ext + "background.bundle.js", "utf8");
const cs = fs.readFileSync(ext + "contentScript.bundle.js", "utf8");
const packaged = fs.existsSync(ext + "builtin-plugins") ? fs.readdirSync(ext + "builtin-plugins").sort() : [];
const expected = list.map((e) => e.id + "-" + e.sha256 + ".js").sort();
if (JSON.stringify(packaged) !== JSON.stringify(expected)) throw new Error("packaged built-in plugins " + packaged + " != index " + expected);
for (const e of list) {
  if (!bg.includes(e.sha256)) throw new Error("built-in " + e.id + " missing from background.bundle.js");
  if (!cs.includes(e.sha256)) throw new Error("built-in " + e.id + " missing from contentScript.bundle.js");
  const bytes = fs.readFileSync(ext + "builtin-plugins/" + e.id + "-" + e.sha256 + ".js");
  if (crypto.createHash("sha256").update(bytes).digest("hex") !== e.sha256) throw new Error("built-in " + e.id + ": file is not its sha256");
  console.log("built-in plugin (product origins only): " + e.id + " sha256 " + e.sha256 + " (" + bytes.length + " bytes)");
}
if (!list.length) console.log("built-in plugins: none (nothing can run)");
'
# No path for page-supplied code may reach the bundles: the stock execCode API and its messages are removed, and the
# page can only name a built-in plugin.
page_code_hits="$(grep -lE 'TLSN_EXEC_CODE|EXEC_CODE_OFFSCREEN|GET_PLUGIN_STATS_OFFSCREEN|execCode' "$OUT"/extension/*.js 2>/dev/null || true)"
[ -z "$page_code_hits" ] || { echo "page-code entry point in the bundles: $page_code_hits" >&2; exit 1; }
echo "page-supplied code: no entry point (built-in plugins only)"
# No path of this machine in the package (webpack would inline a bare import.meta.url as file://<abs path>). The
# prebuilt wasm carries upstream CI paths (/home/runner/...) and emscripten's virtual /home/web_user; ours never.
build_path_hits="$(grep -rlaF -e "$ROOT" -e "$HOME" "$OUT/extension" 2>/dev/null || true)"
[ -z "$build_path_hits" ] || { echo "absolute build path in the package: $build_path_hits" >&2; exit 1; }
echo "build paths: none in the package"
echo "unpacked extension: $OUT/extension"
