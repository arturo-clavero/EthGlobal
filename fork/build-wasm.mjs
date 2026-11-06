// Rebuild the pinned prover from the patched TLSNotary core (core/), with the same bounded mux as the verifier.
// Cargo + bindgen + Binaryen reproduce upstream wasm-pack's custom `wasm` profile.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync,
  renameSync, rmSync, writeFileSync, createWriteStream } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const hashFile = file => sha(readFileSync(file));
// The digest prepare-core.sh pins each patch directory by: sha256 over `sha256sum <sorted ./*.patch>`, so the
// bytes, the names and the set are all covered. Kept byte-identical to the shell so both sides agree.
const patchesDigest = dir => sha(readdirSync(dir).filter(n => n.endsWith('.patch')).map(n => `./${n}`).sort()
  .map(n => `${hashFile(join(dir, n))}  ${n}\n`).join(''));
const manifestName = 'fork-wasm-provenance.json';
const required = ['package.json', 'tlsn_wasm.js', 'tlsn_wasm_bg.wasm', 'tlsn_wasm.d.ts', 'tlsn_wasm_bg.wasm.d.ts', 'spawn.js'];

export function patchSpawnSnippet(source) {
  assert.equal((source.match(/import\('\.\.\/\.\.\/\.\.'\)/g) || []).length, 2, 'WASM_SPAWN_IMPORT_CHANGED');
  return source.replaceAll("import('../../..')", "import('../../../tlsn_wasm.js')");
}

function filesBelow(directory, prefix = '') {
  const files = [];
  for (const entry of readdirSync(join(directory, prefix), { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    assert(!entry.isSymbolicLink(), 'WASM_PACKAGE_SYMLINK');
    if (entry.isDirectory()) files.push(...filesBelow(directory, name));
    else { assert(entry.isFile(), 'WASM_PACKAGE_FILE_TYPE'); files.push(name); }
  }
  return files.sort();
}

export function validatePackage(directory, inputHash, pins) {
  assert(!lstatSync(directory).isSymbolicLink(), 'WASM_PACKAGE_SYMLINK');
  const proof = JSON.parse(readFileSync(join(directory, manifestName), 'utf8'));
  assert.equal(proof.schema, 1, 'WASM_PROVENANCE_SCHEMA');
  assert.equal(proof.inputHash, inputHash, 'WASM_PROVENANCE_INPUT');
  assert.equal(sha(JSON.stringify(proof.inputs)), inputHash, 'WASM_PROVENANCE_INPUT_HASH');
  assert(proof.files && typeof proof.files === 'object' && !Array.isArray(proof.files), 'WASM_PROVENANCE_FILES');
  const files = filesBelow(directory).filter(file => file !== manifestName);
  assert.deepEqual(Object.keys(proof.files).sort(), files, 'WASM_PACKAGE_FILE_SET');
  for (const name of required) assert(files.includes(name), 'WASM_PACKAGE_REQUIRED_FILE');
  assert(files.some(name => /^snippets\/[^/]+\/js\/spawn\.js$/.test(name)), 'WASM_PACKAGE_SPAWN_SNIPPET');
  for (const name of files) assert.equal(hashFile(join(directory, name)), proof.files[name], 'WASM_PACKAGE_HASH');
  const pkg = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'tlsn-wasm', 'WASM_PACKAGE_NAME');
  assert.equal(pkg.version, pins.packageVersion, 'WASM_PACKAGE_VERSION');
  assert.equal(pkg.type, 'module', 'WASM_PACKAGE_MODULE_TYPE');
  assert.equal(pkg.main, 'tlsn_wasm.js', 'WASM_PACKAGE_ENTRY');
  assert.equal(pkg.types, 'tlsn_wasm.d.ts', 'WASM_PACKAGE_TYPES');
  assert.deepEqual(pkg.sideEffects, ['./snippets/*'], 'WASM_PACKAGE_WORKER_EFFECTS');
  assert.equal(hashFile(join(directory, 'tlsn_wasm.d.ts')), pins.publicTypesSha256, 'WASM_PUBLIC_ABI_CHANGED');
  return proof;
}

export function stagePackage(source, upstream, inputHash, pins) {
  validatePackage(source, inputHash, pins);
  const root = realpathSync(upstream);
  const parent = realpathSync(join(root, 'packages/extension/node_modules'));
  assert(parent.startsWith(`${root}${sep}`), 'WASM_STAGE_OUTSIDE_UPSTREAM');
  const target = join(parent, 'tlsn-wasm');
  assert(!lstatSync(target, { throwIfNoEntry: false })?.isSymbolicLink(), 'WASM_STAGE_SYMLINK');
  const temporary = `${target}.staging-${process.pid}`, backup = `${target}.backup-${process.pid}`;
  assert(!existsSync(temporary) && !existsSync(backup), 'WASM_STAGE_BUSY');
  let backedUp = false;
  try {
    cpSync(source, temporary, { recursive: true, errorOnExist: true });
    validatePackage(temporary, inputHash, pins);
    if (existsSync(target)) { renameSync(target, backup); backedUp = true; }
    try { renameSync(temporary, target); }
    catch (error) { if (backedUp) { renameSync(backup, target); backedUp = false; } throw error; }
    if (backedUp) rmSync(backup, { recursive: true });
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

async function tool(spec, cache) {
  const archive = join(cache, `${spec.sha256}.tar.gz`);
  if (!existsSync(archive)) {
    const temporary = `${archive}.download-${process.pid}`;
    try {
      const response = await fetch(spec.url, { signal: AbortSignal.timeout(180_000) });
      assert(response.ok && response.body, 'WASM_TOOL_DOWNLOAD_FAILED');
      const hash = createHash('sha256'); let bytes = 0;
      await pipeline(Readable.fromWeb(response.body), new Transform({ transform(chunk, _encoding, callback) {
        bytes += chunk.length;
        if (bytes > spec.bytes) { callback(new Error('WASM_TOOL_DOWNLOAD_BOUND')); return; }
        hash.update(chunk); callback(null, chunk);
      } }), createWriteStream(temporary, { flags: 'wx', mode: 0o600 }));
      assert.equal(bytes, spec.bytes, 'WASM_TOOL_DOWNLOAD_SIZE');
      assert.equal(hash.digest('hex'), spec.sha256, 'WASM_TOOL_DOWNLOAD_HASH');
      renameSync(temporary, archive);
    } finally { rmSync(temporary, { force: true }); }
  }
  assert.equal(hashFile(archive), spec.sha256, 'WASM_TOOL_ARCHIVE_HASH');
  const directory = join(cache, spec.sha256);
  mkdirSync(directory, { recursive: true });
  // Extract only the pinned executable, including on reuse; never trust a stale cached binary.
  execFileSync('tar', ['-xzf', archive, '-C', directory, spec.member], { stdio: 'inherit' });
  return join(directory, spec.member);
}

function run(command, args, options = {}) {
  return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...options });
}

async function buildAndStage(upstream, cache) {
  const pins = JSON.parse(readFileSync(join(here, 'wasm-build-pins.json'), 'utf8'));
  assert.equal(process.platform, 'linux', 'WASM_PINNED_BUILD_REQUIRES_LINUX');
  assert.equal(process.arch, 'x64', 'WASM_PINNED_BUILD_REQUIRES_X64');
  const coreKit = resolve(here, '../core');
  const version = readFileSync(join(coreKit, 'VERSION'), 'utf8');
  const coreCommit = /^TLSN_CORE_COMMIT=([a-f0-9]{40})$/m.exec(version)?.[1];
  const corePatchesSha256 = /^TLSN_CORE_PATCHES_SHA256=([a-f0-9]{64})$/m.exec(version)?.[1];
  const mpzPatchesSha256 = /^TLSN_MPZ_PATCHES_SHA256=([a-f0-9]{64})$/m.exec(version)?.[1];
  assert.equal(coreCommit, pins.coreCommit, 'WASM_CORE_PIN_MISMATCH');
  // The whole series is pinned, not one patch: the core carries the mux backpressure stack and MPZ carries the
  // post-handshake batch synchronization, and the prover must be built from exactly both.
  assert.equal(patchesDigest(join(coreKit, 'patches')), corePatchesSha256, 'WASM_CORE_PATCHES_HASH');
  assert.equal(patchesDigest(join(coreKit, 'mpz-patches')), mpzPatchesSha256, 'WASM_MPZ_PATCHES_HASH');
  const toolchain = resolve(process.env.TLSN_WASM_TOOLCHAIN || join(homedir(), '.cache/gcp-private-proof/toolchains', pins.toolchain));
  const rustc = join(toolchain, 'bin/rustc'), cargo = join(toolchain, 'bin/cargo');
  const compiler = run(rustc, ['-vV']);
  assert(compiler.includes(`release: ${pins.rustcRelease}\n`) &&
    new RegExp(`^commit-hash: ${pins.rustcCommitPrefix}[a-f0-9]+$`, 'm').test(compiler), 'WASM_RUSTC_PIN_MISMATCH');
  const clang = realpathSync(process.env.TLSN_WASM_CLANG || '/usr/bin/clang');
  const clangVersion = /^.*clang version ([0-9.]+)(?:\s|$)/m.exec(run(clang, ['--version']))?.[1];
  assert.equal(clangVersion, pins.clangVersion, 'WASM_CLANG_PIN_MISMATCH');
  const inputs = { pinsSha256: hashFile(join(here, 'wasm-build-pins.json')), recipeSha256: hashFile(fileURLToPath(import.meta.url)),
    coreCommit, corePatchesSha256, mpzPatchesSha256, cargoLockSha256: pins.cargoLockSha256, cargoConfigSha256: pins.cargoConfigSha256,
    rustcSha256: hashFile(rustc), cargoSha256: hashFile(cargo), clangSha256: hashFile(clang), clangVersion };
  const inputHash = sha(JSON.stringify(inputs));
  const artifact = join(cache, 'packages', inputHash);
  if (!existsSync(artifact)) {
    const core = join(cache, 'core');
    run('bash', [join(coreKit, 'prepare-core.sh'), core]);
    assert.equal(hashFile(join(core, 'Cargo.lock')), pins.cargoLockSha256, 'WASM_CARGO_LOCK_CHANGED');
    assert.equal(hashFile(join(core, 'crates/wasm/.cargo/config.toml')), pins.cargoConfigSha256, 'WASM_CARGO_FLAGS_CHANGED');
    const tools = join(cache, 'tools'); mkdirSync(tools, { recursive: true });
    const bindgen = await tool(pins.bindgen, tools), optimizer = await tool(pins.optimizer, tools);
    assert(run(bindgen, ['--version']).startsWith(`wasm-bindgen ${pins.bindgen.version}`), 'WASM_BINDGEN_VERSION');
    assert(run(optimizer, ['--version']).includes(`wasm-opt version ${pins.optimizer.version}`), 'WASM_OPT_VERSION');
    const cargoHome = resolve(process.env.CARGO_HOME || join(homedir(), '.cache/gcp-private-proof/cargo'));
    const target = join(cache, 'target');
    const remaps = [[core, '/tlsn-core'], [cargoHome, '/cargo'], [toolchain, '/rust']];
    const env = { ...process.env, PATH: `${join(toolchain, 'bin')}:${process.env.PATH}`, RUSTC: rustc,
      CARGO_HOME: cargoHome, CARGO_TARGET_DIR: target, CARGO_BUILD_JOBS: '1',
      CC_wasm32_unknown_unknown: clang,
      CFLAGS_wasm32_unknown_unknown: remaps.map(([from, to]) => `-ffile-prefix-map=${from}=${to}`).join(' '),
      CARGO_ENCODED_RUSTFLAGS: [...pins.rustflags, ...remaps.map(([from, to]) => `--remap-path-prefix=${from}=${to}`)].join('\x1f') };
    for (const key of Object.keys(env)) if (['RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CFLAGS'].includes(key) ||
      key.startsWith('CARGO_PROFILE_')) delete env[key];
    console.log('Building pinned TLSNotary WASM (one Cargo job).');
    run(cargo, ['build', '--locked', '--profile', 'wasm', '--target', 'wasm32-unknown-unknown', '-p', 'tlsn-wasm'],
      { cwd: join(core, 'crates/wasm'), env, stdio: 'inherit' });
    const output = `${artifact}.building-${process.pid}`;
    mkdirSync(output, { recursive: true });
    try {
      run(bindgen, [join(target, 'wasm32-unknown-unknown/wasm/tlsn_wasm.wasm'), '--target', 'web', '--out-dir', output], { stdio: 'inherit' });
      const wasm = join(output, 'tlsn_wasm_bg.wasm'), optimized = `${wasm}.optimized`;
      run(optimizer, [wasm, '-o', optimized, '-O'], { stdio: 'inherit' }); renameSync(optimized, wasm);
      const snippets = filesBelow(output).filter(name => /^snippets\/[^/]+\/js\/spawn\.js$/.test(name));
      assert.equal(snippets.length, 1, 'WASM_SPAWN_SNIPPET_COUNT');
      const snippet = join(output, snippets[0]), original = readFileSync(snippet, 'utf8');
      const patched = patchSpawnSnippet(original);
      writeFileSync(snippet, patched); writeFileSync(join(output, 'spawn.js'), patched);
      cpSync(join(core, 'crates/wasm/README.md'), join(output, 'README.md'));
      writeFileSync(join(output, 'package.json'), JSON.stringify({ name: 'tlsn-wasm', version: pins.packageVersion,
        type: 'module', main: 'tlsn_wasm.js', types: 'tlsn_wasm.d.ts', license: 'MIT OR Apache-2.0',
        files: ['tlsn_wasm_bg.wasm', 'tlsn_wasm.js', 'tlsn_wasm.d.ts', 'tlsn_wasm_bg.wasm.d.ts', 'spawn.js', 'snippets/'],
        sideEffects: ['./snippets/*'] }, null, 2) + '\n');
      const files = Object.fromEntries(filesBelow(output).map(name => [name, hashFile(join(output, name))]));
      writeFileSync(join(output, manifestName), JSON.stringify({ schema: 1, inputHash, inputs,
        compiler: compiler.trim(), clangVersion, bindgen: pins.bindgen.version, optimizer: pins.optimizer.version, files }, null, 2) + '\n');
      validatePackage(output, inputHash, pins);
      run('bash', [join(coreKit, 'prepare-core.sh'), core]);
      assert.equal(hashFile(join(core, 'Cargo.lock')), pins.cargoLockSha256, 'WASM_CARGO_LOCK_CHANGED');
      renameSync(output, artifact);
    } finally { rmSync(output, { recursive: true, force: true }); }
  }
  stagePackage(artifact, upstream, inputHash, pins);
  console.log(`Pinned TLSNotary WASM staged; provenance ${inputHash}.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const locked = process.argv[2] === '--locked';
  const upstream = resolve(process.argv[locked ? 3 : 2] || '');
  assert(process.argv.length === (locked ? 4 : 3), 'usage: build-wasm.mjs /path/to/upstream');
  const cache = resolve(process.env.TLSN_WASM_CACHE || join(homedir(), '.cache/gcp-private-proof/wasm'));
  mkdirSync(cache, { recursive: true });
  if (locked) await buildAndStage(upstream, cache);
  else run('flock', [join(cache, 'build.lock'), process.execPath, fileURLToPath(import.meta.url), '--locked', upstream], { stdio: 'inherit' });
}
