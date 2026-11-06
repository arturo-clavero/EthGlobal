import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import test from 'node:test';

const here = fileURLToPath(new URL('.', import.meta.url));
const source = readFileSync(join(here, 'build.sh'), 'utf8');
// Execute the build's manifest snippets so packaging omissions fail without compiling WASM.
const snippet = start => {
  const at = source.indexOf(start);
  assert.notEqual(at, -1, `build.sh snippet not found: ${start}`);
  return source.slice(at, source.indexOf("\n'", at));
};
const build = snippet('const fs = require("fs"), crypto = require("crypto");\nconst p = ');
const guard = snippet('const m = JSON.parse(require("fs").readFileSync(process.env.OUT');
const consoleHosts = ['https://ap-southeast-2.console.aws.amazon.com/*', 'https://*.ap-southeast-2.console.aws.amazon.com/*'];

function fixture(t, env) {
  const out = mkdtempSync(join(tmpdir(), 'tlsn-manifest-'));
  t.after(() => rmSync(out, { recursive: true, force: true }));
  mkdirSync(join(out, 'extension'));
  const path = join(out, 'extension/manifest.json');
  writeFileSync(path, JSON.stringify({ icons: { 128: 'icon-128.png' },
    permissions: ['offscreen', 'webRequest', 'activeTab', 'tabs', 'windows'],
    content_scripts: [{ matches: ['<all_urls>'], js: ['contentScript.bundle.js'] }],
    web_accessible_resources: [{ matches: ['<all_urls>'], resources: ['content.bundle.js'] }] }));
  writeFileSync(join(out, 'extension/content.bundle.js'), 'const bridge = { version="0.1.0.1501" };');
  const context = { require: createRequire(import.meta.url), Buffer, console: { log() {} }, process: { env: {
    OUT: out, KEY_FILE: '', ICONS: '', PRODUCT_ORIGINS: 'https://app.example.com', EXT_VERSION: '0.1.0.1501',
    NAME: 'test', DESCRIPTION: 'test description', ...env,
  } } };
  runInNewContext(build, context);
  return { out, path, context, manifest: JSON.parse(readFileSync(path, 'utf8')) };
}

test('package captures AWS early and the production guard limits the regional wildcard', t => {
  const { path, context, manifest } = fixture(t, {});
  assert.equal(manifest.name, 'test');
  assert.equal(manifest.description, 'test description');
  assert.deepEqual(manifest.permissions, ['offscreen', 'webRequest']);
  assert.equal(manifest.content_scripts.length, 2);
  assert.deepEqual(manifest.content_scripts[1].matches, consoleHosts);
  assert.equal(manifest.content_scripts[1].run_at, 'document_start');
  assert.deepEqual(manifest.content_scripts[1].js, manifest.content_scripts[0].js);
  for (const host of [...consoleHosts, 'https://iam.amazonaws.com/*', 'https://cloudtrail.us-east-1.amazonaws.com/*'])
    assert(manifest.host_permissions.includes(host));
  for (const host of ['https://github.com/*', 'https://accounts.google.com/*', 'https://console.cloud.google.com/*',
    'https://cloudconsole-pa.clients6.google.com/*', 'https://logging.clients6.google.com/*', 'https://app.example.com/*'])
    assert(manifest.content_scripts[0].matches.includes(host));
  for (const host of consoleHosts) assert(manifest.web_accessible_resources[0].matches.includes(host));
  assert(!manifest.content_scripts.some(script => script.matches.some(host => host.includes('iam.amazonaws.com') || host.includes('cloudtrail.us-east-1.amazonaws.com'))));
  const check = value => {
    writeFileSync(path, JSON.stringify(value));
    runInNewContext(guard, { require: context.require, process: context.process });
  };
  check(manifest);
  for (const host of ['<all_urls>', '*://example.com/*', 'https://*.console.aws.amazon.com/*',
    'https://*.us-east-1.console.aws.amazon.com/*', 'http://localhost/*', 'http://127.0.0.1/*']) {
    for (const target of ['host', 'content', 'resource']) {
      const changed = structuredClone(manifest);
      (target === 'host' ? changed.host_permissions : target === 'content' ? changed.content_scripts[1].matches : changed.web_accessible_resources[0].matches).push(host);
      assert.throws(() => check(changed), /broad or loopback host access/);
    }
  }
});

test('without FORK_KEY_FILE the manifest has no key and upstream icons are kept', t => {
  const { out, manifest } = fixture(t, {});
  assert(!('key' in manifest));
  assert(!existsSync(join(out, 'extension-id.txt')));
  assert.deepEqual(manifest.icons, { 128: 'icon-128.png' });
});

test('FORK_KEY_FILE pins the key and the derived extension id; FORK_ICON_DIR replaces the icons', t => {
  const der = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' });
  const dir = mkdtempSync(join(tmpdir(), 'tlsn-key-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'key.pub.b64'), der.toString('base64') + '\n');
  const { out, manifest } = fixture(t, { KEY_FILE: join(dir, 'key.pub.b64'), ICONS: '1' });
  assert.equal(manifest.key, der.toString('base64'));
  assert.match(readFileSync(join(out, 'extension-id.txt'), 'utf8'), /^[a-p]{32}\n$/);
  assert.deepEqual(manifest.icons, { 16: 'icon-16.png', 48: 'icon-48.png', 128: 'icon-128.png' });
});

test('refuses a page bridge whose version differs from the manifest', t => {
  assert.throws(() => fixture(t, { EXT_VERSION: '0.1.0.1502' }), /page bridge version/);
});
