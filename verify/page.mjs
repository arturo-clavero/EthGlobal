// DOM glue for index.html. All checks live in verify.mjs.
import { describeClaim, parseDropped, verifyCommitment } from './verify.mjs';

const $ = id => document.getElementById(id);
const loadJson = async path => {
  const response = await fetch(new URL(path, import.meta.url));
  if (!response.ok) throw new Error(`${path}: ${response.status}`);
  return response.json();
};
const text = (tag, value, className) => Object.assign(document.createElement(tag), { textContent: value, className: className ?? '' });

const STATUS = {
  'verified': ['✓ Verified', 'ok'],
  'signature-only': ['✓ Signed by the verifier (public proof bundle not available)', 'warn'],
  'failed': ['✗ Does not verify', 'bad'],
  'not-found': ['✗ No attestation found for this commitment', 'bad'],
};

function render(result) {
  const box = $('result');
  box.replaceChildren();
  const [label, className] = STATUS[result.status] ?? STATUS.failed;
  box.append(text('div', label, `status ${className}`));
  if (result.claim && result.status !== 'failed') box.append(text('p', describeClaim(result), 'claim'));
  const details = document.createElement('details');
  details.append(text('summary', 'Details'));
  const checks = document.createElement('ul');
  for (const check of result.checks ?? []) checks.append(text('li', `${check.ok ? '✓' : '✗'} ${check.label}`));
  details.append(text('p', 'Checked in this browser:'), checks);
  const trust = document.createElement('ul');
  for (const line of result.restsOnSignature ?? []) trust.append(text('li', line));
  details.append(text('p', 'Taken from the verifier’s signature:'), trust);
  if (result.verifier) details.append(text('p', `Verifier key: ${result.verifier}`));
  if (result.humanCheck) details.append(text('p', `One-human check: ${result.humanCheck.credential}, ${result.humanCheck.scope}`));
  if (result.commitment) { const p = text('p', 'Commitment: '); p.append(text('code', result.commitment)); details.append(p); }
  box.append(details);
  box.hidden = false;
}

async function run(commitment, dropped = {}) {
  $('result').hidden = false;
  $('result').replaceChildren(text('div', 'Checking…', 'status'));
  try {
    const [keys, registry, policy] = await Promise.all([loadJson('./keys.json'), import('../crops/pin-registry/read.mjs'),
      import('../private-proof/gcp/policy.mjs').catch(() => ({}))]);
    render(await verifyCommitment({ commitment: commitment || undefined, dropped, keys, registry, loadJson, gcpBatches: policy.BATCHES }));
  } catch (error) {
    $('result').replaceChildren(text('div', `✗ ${error.message}`, 'status bad'));
  }
}

async function readFile(file) {
  try { await run($('commitment').value.trim().toLowerCase(), parseDropped(await file.text())); }
  catch (error) { $('result').hidden = false; $('result').replaceChildren(text('div', `✗ ${error.message}`, 'status bad')); }
}

$('form').addEventListener('submit', event => { event.preventDefault(); run($('commitment').value.trim().toLowerCase()); });
$('file').addEventListener('change', event => { if (event.target.files[0]) readFile(event.target.files[0]); });
const drop = $('drop');
drop.addEventListener('dragover', event => { event.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', event => {
  event.preventDefault(); drop.classList.remove('over');
  if (event.dataTransfer.files[0]) readFile(event.dataTransfer.files[0]);
});

const initial = new URLSearchParams(location.search).get('commitment');
if (initial) { $('commitment').value = initial; run(initial.trim().toLowerCase()); }
