import { createHash, webcrypto } from 'node:crypto';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AwsPrivateWitnessRun, AWS_PRIVATE_TIMEOUT_MS } from '../../src/offscreen/awsPrivateWitness';
import type { AwsPrivateModule } from '../../src/aws-private/browser-client.mjs';
import type { GcpPrivateWitness } from '../../src/offscreen/gcpPrivateWitness';

const proofId = '11111111-1111-4111-8111-111111111111';
const ids = ['abcdefab-cdef-4abc-8def-abcdefabcdef', '33333333-3333-4333-8333-333333333333'];
const runData = { _autoApproved: '1', method: 'AWS_ACCOUNT', mode: 'Proxy', proofId, pluginSha256: 'a'.repeat(64) };
const attempt = () => ({ proofId, pluginSha256: runData.pluginSha256, nonceMac: 'b'.repeat(43),
  identityService: 'iam' as const, region: 'us-east-1' as const, issuedAt: Date.now(), expiresAt: Date.now() + 600_000 });
const bytes = () => new TextEncoder().encode('PRIVATE_SENTINEL');
const plan = () => Object.fromEntries(['sent', 'recv'].map(direction => [`${direction}RangesWithHandlers`, [{
  start: 0, end: bytes().length, handler: { type: direction.toUpperCase(), part: 'ALL', action: { kind: 'HASH', algorithm: 'SHA256' } },
}]])) as ReturnType<AwsPrivateModule['getRevealPlan']>;
const bundle = () => ({ kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: [...ids], proofs:
  ['aws-identity-link-v1', 'aws-event-link-v1'].map((circuitId, index) => ({ circuitId, proof: 'AQID',
    publicInputs: Array(index === 0 ? 264 : 199).fill('0') })) });
const module = (): AwsPrivateModule => ({ getRevealPlan: vi.fn(plan), clear: vi.fn(), prove: vi.fn().mockResolvedValue(bundle()) });
const buffers = (w: GcpPrivateWitness) => [w.sent, w.recv, ...[...w.openings.sent, ...w.openings.recv].flatMap(o => [o.hash, o.blinder])];
const runs: AwsPrivateWitnessRun[] = [];
const create = (local = module(), context = attempt()) => {
  const run = new AwsPrivateWitnessRun(runData, proofId, context, local); runs.push(run); return run;
};
const session = (index: number) => ({ ...runData, nonceMac: 'b'.repeat(43), step: index === 0 ? 'identity' : 'E0' });
const host = (index: number) => index === 0 ? 'iam.amazonaws.com' : 'cloudtrail.us-east-1.amazonaws.com';
async function prepare(run: AwsPrivateWitnessRun, index = 0, id = ids[index]) {
  run.begin(session(index), host(index), false);
  await run.selectRanges(id, host(index), bytes(), bytes(), () => { throw new Error('Must use AWS planner'); });
  const blinder = Array(16).fill(1), hash = createHash('sha256').update(bytes()).update(Uint8Array.from(blinder)).digest();
  const openings = { sent: [{ hash: [...hash], blinder: [...blinder] }], recv: [{ hash: [...hash], blinder: [...blinder] }] };
  const response = { results: ['SENT', 'RECV'].map(type => ({ type, part: 'ALL', action: { kind: 'HASH', algorithm: 'SHA256' }, value: hash.toString('hex') })) };
  return { openings, response, accept: () => run.accept(id, host(index), bytes(), bytes(), openings, response) };
}
beforeEach(() => { vi.stubGlobal('crypto', webcrypto); });
afterEach(() => { for (const run of runs.splice(0)) run.clear(); vi.useRealTimers(); vi.unstubAllGlobals(); });

it('never collects after cancellation and erases a late credential response without fetching AWS', async () => {
  const run = create(), capture = vi.fn(); run.clear();
  await expect(run.collect(capture)).rejects.toThrow('AWS_PRIVATE_COLLECTION_FAILED');
  expect(capture).not.toHaveBeenCalled();
  const active = create(), fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  let resolve!: (value: any) => void;
  const pending = active.collect(() => new Promise(yes => { resolve = yes; }));
  active.clear();
  const credentials = { accessKeyId: 'ASIA' + 'A'.repeat(16), secretAccessKey: 's'.repeat(40),
    sessionToken: 't'.repeat(100), expiration: new Date(Date.now() + 3600000).toISOString() };
  resolve({ credentials });
  await expect(pending).rejects.toThrow('AWS_PRIVATE_COLLECTION_FAILED');
  expect(Object.values(credentials).every(value => value === '')).toBe(true);
  expect(fetch).not.toHaveBeenCalled();
});

it('binds the approved private method, plugin, request, nonce, IAM service and expiry', () => {
  for (const change of [{ _autoApproved: '0' }, { method: 'AWS_WORK_POC' }, { method: 'GCP_WORK' }, { mode: 'Mpc' }, { pluginSha256: 'c'.repeat(64) }])
    expect(() => new AwsPrivateWitnessRun({ ...runData, ...change }, proofId, attempt(), module())).toThrow();
  for (const change of [{ identityService: 'sts' }, { region: 'us-west-2' }, { nonceMac: 'c'.repeat(64) }, { expiresAt: Date.now() }])
    expect(() => new AwsPrivateWitnessRun(runData, proofId, { ...attempt(), ...change } as ReturnType<typeof attempt>, module())).toThrow();
  expect(() => new AwsPrivateWitnessRun(runData, 'wrong', attempt(), module())).toThrow();
  expect(() => new AwsPrivateWitnessRun(runData, proofId, attempt(), { ...module(), getRevealPlan: undefined } as never)).toThrow();
});

it('accepts exactly identity then E0 and returns only the closed AWS bundle, clearing retained bytes', async () => {
  const local = module(); let held: Uint8Array[] = [];
  local.prove = vi.fn(async witnesses => { held = witnesses.flatMap(buffers); return bundle(); });
  const run = create(local);
  expect(Object.keys(await (await prepare(run)).accept())).toEqual(['results']);
  await (await prepare(run, 1)).accept();
  const result = await run.finish();
  expect(result).toEqual(bundle()); expect(JSON.stringify(result)).not.toContain('PRIVATE_SENTINEL');
  expect(held.length).toBeGreaterThan(0); expect(held.every(b => b.every(n => n === 0))).toBe(true);
  expect(local.clear).toHaveBeenCalledOnce();
  await expect(run.finish()).rejects.toThrow();
});

it('rejects wrong hosts, nonce, legacy steps, relay, missing sessions and UUID case aliases', async () => {
  for (const change of [{ step: 'E0' }, { step: ids[1] }, { nonceMac: 'c'.repeat(43) }])
    expect(() => create().begin({ ...session(0), ...change }, host(0), false)).toThrow();
  expect(() => create().begin(session(0), 'accounts.google.com', false)).toThrow();
  expect(() => create().begin(session(0), host(0), true)).toThrow();
  await expect(create().finish()).rejects.toThrow();
  const run = create(); await (await prepare(run)).accept();
  await expect(prepare(run, 1, ids[0].toUpperCase())).rejects.toThrow();
});

it('rejects altered native openings and results before any private proof is generated', async () => {
  for (const alter of [
    (native: Awaited<ReturnType<typeof prepare>>) => { native.openings.sent[0].blinder[0] ^= 1; },
    (native: Awaited<ReturnType<typeof prepare>>) => { native.openings.sent.push(native.openings.sent[0]); },
    (native: Awaited<ReturnType<typeof prepare>>) => { native.response.results[0].value = 'a'.repeat(64); },
  ]) {
    const local = module(), run = create(local), native = await prepare(run); alter(native);
    await expect(native.accept()).rejects.toThrow(); expect(local.prove).not.toHaveBeenCalled(); run.clear();
  }
});

it('rejects transplanted session IDs and private fields from the compiled module', async () => {
  for (const result of [{ ...bundle(), sessionIds: [...ids].reverse() }, { ...bundle(), witness: 'PRIVATE_SENTINEL' }]) {
    const local = module(); local.prove = vi.fn().mockResolvedValue(result);
    const run = create(local); await (await prepare(run)).accept(); await (await prepare(run, 1)).accept();
    await expect(run.finish()).rejects.toThrow(); expect(local.clear).toHaveBeenCalledOnce();
  }
});

it('clears pending planner copies at the earlier attempt or absolute thirteen-minute expiry', async () => {
  vi.useFakeTimers();
  for (const lifetime of [1000, 900_000]) {
    const local = module(); let copies: { sent: Uint8Array; recv: Uint8Array } | undefined, resolve!: (value: ReturnType<typeof plan>) => void;
    local.getRevealPlan = vi.fn((_session, value) => { copies = value; return new Promise(yes => { resolve = yes; }); }) as never;
    const run = create(local, { ...attempt(), expiresAt: Date.now() + lifetime });
    run.begin(session(0), host(0), false);
    const pending = expect(run.selectRanges(ids[0], host(0), bytes(), bytes(), () => { throw new Error(); })).rejects.toThrow();
    if (lifetime > 300_000) {
      vi.advanceTimersByTime(300_000);
      expect(local.clear).not.toHaveBeenCalled();
      expect(copies!.sent.some(n => n !== 0)).toBe(true);
    }
    vi.advanceTimersByTime(Math.min(lifetime, AWS_PRIVATE_TIMEOUT_MS) - (lifetime > 300_000 ? 300_000 : 0));
    expect(copies!.sent.every(n => n === 0) && copies!.recv.every(n => n === 0)).toBe(true);
    expect(local.clear).toHaveBeenCalledOnce(); resolve(plan()); await pending;
  }
});

it('cancellation settles a hung module and erases its witness copies', async () => {
  const local = module(); let held: Uint8Array[] = [], signal!: AbortSignal;
  local.prove = vi.fn((witnesses, current) => { held = witnesses.flatMap(buffers); signal = current; return new Promise(() => {}); });
  const run = create(local); await (await prepare(run)).accept(); await (await prepare(run, 1)).accept();
  const pending = expect(run.finish()).rejects.toThrow(); run.clear(); await pending;
  expect(signal.aborted).toBe(true); expect(held.every(b => b.every(n => n === 0))).toBe(true);
});
