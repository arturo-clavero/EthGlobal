import { createHash, webcrypto } from 'node:crypto';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { RevealOutput } from 'tlsn-wasm';
import { GcpPrivateWitnessRun, PrivateWitnessRun, clearGcpOpenings } from '../../src/offscreen/gcpPrivateWitness';
import type { GcpPrivateProofModule, GcpPrivateWitness, GcpPrivateRevealPlan, GcpPrivateProof } from '../../src/offscreen/gcpPrivateWitness';

vi.mock('@tlsn/plugin-sdk', () => ({ canonicalizeHandler: (handler: unknown) => handler }));
beforeEach(() => { vi.stubGlobal('crypto', webcrypto); vi.spyOn(console, 'debug').mockImplementation(() => {}); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const proofId = '11111111-1111-4111-8111-111111111111';
const data = { _autoApproved: '1', method: 'GCP_WORK', mode: 'Proxy', proofId,
  pluginSha256: 'a'.repeat(64), nonceMac: 'b'.repeat(43) };
const bytes = () => new TextEncoder().encode('aBcDe');
const handler = (type: 'SENT' | 'RECV', kind: 'HASH' | 'REVEAL' = 'HASH', part: 'ALL' | 'BODY' = 'ALL') => ({
  type, part, action: kind === 'HASH' ? { kind, algorithm: 'SHA256' as const } : { kind },
});
const fullPlan = (): GcpPrivateRevealPlan => ({
  sentRangesWithHandlers: [{ start: 0, end: 5, handler: handler('SENT') }],
  recvRangesWithHandlers: [{ start: 0, end: 5, handler: handler('RECV') }],
});
const selectivePlan = (): GcpPrivateRevealPlan => ({
  sentRangesWithHandlers: [
    { start: 0, end: 1, handler: handler('SENT', 'REVEAL', 'BODY') },
    { start: 1, end: 2, handler: handler('SENT', 'HASH', 'BODY') },
    { start: 2, end: 3, handler: handler('SENT', 'REVEAL', 'BODY') },
    { start: 3, end: 4, handler: handler('SENT', 'HASH', 'BODY') },
    { start: 4, end: 5, handler: handler('SENT', 'REVEAL', 'BODY') },
  ], recvRangesWithHandlers: fullPlan().recvRangesWithHandlers,
});
const ranges = (plan = fullPlan()) => {
  const reveal = (list: typeof plan.sentRangesWithHandlers) => list.filter(r => r.handler.action !== 'REVEAL' && r.handler.action.kind === 'REVEAL')
    .map(({ start, end }) => ({ start, end }));
  const hashes = (list: typeof plan.sentRangesWithHandlers) => list.filter(r => r.handler.action !== 'REVEAL' && r.handler.action.kind === 'HASH')
    .map(({ start, end }) => ({ start, end, algorithm: 'SHA256' as const }));
  return { ...plan, sentRanges: reveal(plan.sentRangesWithHandlers), recvRanges: reveal(plan.recvRangesWithHandlers),
    commit: { sent: hashes(plan.sentRangesWithHandlers), recv: hashes(plan.recvRangesWithHandlers) } };
};
function receipt(plan = fullPlan(), transcript = bytes()) {
  const openings: RevealOutput = { sent: [], recv: [] };
  const results = [...plan.sentRangesWithHandlers, ...plan.recvRangesWithHandlers].map((range, index) => {
    let value = new TextDecoder().decode(transcript.subarray(range.start, range.end));
    if (range.handler.action !== 'REVEAL' && range.handler.action.kind === 'HASH') {
      const blinder = Array(16).fill(index + 1);
      const hash = createHash('sha256').update(transcript.subarray(range.start, range.end)).update(Uint8Array.from(blinder)).digest();
      openings[range.handler.type === 'SENT' ? 'sent' : 'recv'].push({ hash: Array.from(hash), blinder });
      value = hash.toString('hex');
    }
    return { ...range.handler, value };
  });
  return { openings, response: { results } };
}
const bundle = (): { proofs: GcpPrivateProof[] } => ({ proofs: [{ circuitId: 'atom-v1', proof: 'AQID', publicInputs: ['0x01', '2'] }] });
const module = (): GcpPrivateProofModule => ({ identityEmail: () => 'candidate@example.test',
  prove: vi.fn().mockResolvedValue(bundle()) });
it('clears the pinned module capability when capture is cancelled', async () => {
  const local = module(); local.clear = vi.fn();
  const run = new GcpPrivateWitnessRun(data, proofId, local);
  await session(run, 0);
  run.clear();
  expect(local.clear).toHaveBeenCalledOnce();
});
async function prepare(run: GcpPrivateWitnessRun, index = 0) {
  const host = index === 0 ? 'accounts.google.com' : 'logging.clients6.google.com';
  const id = `22222222-2222-4222-8222-22222222222${index}`;
  run.begin({ ...data, step: index === 0 ? 'identity' : `groups:${index - 1}` }, host, false);
  const chosen = await run.selectRanges(id, host, bytes(), bytes(), () => ranges());
  return { id, host, chosen };
}
async function session(run: GcpPrivateWitnessRun, index: number) {
  const { id, host, chosen } = await prepare(run, index);
  const native = receipt(chosen);
  return run.accept(id, host, bytes(), bytes(), native.openings, native.response);
}
const buffers = (w: GcpPrivateWitness) => [w.sent, w.recv, ...[...w.openings.sent, ...w.openings.recv].flatMap(o => [o.hash, o.blinder])];

describe('compiled provider policy uses the existing private byte owner', () => {
  const runData = { ...data, method: 'AZURE_WORK_PRIVATE' };
  const host = 'graph.microsoft.com';
  const id = '33333333-3333-4333-8333-333333333333';
  const policy = () => ({ method: 'AZURE_WORK_PRIVATE' as const, nonceMac: data.nonceMac,
    steps: [{ step: 'identity', host }], proveTimeoutMs: 25,
    finish: vi.fn((result: unknown, sessionIds: string[]) => ({ result, sessionIds })) });
  const capture = async (run: PrivateWitnessRun) => {
    run.begin({ ...runData, step: 'identity' }, host, false);
    const chosen = await run.selectRanges(id, host, bytes(), bytes(), () => ranges());
    const native = receipt(chosen);
    return run.accept(id, host, bytes(), bytes(), native.openings, native.response);
  };
  it('requires the compiled method, request ID, nonce, step and host', async () => {
    const local = { prove: vi.fn() };
    expect(() => new PrivateWitnessRun(data, proofId, local, policy())).toThrow();
    expect(() => new PrivateWitnessRun(runData, 'other', local, policy())).toThrow();
    const run = new PrivateWitnessRun(runData, proofId, local, policy());
    for (const change of [{ method: 'GCP_WORK' }, { nonceMac: 'c'.repeat(43) },
      { proofId: 'other' }, { pluginSha256: 'c'.repeat(64) }, { step: 'groups:0' }]) {
      expect(() => run.begin({ ...runData, step: 'identity', ...change }, host, false)).toThrow();
    }
    expect(() => run.begin({ ...runData, step: 'identity' }, 'accounts.google.com', false)).toThrow();
    expect(() => run.begin({ ...runData, step: 'identity' }, host, true)).toThrow();
    await expect(run.finish()).rejects.toThrow();
    run.clear();
    expect(local.prove).not.toHaveBeenCalled();
  });
  it('passes exact session IDs to the policy without requiring GCP identity output', async () => {
    let held: Uint8Array[] = [];
    const local = { prove: vi.fn(async (w: readonly GcpPrivateWitness[]) => {
      held = w.flatMap(buffers); return { testProof: true };
    }), clear: vi.fn() };
    const selected = policy(), run = new PrivateWitnessRun(runData, proofId, local, selected);
    expect(await capture(run)).toEqual(receipt().response);
    expect(await run.finish()).toEqual({ result: { testProof: true }, sessionIds: [id] });
    expect(selected.finish).toHaveBeenCalledWith({ testProof: true }, [id]);
    expect(held.length).toBeGreaterThan(0);
    expect(held.every(value => value.every(byte => byte === 0))).toBe(true);
    expect(local.clear).toHaveBeenCalled();
    await expect(capture(run)).rejects.toThrow();
  });
  it('rejects substituted native openings under a different compiled policy', async () => {
    const local = { prove: vi.fn(), clear: vi.fn() };
    const run = new PrivateWitnessRun(runData, proofId, local, policy());
    run.begin({ ...runData, step: 'identity' }, host, false);
    const chosen = await run.selectRanges(id, host, bytes(), bytes(), () => ranges());
    const native = receipt(chosen); native.openings.sent[0].blinder[0] ^= 1;
    await expect(run.accept(id, host, bytes(), bytes(), native.openings, native.response)).rejects.toThrow();
    run.clear();
    expect(local.prove).not.toHaveBeenCalled();
  });
  it('enforces the compiled timeout, aborts proving and erases retained copies', async () => {
    vi.useFakeTimers();
    let held: Uint8Array[] = [], signal: AbortSignal | undefined;
    const local = { prove: (w: readonly GcpPrivateWitness[], s: AbortSignal) => {
      held = w.flatMap(buffers); signal = s; return new Promise(() => {});
    }, clear: vi.fn() };
    const selected = policy(), run = new PrivateWitnessRun(runData, proofId, local, selected);
    await capture(run);
    const result = expect(run.finish()).rejects.toThrow();
    await vi.advanceTimersByTimeAsync(25); await result;
    expect(signal?.aborted).toBe(true);
    expect(held.every(value => value.every(byte => byte === 0))).toBe(true);
    expect(local.clear).toHaveBeenCalled();
    expect(selected.finish).not.toHaveBeenCalled();
  });
});

describe('GCP private witness stays in its offscreen execution', () => {
  it('requires the pinned, approved GCP run and matching request ID', () => {
    for (const change of [{ _autoApproved: '0' }, { method: 'AWS_WORK' }, { mode: 'Mpc' }, { pluginSha256: '' }])
      expect(() => new GcpPrivateWitnessRun({ ...data, ...change }, proofId, module())).toThrow();
    expect(() => new GcpPrivateWitnessRun(data, 'other', module())).toThrow();
  });
  it('preserves full-hash runs, returns only provisional email and sanitized final proof, and erases copies', async () => {
    let held: Uint8Array[] = [];
    const local = module();
    local.prove = async witnesses => { held = witnesses.flatMap(buffers); return bundle(); };
    const run = new GcpPrivateWitnessRun(data, proofId, local);
    expect(await session(run, 0)).toEqual({ ...receipt().response, privateAccountEmail: 'candidate@example.test' });
    for (let i = 1; i < 6; i++) expect(await session(run, i)).toEqual(receipt().response);
    const result = await run.finish();
    expect(Object.keys(result).sort()).toEqual(['kind', 'proofs', 'sessionIds', 'version']);
    expect(result.sessionIds).toHaveLength(6);
    expect(held.length).toBeGreaterThan(0);
    expect(held.every(array => array.every(n => n === 0))).toBe(true);
    expect(JSON.stringify(result)).not.toContain('candidate@example.test');
    expect(vi.mocked(console.debug).mock.calls).toEqual(Array.from({ length: 6 }, () =>
      [['GCP_PRIVATE_ACCEPT_ENTERED'], ['GCP_PRIVATE_ACCEPTED']]).flat());
    await expect(session(run, 0)).rejects.toThrow();
  });
  it('rejects reveals, partial hashes and oversized transcripts on the default path', () => {
    const run = new GcpPrivateWitnessRun(data, proofId, module());
    expect(() => run.checkRanges(bytes(), bytes(), ranges(selectivePlan()))).toThrow();
    const partial = ranges(); partial.commit.sent[0].end = 2;
    expect(() => run.checkRanges(bytes(), bytes(), partial)).toThrow();
    expect(() => run.checkRanges(new Uint8Array(16385), bytes(), ranges())).toThrow();
  });
  it('rejects cross-run sessions, wrong hosts, concurrent sessions, and missing batches', async () => {
    const run = new GcpPrivateWitnessRun(data, proofId, module());
    expect(() => run.begin({ ...data, proofId: 'other', step: 'identity' }, 'accounts.google.com', false)).toThrow();
    expect(() => run.begin({ ...data, step: 'identity' }, 'evil.test', false)).toThrow();
    const native = await prepare(run);
    expect(() => run.begin({ ...data, step: 'identity' }, native.host, false)).toThrow();
    const r = receipt();
    await expect(run.accept(proofId, native.host, bytes(), bytes(), r.openings, r.response)).rejects.toThrow();
    expect(vi.mocked(console.debug).mock.calls).toEqual([
      ['GCP_PRIVATE_ACCEPT_ENTERED'], ['GCP_PRIVATE_ACCEPT_FAILED_PRECONDITION'],
    ]);
    await expect(run.finish()).rejects.toThrow(); run.clear();
  });
  it('freezes copied selective plans and maps reordered openings by native digest', async () => {
    let planCopies: Uint8Array[] = [], witness: GcpPrivateWitness | undefined;
    const plan = selectivePlan(), local = module();
    local.getRevealPlan = (_, copies) => { planCopies = [copies.sent, copies.recv]; return plan; };
    local.identityEmail = w => { witness = w; return 'candidate@example.test'; };
    const run = new GcpPrivateWitnessRun(data, proofId, local);
    const { id, host, chosen } = await prepare(run);
    expect(planCopies.every(b => b.every(n => n === 0))).toBe(true);
    plan.sentRangesWithHandlers[0].end = 5;
    expect(chosen.sentRangesWithHandlers[0].end).toBe(1);
    expect(Object.isFrozen(chosen.sentRangesWithHandlers[0].handler.action)).toBe(true);
    const native = receipt(chosen); native.openings.sent.reverse();
    await run.accept(id, host, bytes(), bytes(), native.openings, native.response);
    expect(witness!.openings.sent.map(o => [o.start, o.end])).toEqual([[1, 2], [3, 4]]);
    const held = buffers(witness!); run.clear(); clearGcpOpenings(native.openings);
    expect(held.every(b => b.every(n => n === 0))).toBe(true);
    expect([...native.openings.sent, ...native.openings.recv].every(o => o.blinder.every(n => n === 0))).toBe(true);
  });
  it('rejects gaps, overlaps, empty, duplicate, excessive, wrongly directed and wrongly hashed ranges before disclosure', async () => {
    const changes: Array<(p: GcpPrivateRevealPlan) => void> = [
      p => { p.sentRangesWithHandlers[1].start = 2; },
      p => { p.sentRangesWithHandlers[1].start = 0; },
      p => { p.sentRangesWithHandlers[1].end = 1; },
      p => { p.sentRangesWithHandlers.push(p.sentRangesWithHandlers[0]); },
      p => { p.sentRangesWithHandlers = Array(257).fill(p.sentRangesWithHandlers[0]); },
      p => { p.sentRangesWithHandlers[1].handler.type = 'RECV'; },
      p => { p.sentRangesWithHandlers[1].handler.action = { kind: 'HASH', algorithm: 'BLAKE3' }; },
    ];
    for (const change of changes) {
      const plan = selectivePlan(); change(plan);
      const run = new GcpPrivateWitnessRun(data, proofId, { ...module(), getRevealPlan: () => plan });
      await expect(prepare(run)).rejects.toThrow(); run.clear();
    }
  });
  it('rejects wrong blinder, wrong plaintext, result order, hash, direction, algorithm and missing/duplicate openings', async () => {
    const changes: Array<[string, (r: ReturnType<typeof receipt>) => void]> = [
      ['COMMITMENT_MATCH', r => { r.openings.sent[0].blinder[0] ^= 1; }],
      ['REVEAL_MATCH', r => { r.response.results[0].value = 'wrong'; }],
      ['COMMITMENT_MATCH', r => { [r.response.results[1], r.response.results[3]] = [r.response.results[3], r.response.results[1]]; }],
      ['OPENING_LOOKUP', r => { r.response.results[1].value = 'ff'.repeat(32); }],
      ['RESULT_SHAPE', r => { r.response.results[1].type = 'RECV'; }],
      ['OPENING_LOOKUP', r => { r.response.results[1].action = { kind: 'HASH', algorithm: 'BLAKE3' } as never; }],
      ['OPENINGS', r => { r.openings.sent.pop(); }],
      ['OPENINGS', r => { r.openings.sent[1] = r.openings.sent[0]; }],
    ];
    for (const [stage, change] of changes) {
      vi.mocked(console.debug).mockClear();
      const run = new GcpPrivateWitnessRun(data, proofId, { ...module(), getRevealPlan: selectivePlan });
      const { id, host, chosen } = await prepare(run), native = receipt(chosen); change(native);
      await expect(run.accept(id, host, bytes(), bytes(), native.openings, native.response)).rejects.toThrow();
      expect(vi.mocked(console.debug).mock.calls).toEqual([
        ['GCP_PRIVATE_ACCEPT_ENTERED'], [`GCP_PRIVATE_ACCEPT_FAILED_${stage}`],
      ]);
      run.clear(); clearGcpOpenings(native.openings);
    }
    const run = new GcpPrivateWitnessRun(data, proofId, { ...module(), getRevealPlan: selectivePlan });
    const { id, host, chosen } = await prepare(run), native = receipt(chosen), changed = bytes(); changed[1] ^= 1;
    await expect(run.accept(id, host, changed, bytes(), native.openings, native.response)).rejects.toThrow(); run.clear();
  });
  it('never inspects a caught value and preserves the original identity failure', async () => {
    const thrown = new Proxy({}, { get() { throw new Error('private error property'); } });
    const run = new GcpPrivateWitnessRun(data, proofId, { ...module(), identityEmail() { throw thrown; } });
    const { id, host, chosen } = await prepare(run), native = receipt(chosen);
    await expect(run.accept(id, host, bytes(), bytes(), native.openings, native.response)).rejects.toBe(thrown);
    expect(vi.mocked(console.debug).mock.calls).toEqual([
      ['GCP_PRIVATE_ACCEPT_ENTERED'], ['GCP_PRIVATE_ACCEPT_FAILED_IDENTITY'],
    ]);
    run.clear(); clearGcpOpenings(native.openings);
  });
  it('does not let failed diagnostic logging change acceptance or the original error', async () => {
    vi.mocked(console.debug).mockImplementation(() => { throw new Error('console unavailable'); });
    const run = new GcpPrivateWitnessRun(data, proofId, module());
    expect(await session(run, 0)).toHaveProperty('privateAccountEmail', 'candidate@example.test');
    run.clear();
    const thrown = new Error('private identity detail');
    const failing = new GcpPrivateWitnessRun(data, proofId, { ...module(), identityEmail() { throw thrown; } });
    await expect(session(failing, 0)).rejects.toBe(thrown);
    failing.clear();
  });
  it('erases witness copies after local proof failure', async () => {
    let held: Uint8Array[] = [];
    const local = module();
    local.prove = async witnesses => { held = witnesses.flatMap(buffers); throw new Error('private witness details'); };
    const run = new GcpPrivateWitnessRun(data, proofId, local);
    for (let i = 0; i < 6; i++) await session(run, i);
    await expect(run.finish()).rejects.toThrow();
    expect(held.every(b => b.every(n => n === 0))).toBe(true);
  });
  it('aborts and erases after the proving deadline, and safely ignores late completion', async () => {
    let held: Uint8Array[] = [], signal: AbortSignal | undefined, resolve!: (value: { proofs: GcpPrivateProof[] }) => void;
    const local = module();
    local.prove = (witnesses, abort) => { held = witnesses.flatMap(buffers); signal = abort; return new Promise(r => { resolve = r; }); };
    const run = new GcpPrivateWitnessRun(data, proofId, local);
    for (let i = 0; i < 6; i++) await session(run, i);
    vi.useFakeTimers();
    const completed = expect(run.finish()).rejects.toThrow('GCP_PRIVATE_PROOF_INVALID');
    await vi.advanceTimersByTimeAsync(540000);
    expect(signal!.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(119999);
    expect(signal!.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1); await completed;
    expect(signal!.aborted).toBe(true);
    expect(held.every(b => b.every(n => n === 0))).toBe(true);
    resolve(bundle()); await Promise.resolve();
  });
  it('clear cancels a pending proof and zeroes witnesses immediately', async () => {
    let held: Uint8Array[] = [], signal: AbortSignal | undefined;
    const local = module(); local.prove = (w, s) => { held = w.flatMap(buffers); signal = s; return new Promise(() => {}); };
    const run = new GcpPrivateWitnessRun(data, proofId, local);
    for (let i = 0; i < 6; i++) await session(run, i);
    const completed = expect(run.finish()).rejects.toThrow(); run.clear(); await completed;
    expect(signal!.aborted).toBe(true);
    expect(held.every(b => b.every(n => n === 0))).toBe(true);
  });
  it('accepts registry circuits and exact per-proof/count bounds while copying output fields', async () => {
    const source = bundle();
    source.proofs = ['header-v1', 'atom-v1', 'timestamps-v1', 'identity-scope-v1', 'query-scope-v1']
      .map(circuitId => ({ ...source.proofs[0], circuitId: circuitId as GcpPrivateProof['circuitId'] }));
    source.proofs[0] = { ...source.proofs[0], proof: 'AAAA'.repeat(8192), publicInputs: Array(1024).fill('1') };
    const local = module(); local.prove = async () => source;
    const run = new GcpPrivateWitnessRun(data, proofId, local);
    for (let i = 0; i < 6; i++) await session(run, i);
    const result = await run.finish();
    expect(result.proofs).toEqual(source.proofs);
    source.proofs[0].proof = 'PRIVATE'; source.proofs[0].publicInputs[0] = 'PRIVATE';
    expect(result.proofs[0].proof).toHaveLength(32768);
    expect(result.proofs[0].publicInputs[0]).toBe('1');
    const maxCount = module(); maxCount.prove = async () => ({ proofs: Array.from({ length: 128 }, () => bundle().proofs[0]) });
    const many = new GcpPrivateWitnessRun(data, proofId, maxCount);
    for (let i = 0; i < 6; i++) await session(many, i);
    expect((await many.finish()).proofs).toHaveLength(128);
  });
  it('rejects malformed/oversized bundles, unknown circuits, supplied keys and extra private fields', async () => {
    const proof = () => bundle().proofs[0];
    const invalid: unknown[] = [
      { proofs: [] }, { proofs: new Array(1) }, { proofs: Array(129).fill(proof()) },
      { proofs: [{ ...proof(), circuitId: 'caller-chosen-circuit' }] },
      { proofs: [{ ...proof(), proof: '' }] }, { proofs: [{ ...proof(), proof: 'AAAA'.repeat(8193) }] },
      { proofs: [{ ...proof(), proof: 'raw witness' }] }, { proofs: [{ ...proof(), proof: 'ああああ' }] },
      { proofs: [{ ...proof(), publicInputs: [] }] }, { proofs: [{ ...proof(), publicInputs: new Array(1) }] },
      { proofs: [{ ...proof(), publicInputs: Array(1025).fill('1') }] },
      { proofs: [{ ...proof(), publicInputs: ['1', 'candidate@example.test'] }] },
      { proofs: [{ ...proof(), publicInputs: ['1'.repeat(79)] }] },
      { proofs: [{ ...proof(), publicInputs: ['0x' + 'a'.repeat(65)] }] },
      { proofs: [{ ...proof(), publicInputs: ['١'] }] },
      { proofs: [proof()], privateWitness: 'PRIVATE' },
      { proofs: [{ ...proof(), privateWitness: 'PRIVATE' }] },
      { proofs: [{ ...proof(), verificationKey: 'CALLER_KEY' }] },
      { proofs: [Object.defineProperty(proof(), 'secret', { value: 'PRIVATE', enumerable: false })] },
      { proofs: [Object.assign(proof(), { [Symbol('secret')]: 'PRIVATE' })] },
      // Each proof passes its own cap, but framing makes the complete envelope exceed 4MiB.
      { proofs: Array.from({ length: 128 }, () => ({ ...proof(), proof: 'AAAA'.repeat(8192) })) },
    ];
    for (const value of invalid) {
      let held: Uint8Array[] = [];
      const local = module();
      local.prove = async w => { held = w.flatMap(buffers); return value as Awaited<ReturnType<GcpPrivateProofModule['prove']>>; };
      const run = new GcpPrivateWitnessRun(data, proofId, local);
      for (let i = 0; i < 6; i++) await session(run, i);
      await expect(run.finish()).rejects.toThrow('GCP_PRIVATE_PROOF_INVALID');
      expect(held.every(b => b.every(n => n === 0))).toBe(true);
    }
  });
});
