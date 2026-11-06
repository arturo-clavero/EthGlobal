import { azureCatalogClaims, azureCatalogResult } from '../fixtures/azureCatalogResult';
import { describe, it, expect, vi } from 'vitest';
import { createAzurePrivateRun } from '../../src/offscreen/azurePrivateWitness';
vi.mock('@tlsn/plugin-sdk', () => ({ canonicalizeHandler: (h: unknown) => h }));
const now = Date.now(), attempt = { proofId: '11111111-1111-4111-8111-111111111111', pluginSha256: 'a'.repeat(64),
  nonceMac: 'b'.repeat(43), challenge: 'c'.repeat(64), cutoffMs: now, issuedAt: now, expiresAt: now + 3600000 };
const data = { _autoApproved: '1', proofId: attempt.proofId, pluginSha256: attempt.pluginSha256, method: 'AZURE_WORK_PRIVATE', mode: 'Proxy' };
const session = { ...data, nonceMac: attempt.nonceMac, step: 'identity' };
describe('Azure compiled private policy', () => {
  it('binds exact method, nonce and first host; no aliases or caller policies', () => {
    const module = { prove: vi.fn(), clear: vi.fn() };
    const run = createAzurePrivateRun(data, data.proofId, module, attempt);
    expect(() => run.begin(session, 'graph.microsoft.com', false)).not.toThrow(); run.clear(); expect(module.clear).toHaveBeenCalled();
    for (const changed of [{ ...data, method: 'AZURE_WORK' }, { ...data, method: 'GCP_WORK' }, { ...data, pluginSha256: 'd'.repeat(64) }]) {
      expect(() => createAzurePrivateRun(changed, data.proofId, module, attempt)).toThrow();
    }
    for (const [s, host] of [[{ ...session, nonceMac: 'e'.repeat(43) }, 'graph.microsoft.com'], [session, 'management.azure.com']] as const) {
      const next = createAzurePrivateRun(data, data.proofId, module, attempt);
      expect(() => next.begin(s, host, false)).toThrow(); next.clear();
    }
  });
  it('rejects mismatched attempt identity, expiry and extra fields', () => {
    const module = { prove: vi.fn(), clear: vi.fn() };
    for (const value of [{ ...attempt, proofId: '22222222-2222-4222-8222-222222222222' },
      { ...attempt, expiresAt: now - 1 }, { ...attempt, transcript: 'private' }]) {
      expect(() => createAzurePrivateRun(data, data.proofId, module, value)).toThrow();
    }
  });
});


// Exercise the real lifecycle and policy.finish; only the proof-producing module is synthetic.
async function capturedCatalogRun(result: unknown) {
  const range = (type: 'SENT' | 'RECV') => ({ start: 0, end: 1,
    handler: { type, part: 'ALL' as const, action: { kind: 'REVEAL' as const } } });
  const plan = { sentRangesWithHandlers: [range('SENT')], recvRangesWithHandlers: [range('RECV')] };
  const module = { getRevealPlan: () => plan, prove: vi.fn().mockResolvedValue(result), clear: vi.fn() };
  const run = createAzurePrivateRun(data, data.proofId, module, attempt);
  const ids = azureCatalogResult().sessionIds, bytes = new TextEncoder().encode('x');
  try {
    for (const [index, step] of ['identity', 'tenant', 'activity'].entries()) {
      const host = index === 0 ? 'graph.microsoft.com' : 'management.azure.com';
      run.begin({ ...session, step }, host, false);
      await run.selectRanges(ids[index], host, bytes, bytes, () => { throw new Error('Unexpected fallback'); });
      await run.accept(ids[index], host, bytes, bytes, { sent: [], recv: [] },
        { results: [range('SENT'), range('RECV')].map(({ handler }) => ({ ...handler, value: 'x' })) });
    }
    return { run, module };
  } catch (error) { run.clear(); throw error; }
}

describe('Azure catalog finish policy', () => {
  it.each(azureCatalogClaims)('returns %s with exact captured session order and rejects replay', async claim => {
    const result = azureCatalogResult(claim), { run, module } = await capturedCatalogRun(result);
    try {
      await expect(run.finish()).resolves.toEqual(result);
      await expect(run.finish()).rejects.toThrow('GCP_PRIVATE_PROOF_INVALID');
      expect(module.prove).toHaveBeenCalledOnce(); expect(module.clear).toHaveBeenCalledOnce();
    } finally { run.clear(); }
  });
  it.each(['AZURE_UNKNOWN_OPERATION', 'AZURE_WEB_APP_SLOT_SWAP'])('rejects unsupported claim %s at finish', async claim => {
    const { run, module } = await capturedCatalogRun({ ...azureCatalogResult(), claim });
    try {
      await expect(run.finish()).rejects.toThrow('AZURE_PRIVATE_BUNDLE_INVALID');
      expect(module.clear).toHaveBeenCalledOnce();
    } finally { run.clear(); }
  });
  it.each(['reordered', 'foreign', 'duplicate'])('rejects %s session IDs at finish', async change => {
    const result = azureCatalogResult('AZURE_ROLE_ASSIGNMENT_WRITE');
    if (change === 'reordered') [result.sessionIds[0], result.sessionIds[1]] = [result.sessionIds[1], result.sessionIds[0]];
    if (change === 'foreign') result.sessionIds[2] = '44444444-4444-4444-8444-444444444444';
    if (change === 'duplicate') result.sessionIds[2] = result.sessionIds[0];
    const { run, module } = await capturedCatalogRun(result);
    try {
      await expect(run.finish()).rejects.toThrow(change === 'duplicate' ? 'AZURE_PRIVATE_BUNDLE_INVALID' : 'AZURE_PRIVATE_RUN_INVALID');
      await expect(run.finish()).rejects.toThrow('GCP_PRIVATE_PROOF_INVALID');
      expect(module.prove).toHaveBeenCalledOnce(); expect(module.clear).toHaveBeenCalledOnce();
    } finally { run.clear(); }
  });
});
