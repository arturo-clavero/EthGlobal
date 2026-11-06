import { canonicalizeHandler } from '@tlsn/plugin-sdk';
import type { Commit, RevealOutput } from 'tlsn-wasm';
import type { RevealRangeWithHandler } from './ProveManager';
import { proofBundle, sanitizeGcpPrivateResult, type GcpPrivateProof } from './gcpPrivateResult';

type Opening = { start: number; end: number; hash: Uint8Array; blinder: Uint8Array };
export interface GcpPrivateSession {
  sessionId: string; serverName: string; step: string; proofId: string; nonceMac: string;
}
export interface GcpPrivateRevealPlan {
  sentRangesWithHandlers: RevealRangeWithHandler[];
  recvRangesWithHandlers: RevealRangeWithHandler[];
}
interface ComputedRanges extends GcpPrivateRevealPlan {
  sentRanges: Array<{ start: number; end: number }>;
  recvRanges: Array<{ start: number; end: number }>;
  commit: Commit | undefined;
}
export interface GcpPrivateWitness extends GcpPrivateSession {
  sent: Uint8Array; recv: Uint8Array;
  selections: { sent: readonly RevealRangeWithHandler[]; recv: readonly RevealRangeWithHandler[] };
  openings: { sent: Opening[]; recv: Opening[] };
}
export type { GcpPrivateCircuitId, GcpPrivateProof } from './gcpPrivateResult';

/** Extension-compiled code only. Never populate this capability from a runtime message. */
export interface GcpPrivateProofModule {
  /** Drop local project/identity state and terminate any active proof worker. */
  clear?(): void;
  /** Copies are erased when this callback settles. The module owns parsing/policy semantics. */
  getRevealPlan?(session: Readonly<GcpPrivateSession>, transcripts: { sent: Uint8Array; recv: Uint8Array }):
    GcpPrivateRevealPlan | Promise<GcpPrivateRevealPlan>;
  /** Local query construction only; the final circuit must authenticate this account again. */
  identityEmail(witness: Readonly<GcpPrivateWitness>): string;
  /** The adapter MUST terminate its proving worker on abort; a Promise timeout cannot stop CPU work. */
  prove(witnesses: readonly GcpPrivateWitness[], signal: AbortSignal): Promise<{ proofs: GcpPrivateProof[] }>;
}

const STEPS = ['identity', 'groups:0', 'groups:1', 'groups:2', 'groups:3', 'groups:4'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX = /^[0-9a-f]{64}$/;
const PARTS = ['START_LINE', 'PROTOCOL', 'METHOD', 'REQUEST_TARGET', 'STATUS_CODE', 'HEADERS', 'BODY', 'ALL'];
// Local proving can exceed nine minutes; keep its limit inside the 13-minute route.
// The 15-minute nonce still bounds freshness, including server-side verification.
const PROVE_TIMEOUT_MS = 11 * 60 * 1000;
type AcceptStage = 'PRECONDITION' | 'OPENINGS' | 'RESULT_SHAPE' | 'REVEAL_MATCH' |
  'OPENING_LOOKUP' | 'COMMITMENT_MATCH' | 'IDENTITY';
export function gcpPrivateDiagnostic(code: 'ACCEPT_ENTERED' | 'ACCEPTED' | `ACCEPT_FAILED_${AcceptStage}` |
  'EXECUTE_FAILED' | 'HEARTBEAT_NOT_OK' | 'HEARTBEAT_REJECTED'): void {
  try { console.debug(`GCP_PRIVATE_${code}`); } catch { /* Diagnostics must not affect cleanup or the original error. */ }
}
function fail(): never { throw new Error('GCP_PRIVATE_PROOF_INVALID'); }
const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

function validateOpening(value: { hash: number[]; blinder: number[] } | undefined): asserts value is { hash: number[]; blinder: number[] } {
  if (!value || value.hash?.length !== 32 || value.blinder?.length !== 16 ||
      ![...value.hash, ...value.blinder].every(n => Number.isInteger(n) && n >= 0 && n <= 255)) fail();
}
export function clearGcpOpenings(openings: RevealOutput | undefined): void {
  for (const item of [...(openings?.sent ?? []), ...(openings?.recv ?? [])]) {
    item.hash.fill(0); item.blinder.fill(0);
  }
}

/** Labels are metadata, not evidence of HTTP or JSON semantics. Require complete byte coverage. */
function partition(ranges: RevealRangeWithHandler[], length: number, direction: 'SENT' | 'RECV') {
  if (!Number.isSafeInteger(length) || length < 1 || length > 16384 ||
      !Array.isArray(ranges) || !ranges.length || ranges.length > 256) fail();
  let end = 0;
  const result = ranges.map(range => {
    if (!range || !Number.isSafeInteger(range.start) || !Number.isSafeInteger(range.end) ||
        range.start !== end || range.end <= range.start || range.end > length) fail();
    const handler = canonicalizeHandler(range.handler);
    if (handler.type !== direction || !PARTS.includes(handler.part) ||
        (handler.part === 'ALL' && (range.start !== 0 || range.end !== length)) ||
        (handler.action.kind !== 'REVEAL' &&
          (handler.action.kind !== 'HASH' || handler.action.algorithm !== 'SHA256'))) fail();
    end = range.end;
    // Drop caller-supplied params/labels. Native validates bytes, not their semantic meaning.
    const action = handler.action.kind === 'HASH'
      ? { kind: 'HASH' as const, algorithm: 'SHA256' as const } : { kind: 'REVEAL' as const };
    return Object.freeze({ start: range.start, end: range.end,
      handler: Object.freeze({ type: direction, part: handler.part, action: Object.freeze(action) }) });
  });
  if (end !== length) fail();
  return Object.freeze(result) as unknown as RevealRangeWithHandler[];
}
function derive(plan: GcpPrivateRevealPlan, sent: Uint8Array, recv: Uint8Array): ComputedRanges {
  const sentHandlers = partition(plan.sentRangesWithHandlers, sent.length, 'SENT');
  const recvHandlers = partition(plan.recvRangesWithHandlers, recv.length, 'RECV');
  const reveal = (ranges: RevealRangeWithHandler[]) => ranges.filter(r => canonicalizeHandler(r.handler).action.kind === 'REVEAL')
    .map(({ start, end }) => ({ start, end }));
  const commit = (ranges: RevealRangeWithHandler[]) => ranges.filter(r => canonicalizeHandler(r.handler).action.kind === 'HASH')
    .map(({ start, end }) => ({ start, end, algorithm: 'SHA256' as const }));
  return { sentRangesWithHandlers: sentHandlers, recvRangesWithHandlers: recvHandlers,
    sentRanges: reveal(sentHandlers), recvRanges: reveal(recvHandlers),
    commit: { sent: commit(sentHandlers), recv: commit(recvHandlers) } };
}

/** No getter, serialization, storage, or message handler exposes this execution's witness. */
export class GcpPrivateWitnessRun {
  private readonly witnesses: GcpPrivateWitness[] = [];
  private nonceMac: string | undefined;
  private activeHost: string | undefined;
  private activeSessionId: string | undefined;
  private selection: ComputedRanges | undefined;
  private planning: { sent: Uint8Array; recv: Uint8Array } | undefined;
  private closed = false;
  private proving: AbortController | undefined;

  constructor(private readonly run: Record<string, string>, requestId: string | null,
    private readonly module: GcpPrivateProofModule) {
    if (run._autoApproved !== '1' || run.method !== 'GCP_WORK' || run.mode !== 'Proxy' ||
        !HEX.test(run.pluginSha256 ?? '') || !UUID.test(run.proofId ?? '') || requestId !== run.proofId) fail();
    this.run = { ...run };
  }
  begin(session: Record<string, string>, serverName: string, relay: boolean): void {
    const expected = STEPS[this.witnesses.length];
    if (this.closed || this.activeHost || !expected || relay || session.mode !== 'Proxy' ||
        session.proofId !== this.run.proofId || session.method !== 'GCP_WORK' ||
        session.pluginSha256 !== this.run.pluginSha256 || session.step !== expected ||
        serverName !== (expected === 'identity' ? 'accounts.google.com' : 'logging.clients6.google.com') ||
        !/^[A-Za-z0-9_-]{43}$/.test(session.nonceMac ?? '') ||
        (this.nonceMac !== undefined && session.nonceMac !== this.nonceMac)) fail();
    this.nonceMac = session.nonceMac;
    this.activeHost = serverName;
  }
  async selectRanges(sessionId: string | null, serverName: string, sent: Uint8Array, recv: Uint8Array,
    fallback: () => ComputedRanges | Promise<ComputedRanges>): Promise<ComputedRanges> {
    if (this.closed || this.selection || this.activeSessionId || !sessionId || !UUID.test(sessionId) ||
        this.activeHost !== serverName || this.witnesses.some(w => w.sessionId === sessionId) ||
        !sent.length || !recv.length || sent.length > 16384 || recv.length > 16384) fail();
    this.activeSessionId = sessionId;
    let ranges: ComputedRanges;
    if (this.module.getRevealPlan) {
      const copies = { sent: sent.slice(), recv: recv.slice() };
      this.planning = copies;
      try {
        const plan = await this.module.getRevealPlan(Object.freeze({ sessionId, serverName,
          step: STEPS[this.witnesses.length], proofId: this.run.proofId, nonceMac: this.nonceMac! }), copies);
        if (this.closed) fail();
        ranges = derive(plan, sent, recv);
      } finally {
        copies.sent.fill(0); copies.recv.fill(0);
        if (this.planning === copies) this.planning = undefined;
      }
    } else ranges = await fallback();
    this.checkRanges(sent, recv, ranges);
    return this.selection!;
  }
  checkRanges(sent: Uint8Array, recv: Uint8Array, ranges: ComputedRanges): void {
    if (this.closed || this.selection) fail();
    const checked = derive(ranges, sent, recv);
    if (JSON.stringify(ranges.sentRanges) !== JSON.stringify(checked.sentRanges) ||
        JSON.stringify(ranges.recvRanges) !== JSON.stringify(checked.recvRanges) ||
        JSON.stringify(ranges.commit ?? { sent: [], recv: [] }) !== JSON.stringify(checked.commit)) fail();
    if (!this.module.getRevealPlan) {
      for (const handlers of [checked.sentRangesWithHandlers, checked.recvRangesWithHandlers]) {
        if (handlers.length !== 1 || handlers[0].handler.part !== 'ALL' ||
            canonicalizeHandler(handlers[0].handler).action.kind !== 'HASH') fail();
      }
    }
    this.selection = checked;
  }
  async accept(sessionId: string | null, serverName: string, sent: Uint8Array, recv: Uint8Array,
    openings: RevealOutput, response: { results: unknown[] } | null) {
    let stage: AcceptStage = 'PRECONDITION';
    gcpPrivateDiagnostic('ACCEPT_ENTERED');
    try {
      const selection = this.selection;
      if (this.closed || !selection || this.activeHost !== serverName || !sessionId || !UUID.test(sessionId) ||
          (this.activeSessionId !== undefined && this.activeSessionId !== sessionId) ||
          this.witnesses.some(w => w.sessionId === sessionId) || !Array.isArray(response?.results) ||
          response.results.length !== selection.sentRangesWithHandlers.length + selection.recvRangesWithHandlers.length) fail();
      const witness: GcpPrivateWitness = Object.freeze({ sessionId, serverName, step: STEPS[this.witnesses.length],
        proofId: this.run.proofId, nonceMac: this.nonceMac!, sent: sent.slice(), recv: recv.slice(),
        selections: { sent: selection.sentRangesWithHandlers, recv: selection.recvRangesWithHandlers },
        openings: { sent: [] as Opening[], recv: [] as Opening[] } });
      // Own every copy before an asynchronous check or local parser can fail.
      this.witnesses.push(witness);
      const results: Array<{ type: string; part: string; action: unknown; value: string }> = [];
      let index = 0;
      for (const [direction, bytes, ranges, source, held] of [
        ['SENT', witness.sent, witness.selections.sent, openings.sent, witness.openings.sent],
        ['RECV', witness.recv, witness.selections.recv, openings.recv, witness.openings.recv],
      ] as const) {
        stage = 'OPENINGS';
        if (!Array.isArray(source) || source.length !== ranges.filter(r => canonicalizeHandler(r.handler).action.kind === 'HASH').length ||
            ranges[ranges.length - 1].end !== bytes.length) fail();
        const byDigest = new Map<string, Opening>();
        for (const opening of source) {
          validateOpening(opening);
          const copy = { start: 0, end: 0, hash: Uint8Array.from(opening.hash), blinder: Uint8Array.from(opening.blinder) };
          held.push(copy);
          const digest = hex(copy.hash);
          if (byDigest.has(digest)) fail();
          byDigest.set(digest, copy);
        }
        // Native session_completed omits config. It returns process_ranges(sent), then recv,
        // in submitted config order. The server must independently validate webhook config/ranges.
        for (const range of ranges) {
          stage = 'RESULT_SHAPE';
          const handler = canonicalizeHandler(range.handler);
          const result = response.results[index++] as { type?: unknown; part?: unknown;
            action?: { kind?: unknown; algorithm?: unknown }; value?: unknown } | null;
          if (!result || result.type !== direction || result.part !== handler.part ||
              result.action?.kind !== handler.action.kind || typeof result.value !== 'string') fail();
          if (handler.action.kind === 'REVEAL') {
            stage = 'REVEAL_MATCH';
            if (result.action.algorithm !== undefined || result.value !==
                new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(range.start, range.end))) fail();
          } else {
            stage = 'OPENING_LOOKUP';
            if (result.action.algorithm !== 'SHA256' || !HEX.test(result.value)) fail();
            const opening = byDigest.get(result.value);
            if (!opening) fail();
            opening.start = range.start; opening.end = range.end;
            stage = 'COMMITMENT_MATCH';
            const preimage = new Uint8Array(range.end - range.start + 16);
            try {
              preimage.set(bytes.subarray(range.start, range.end)); preimage.set(opening.blinder, range.end - range.start);
              const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', preimage.buffer));
              const matches = hex(digest) === result.value; digest.fill(0);
              if (this.closed || !matches) fail();
            } finally { preimage.fill(0); }
            byDigest.delete(result.value);
          }
          results.push({ type: direction, part: handler.part, action: handler.action.kind === 'HASH'
            ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' }, value: result.value });
        }
        stage = 'OPENINGS';
        if (byDigest.size) fail();
        held.sort((a, b) => a.start - b.start);
      }
      this.activeHost = undefined; this.activeSessionId = undefined; this.selection = undefined;
      if (witness.step !== 'identity') { gcpPrivateDiagnostic('ACCEPTED'); return { results }; }
      stage = 'IDENTITY';
      const email = this.module.identityEmail(witness);
      if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
          email.toLowerCase().endsWith('.gserviceaccount.com')) fail();
      gcpPrivateDiagnostic('ACCEPTED');
      return { results, privateAccountEmail: email };
    } catch (error) {
      gcpPrivateDiagnostic(`ACCEPT_FAILED_${stage}`);
      throw error;
    }
  }
  async finish() {
    if (this.closed || this.activeHost || this.witnesses.length !== STEPS.length) fail();
    this.closed = true;
    const controller = new AbortController();
    this.proving = controller;
    let onAbort: () => void = () => {};
    const cancelled = new Promise<never>((_, reject) => {
      onAbort = () => reject(new Error('GCP_PRIVATE_PROOF_INVALID'));
      controller.signal.addEventListener('abort', onAbort, { once: true });
    });
    const timer = setTimeout(() => controller.abort(), PROVE_TIMEOUT_MS);
    const sessionIds = this.witnesses.map(w => w.sessionId);
    try {
      const result = await Promise.race([this.module.prove(this.witnesses, controller.signal), cancelled]);
      if (controller.signal.aborted) fail();
      const envelope = { kind: 'GCP_PRIVATE_RESULT' as const, version: 1 as const, proofs: proofBundle(result),
        sessionIds };
      // All accepted strings and generated keys are ASCII, so JSON length equals UTF-8 bytes.
      if (JSON.stringify(envelope).length > 4 * 1024 * 1024) fail();
      return sanitizeGcpPrivateResult(envelope);
    } finally {
      clearTimeout(timer); controller.signal.removeEventListener('abort', onAbort); this.clear();
    }
  }
  clear(): void {
    this.closed = true;
    this.proving?.abort(); this.proving = undefined;
    if (this.planning) {
      this.planning.sent.fill(0); this.planning.recv.fill(0); this.planning = undefined;
    }
    for (const witness of this.witnesses) {
      witness.sent.fill(0); witness.recv.fill(0);
      for (const opening of [...witness.openings.sent, ...witness.openings.recv]) {
        opening.hash.fill(0); opening.blinder.fill(0);
      }
    }
    this.witnesses.length = 0;
    try { this.module.clear?.(); } catch { /* Cleanup must never expose module errors. */ }
    this.nonceMac = undefined; this.activeHost = undefined; this.activeSessionId = undefined; this.selection = undefined;
  }
}
