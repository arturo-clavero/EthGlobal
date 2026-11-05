/**
 * Page progress for auto-approved runs.
 * The embedding page can show where a run of a trusted plugin is (which check, step n of N), not only the plugin's
 * own window. The plugin calls `reportProgress({...})`; the extension forwards it to the page that started the run.
 *
 * Only for runs that autoApprovalFor() approved (an allowlisted plugin, top frame of an allowed-origin tab; decided in
 * the background, fail closed): the offscreen document adds the capability only then, the background forwards only
 * for such a run's own tab, and the content script posts only on an allowed origin. Anything else (stock prompt
 * runs, other origins, other plugins) has no `reportProgress` at all.
 *
 * What may travel is fixed here and checked at every hop: a method key, a status, two small counts and an optional
 * step id. No free text and nothing from a transcript: the plugin's done() result already goes to the same page, so
 * this channel can only carry less.
 */
export interface PageProgress {
  /** The check, e.g. EXAMPLE_WORK (upper-case key). */
  method: string;
  status: 'running' | 'done' | 'busy' | 'failed';
  /** Steps finished so far. */
  index: number;
  /** Steps planned; 0 = not known in advance. */
  total: number;
  /** The step just finished, e.g. A2 or P3 (upper-case id). */
  step?: string;
}

const STATUSES: ReadonlySet<string> = new Set(['running', 'done', 'busy', 'failed']);
const METHOD_RE = /^[A-Z][A-Z0-9_]{0,39}$/;
const STEP_RE = /^[A-Z][A-Z0-9_]{0,15}$/;
const count = (v: unknown): v is number =>
  typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 999;

/** The allowed fields of `raw`, checked; null when anything required is missing or malformed. */
export function sanitizePageProgress(raw: unknown): PageProgress | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.method !== 'string' || !METHOD_RE.test(r.method)) return null;
  if (typeof r.status !== 'string' || !STATUSES.has(r.status)) return null;
  if (!count(r.index) || !count(r.total)) return null;
  const out: PageProgress = {
    method: r.method,
    status: r.status as PageProgress['status'],
    index: r.index,
    total: r.total,
  };
  if (typeof r.step === 'string' && STEP_RE.test(r.step)) out.step = r.step;
  return out;
}
