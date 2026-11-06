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
  /** `account` = the wrong account is signed in (the window waits for a switch). */
  status: 'running' | 'done' | 'busy' | 'failed' | 'account';
  /** Steps finished so far. */
  index: number;
  /** Steps planned; 0 = not known in advance. */
  total: number;
  /** The step just finished, e.g. A2 or P3 (upper-case id). */
  step?: string;
  /** `account` only: the signed-in account name (nothing else about the account). */
  login?: string;
}

const STATUSES: ReadonlySet<string> = new Set(['running', 'done', 'busy', 'failed', 'account']);
/** The signed-in account name, as the plugin reads it. */
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
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
  // `account` carries only the signed-in login (no counts, no step); every other status never has a login.
  if (out.status === 'account') {
    if (typeof r.login !== 'string' || !LOGIN_RE.test(r.login)) return null;
    return { method: out.method, status: 'account', index: 0, total: 0, login: r.login };
  }
  if (typeof r.step === 'string' && STEP_RE.test(r.step)) out.step = r.step;
  return out;
}
