/**
 * Trusted plugins on allowed origins run
 * without the stock approval prompt. The page does not
 * send code at all; it asks for one of the extension's BUILT-IN plugins
 * by id + fingerprint (constants/builtinPlugins.ts). The background decides
 * from Chrome's `sender` (never from the page's message):
 *   1. the request comes from our content script in the TOP FRAME of a tab on a
 *      ALLOWED ORIGIN (constants/productOrigins.ts, build-time list);
 *   2. the plugin id is built in and the page's fingerprint is one of the
 *      packaged versions (else UNKNOWN_PLUGIN / PLUGIN_VERSION_MISMATCH: the
 *      page then asks the user to update the extension);
 *   3. the values are well-formed (URLs, params JSON, the three sessionData
 *      keys the page sends; constants/builtinPlugins.ts checkRunValues).
 * Then the run is auto-approved as "allow all data sharing this session"
 * (pressing Continue on the embedding page is the consent). Anything else is refused:
 * there is no prompt path and no page-supplied code path any more.
 *
 * This is also the only switch for the reveal review ("Approve Reveal to
 * Verifier", straight to proving), for page progress and for
 * navigate: the background writes `_approvalMode` and `_autoApproved`
 * into sessionData AFTER the page's keys (and the page may send only
 * mode/proofId/method), SessionManager reads them from the execution's
 * session data only. Same reveal ranges either way; the plugin permission
 * check still applies (tests/offscreen/straightToProving.test.ts).
 */
import type { ApprovalMode } from '../types/messages';
import { isProductOrigin, PRODUCT_ORIGINS } from '../constants/productOrigins';
import {
  BUILTIN_PLUGINS,
  checkRunValues,
  findBuiltInPlugin,
  type BuiltInPlugin,
  type RunValues,
} from '../constants/builtinPlugins';

/** The parts of a runtime.MessageSender the check reads. */
export interface ExecSender {
  id?: string;
  url?: string;
  origin?: string;
  frameId?: number;
  tab?: unknown;
}

/** The allowed origin of a top-frame content-script sender, or null. */
export function senderProductOrigin(
  sender: ExecSender,
  extensionId: string,
  origins: readonly string[] = PRODUCT_ORIGINS,
): string | null {
  if (!sender || sender.id !== extensionId || !sender.tab || sender.frameId !== 0) return null;
  let origin = sender.origin;
  if (!origin && sender.url) {
    try {
      origin = new URL(sender.url).origin;
    } catch {
      return null;
    }
  }
  return isProductOrigin(origin, origins) ? (origin as string) : null;
}

/**
 * The only sessionData keys a page may send. No `nonce`; each
 * prove() carries the attempt's `nonceMac` from the plugin params, and a raw nonce from the page is refused.
 */
const PAGE_SESSION_KEYS = ['mode', 'proofId', 'method'] as const;
const SESSION_VALUE = /^[A-Za-z0-9_.:-]{1,200}$/;
const REQUEST_ID = /^[A-Za-z0-9_.:-]{1,128}$/;

/** The page's sessionData, checked (only the three keys; mode Proxy or Mpc), or null. */
export function checkPageSessionData(raw: unknown): Record<string, string> | null {
  if (raw === undefined) return {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (!(PAGE_SESSION_KEYS as readonly string[]).includes(key)) return null;
    if (typeof value !== 'string' || !SESSION_VALUE.test(value)) return null;
    out[key] = value;
  }
  if (out.mode !== undefined && out.mode !== 'Proxy' && out.mode !== 'Mpc') return null;
  return out;
}

export type RefusalReason =
  | 'NOT_PRODUCT_PAGE'
  | 'UNKNOWN_PLUGIN'
  | 'PLUGIN_VERSION_MISMATCH'
  | 'BAD_VALUES';

export type AutoApproval =
  | {
      ok: true;
      mode: ApprovalMode;
      plugin: BuiltInPlugin;
      origin: string;
      values: RunValues;
      requestId: string | null;
      /** The page's checked keys only; offscreenSessionData() adds the background's. */
      sessionData: Record<string, string>;
    }
  | { ok: false; error: RefusalReason };

/** Auto-approval for this RUN_BUILTIN request, or the reason it is refused. */
export function autoApprovalFor(
  request: unknown,
  sender: ExecSender,
  extensionId: string,
  origins: readonly string[] = PRODUCT_ORIGINS,
  plugins: readonly BuiltInPlugin[] = BUILTIN_PLUGINS,
): AutoApproval {
  try {
    const origin = senderProductOrigin(sender, extensionId, origins);
    if (!origin) return { ok: false, error: 'NOT_PRODUCT_PAGE' };
    const r = (request ?? {}) as Record<string, unknown>;
    const found = findBuiltInPlugin(r.pluginId, r.fingerprint, plugins);
    if ('error' in found) return { ok: false, error: found.error };
    const values = checkRunValues(r);
    const sessionData = checkPageSessionData(r.sessionData);
    const requestId =
      r.requestId === undefined || r.requestId === null
        ? null
        : typeof r.requestId === 'string' && REQUEST_ID.test(r.requestId)
          ? r.requestId
          : undefined;
    if (!values || !sessionData || requestId === undefined)
      return { ok: false, error: 'BAD_VALUES' };
    return {
      ok: true,
      mode: 'all-session',
      plugin: found.plugin,
      origin,
      values,
      requestId,
      sessionData,
    };
  } catch {
    return { ok: false, error: 'BAD_VALUES' };
  }
}

/** What the background sends the offscreen document as sessionData: the page's keys, then ours. */
export function offscreenSessionData(
  approval: Extract<AutoApproval, { ok: true }>,
): Record<string, string> {
  return {
    ...approval.sessionData,
    _approvalMode: approval.mode,
    // SessionManager adds reportProgress/navigate only for '1'.
    _autoApproved: '1',
  };
}
