/**
 * Auto-approval of allowlisted plugins on allowed origins.
 * EXEC_CODE skips the stock approval prompt only when
 * BOTH hold:
 *   1. the request comes from our content script in the top frame of a tab on a
 *      allowed origin (constants/productOrigins.ts, build-time list), and
 *   2. the code is one of the trusted plugins (constants/pluginAllowlist.ts, build-time
 *      sha256 + layout of each built bundle).
 * Then the plugin runs as if the user had chosen "allow all data sharing this
 * session" (what the embedding page asks for anyway; pressing Continue on the embedding page is the
 * consent). Any other origin or code, and any error, keeps the stock prompt.
 * Nothing about what is proved or revealed changes.
 *
 * This is also the only switch for the reveal review ("Approve Reveal to
 * Verifier", straight to proving): Background
 * writes the mode into sessionData._approvalMode after the page's sessionData,
 * and SessionManager.onProve skips the review only for 'all-session'. Same
 * reveal ranges either way; the plugin permission check still applies
 * (tests/offscreen/straightToProving.test.ts).
 */
import type { ApprovalMode } from '../types/messages';
import { isProductOrigin, PRODUCT_ORIGINS } from '../constants/productOrigins';
import {
  matchAllowedPlugin,
  PLUGIN_ALLOWLIST,
  type AllowedPlugin,
} from '../constants/pluginAllowlist';

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

export interface AutoApproval {
  mode: ApprovalMode;
  plugin: AllowedPlugin;
  origin: string;
}

/** Auto-approval for this EXEC_CODE request, or null (= show the stock prompt). */
export async function autoApprovalFor(
  code: unknown,
  sender: ExecSender,
  extensionId: string,
  origins: readonly string[] = PRODUCT_ORIGINS,
  allowlist: readonly AllowedPlugin[] = PLUGIN_ALLOWLIST,
): Promise<AutoApproval | null> {
  try {
    const origin = senderProductOrigin(sender, extensionId, origins);
    if (!origin) return null;
    const plugin = await matchAllowedPlugin(code, allowlist);
    if (!plugin) return null;
    return { mode: 'all-session', plugin, origin };
  } catch {
    return null;
  }
}
