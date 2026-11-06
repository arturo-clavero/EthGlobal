import { sanitizeGcpPrivateResult } from '../offscreen/gcpPrivateResult';

export const GCP_PRIVATE_ROUTE_TTL_MS = 13 * 60 * 1000;
export interface GcpPrivateRoute { tabId: number; createdAt: number; pageProgress?: boolean; gcpPrivate?: boolean }
interface Sender { id?: string; url?: string; tab?: unknown }

export function liveGcpPrivateRoute(
  requestId: unknown, sender: Sender, routes: Map<string, GcpPrivateRoute>,
  deps: { extensionId: string; offscreenUrl: string; now: number },
) {
  if (typeof requestId !== 'string' || sender.id !== deps.extensionId || sender.tab !== undefined || sender.url !== deps.offscreenUrl) return null;
  const route = routes.get(requestId);
  if (!route?.gcpPrivate || !route.pageProgress || !Number.isInteger(route.tabId) || route.tabId < 0) return null;
  if (deps.now - route.createdAt >= GCP_PRIVATE_ROUTE_TTL_MS || deps.now < route.createdAt) {
    routes.delete(requestId); return null;
  }
  return route;
}

/** A single-use route minted by autoApprovalFor, never restored from message data. */
export function takeGcpPrivateCompletion(
  raw: unknown, sender: Sender, routes: Map<string, GcpPrivateRoute>,
  deps: { extensionId: string; offscreenUrl: string; now: number },
) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const message = raw as Record<string, unknown>;
  if (message.type !== 'GCP_PRIVATE_COMPLETE' || typeof message.requestId !== 'string') return null;
  const route = liveGcpPrivateRoute(message.requestId, sender, routes, deps);
  if (!route) return null;
  routes.delete(message.requestId);
  let response: { success: true; result: ReturnType<typeof sanitizeGcpPrivateResult> } | { success: false; error: string };
  try {
    const keys = Reflect.ownKeys(message);
    if (message.success === true && keys.length === 4 && ['type', 'requestId', 'success', 'result'].every(key => keys.includes(key))) {
      response = { success: true, result: sanitizeGcpPrivateResult(message.result) };
    } else throw new Error();
  } catch { response = { success: false, error: 'GCP_PRIVATE_PROVING_FAILED' }; }
  return { requestId: message.requestId, tabId: route.tabId, response };
}
