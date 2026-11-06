import { sanitizeGcpPrivateResult } from '../offscreen/gcpPrivateResult';
import { sanitizeAwsPrivateResult } from '../aws-private/browser-client.mjs';

export const GCP_PRIVATE_ROUTE_TTL_MS = 13 * 60 * 1000;
export const AWS_PRIVATE_ROUTE_TTL_MS = 13 * 60 * 1000;
export interface GcpPrivateRoute { tabId: number; createdAt: number; pageProgress?: boolean; gcpPrivate?: boolean; awsPrivate?: boolean; windowId?: number; credentialsUsed?: boolean }
interface Sender { id?: string; url?: string; tab?: unknown }

export function livePrivateRoute(
  requestId: unknown, sender: Sender, routes: Map<string, GcpPrivateRoute>,
  deps: { extensionId: string; offscreenUrl: string; now: number },
  provider: 'gcp' | 'aws' = 'gcp',
) {
  if (typeof requestId !== 'string' || sender.id !== deps.extensionId || sender.tab !== undefined || sender.url !== deps.offscreenUrl) return null;
  const route = routes.get(requestId);
  if (!route || (provider === 'aws' ? !route.awsPrivate || route.gcpPrivate : !route.gcpPrivate || route.awsPrivate) || !route.pageProgress || !Number.isInteger(route.tabId) || route.tabId < 0) return null;
  if (deps.now - route.createdAt >= (provider === 'aws' ? AWS_PRIVATE_ROUTE_TTL_MS : GCP_PRIVATE_ROUTE_TTL_MS) || deps.now < route.createdAt) {
    routes.delete(requestId); return null;
  }
  return route;
}

/** A single-use route minted by autoApprovalFor, never restored from message data. */
export function takePrivateCompletion(
  raw: unknown, sender: Sender, routes: Map<string, GcpPrivateRoute>,
  deps: { extensionId: string; offscreenUrl: string; now: number },
  provider: 'gcp' | 'aws' = 'gcp',
) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const message = raw as Record<string, unknown>;
  if (message.type !== (provider === 'aws' ? 'AWS_PRIVATE_COMPLETE' : 'GCP_PRIVATE_COMPLETE') || typeof message.requestId !== 'string') return null;
  const route = livePrivateRoute(message.requestId, sender, routes, deps, provider);
  if (!route) return null;
  routes.delete(message.requestId);
  let response: { success: true; result: ReturnType<typeof sanitizeGcpPrivateResult> | ReturnType<typeof sanitizeAwsPrivateResult> } | { success: false; error: string };
  try {
    const keys = Reflect.ownKeys(message);
    if (message.success === true && keys.length === 4 && ['type', 'requestId', 'success', 'result'].every(key => keys.includes(key))) {
      response = { success: true, result: (provider === 'aws' ? sanitizeAwsPrivateResult : sanitizeGcpPrivateResult)(message.result) };
    } else throw new Error();
  } catch { response = { success: false, error: provider === 'aws' ? 'AWS_PRIVATE_PROVING_FAILED' : 'GCP_PRIVATE_PROVING_FAILED' }; }
  return { requestId: message.requestId, tabId: route.tabId, response };
}

// Existing GCP callers retain their default policy and public names.
export { livePrivateRoute as liveGcpPrivateRoute, takePrivateCompletion as takeGcpPrivateCompletion };
