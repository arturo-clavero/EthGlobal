import { sanitizeAzurePrivateResult } from '../azure-private/browser-result.mjs';

export const AZURE_PRIVATE_ROUTE_TTL_MS = 60 * 60 * 1000;
export interface AzurePrivateRoute { tabId: number; createdAt: number; pageProgress?: boolean; azurePrivate?: boolean; azureOrigin?: string; azureAttempt?: { proofId: string; pluginSha256: string; nonceMac: string } }
interface Sender { id?: string; url?: string; tab?: unknown }

export function liveAzurePrivateRoute(
  requestId: unknown, sender: Sender, routes: Map<string, AzurePrivateRoute>,
  deps: { extensionId: string; offscreenUrl: string; now: number },
) {
  if (typeof requestId !== 'string' || sender.id !== deps.extensionId || sender.tab !== undefined || sender.url !== deps.offscreenUrl) return null;
  const route = routes.get(requestId);
  if (!route?.azurePrivate || !route.pageProgress || !Number.isInteger(route.tabId) || route.tabId < 0) return null;
  if (deps.now - route.createdAt >= AZURE_PRIVATE_ROUTE_TTL_MS || deps.now < route.createdAt) {
    routes.delete(requestId); return null;
  }
  return route;
}

/** A single-use route minted by autoApprovalFor, never restored from message data. */
export function takeAzurePrivateCompletion(
  raw: unknown, sender: Sender, routes: Map<string, AzurePrivateRoute>,
  deps: { extensionId: string; offscreenUrl: string; now: number },
) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const message = raw as Record<string, unknown>;
  if (message.type !== 'AZURE_PRIVATE_COMPLETE' || typeof message.requestId !== 'string') return null;
  const route = liveAzurePrivateRoute(message.requestId, sender, routes, deps);
  if (!route) return null;
  routes.delete(message.requestId);
  let response: { success: true; result: ReturnType<typeof sanitizeAzurePrivateResult> } | { success: false; error: string };
  try {
    const keys = Reflect.ownKeys(message);
    if (message.success === true && keys.length === 4 && ['type', 'requestId', 'success', 'result'].every(key => keys.includes(key))) {
      response = { success: true, result: sanitizeAzurePrivateResult(message.result) };
    } else throw new Error();
  } catch { response = { success: false, error: 'AZURE_PRIVATE_PROVING_FAILED' }; }
  return { requestId: message.requestId, tabId: route.tabId, response };
}

interface PageSender { id?: string; frameId?: number; origin?: string; url?: string; tab?: { id?: number } }

/** Only the original top-frame embedding page may inspect or cancel this route. */
function azurePrivatePageRoute(raw: unknown, sender: PageSender,
  routes: Map<string, AzurePrivateRoute>, extensionId: string) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const value = raw as Record<string, unknown>;
  if (Reflect.ownKeys(value).length !== 4 || !['CANCEL_AZURE_PRIVATE', 'AZURE_PRIVATE_PAGE_HEARTBEAT'].includes(value.type as string) ||
      typeof value.requestId !== 'string' || typeof value.pluginSha256 !== 'string' || typeof value.nonceMac !== 'string') return null;
  const route = routes.get(value.requestId);
  let origin;
  try { origin = sender.origin || new URL(sender.url || '').origin; } catch { return null; }
  if (!route?.azurePrivate || !route.pageProgress || !route.azureAttempt || sender.id !== extensionId || sender.frameId !== 0 ||
      sender.tab?.id !== route.tabId || origin !== route.azureOrigin || route.azureAttempt.proofId !== value.requestId ||
      route.azureAttempt.pluginSha256 !== value.pluginSha256 || route.azureAttempt.nonceMac !== value.nonceMac) return null;
  return { requestId: value.requestId, route };
}

export function liveAzurePrivatePageRoute(raw: unknown, sender: PageSender,
  routes: Map<string, AzurePrivateRoute>, extensionId: string, now: number) {
  if ((raw as { type?: unknown })?.type !== 'AZURE_PRIVATE_PAGE_HEARTBEAT') return false;
  const found = azurePrivatePageRoute(raw, sender, routes, extensionId);
  return !!found && Number.isFinite(now) && Number.isFinite(found.route.createdAt) &&
    now >= found.route.createdAt && now - found.route.createdAt < AZURE_PRIVATE_ROUTE_TTL_MS;
}

export function takeAzurePrivateCancellation(raw: unknown, sender: PageSender,
  routes: Map<string, AzurePrivateRoute>, extensionId: string) {
  if ((raw as { type?: unknown })?.type !== 'CANCEL_AZURE_PRIVATE') return null;
  const found = azurePrivatePageRoute(raw, sender, routes, extensionId);
  if (!found) return null;
  routes.delete(found.requestId);
  return found.requestId;
}

export function dropAzurePrivatePageRoutes(tabId: number, routes: Map<string, AzurePrivateRoute>) {
  for (const [id, route] of routes) if (route.azurePrivate && route.tabId === tabId) routes.delete(id);
}
