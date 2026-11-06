import { awsConsoleSession, awsPrivateCredentials } from '../aws-private/browser-client.mjs';
import { livePrivateRoute, type GcpPrivateRoute } from './gcpPrivateCompletion';

/** A one-use capture from this approved run's managed tab, never a page-supplied credential tuple. */
export async function readAwsPrivateCapture(raw: unknown, sender: { id?: string; url?: string; tab?: unknown },
  routes: Map<string, GcpPrivateRoute>, deps: {
    extensionId: string; offscreenUrl: string; now(): number;
    window(id: number): { tabId: number; headers: Array<{ id: string }> } | undefined;
    tab(id: number): Promise<{ url?: string; windowId?: number }>;
    send(id: number, message: unknown): Promise<unknown>;
  }) {
  try {
    const message = raw as { type?: unknown; requestId?: unknown; windowId?: unknown; captureId?: unknown };
    if (!message || Object.keys(message).length !== 4 || message.type !== 'AWS_PRIVATE_CREDENTIALS' ||
        typeof message.requestId !== 'string' || !Number.isInteger(message.windowId) ||
        typeof message.captureId !== 'string' || !/^[A-Za-z0-9._-]{1,256}$/.test(message.captureId)) throw new Error();
    const route = livePrivateRoute(message.requestId, sender, routes, { ...deps, now: deps.now() }, 'aws');
    if (!route || route.windowId !== message.windowId || route.credentialsUsed) throw new Error();
    route.credentialsUsed = true;
    const windowId = message.windowId as number, managed = deps.window(windowId);
    if (!managed) throw new Error();
    const capture = awsConsoleSession(managed.headers.find(header => header.id === message.captureId), deps.now());
    const origin = new URL(capture.url).origin;
    const check = async () => {
      const tab = await deps.tab(managed.tabId);
      if (livePrivateRoute(message.requestId, sender, routes, { ...deps, now: deps.now() }, 'aws') !== route ||
          deps.window(windowId) !== managed || tab.windowId !== windowId || !tab.url || new URL(tab.url).origin !== origin) throw new Error();
      const latest = [...managed.headers].reverse().find(header => {
        try { awsConsoleSession(header, deps.now()); return true; } catch { return false; }
      });
      const current = awsConsoleSession(latest, deps.now());
      if (current.url !== capture.url || ['cookie', 'x-csrf-token', 'origin'].some(key => current.headers[key] !== capture.headers[key])) throw new Error();
    };
    await check();
    const value = await deps.send(managed.tabId, { type: 'AWS_PRIVATE_CONSOLE_CREDENTIALS', url: capture.url, csrfToken: capture.headers['x-csrf-token'] });
    try {
      await check();
      return { credentials: awsPrivateCredentials(value, deps.now()), ...(capture.accountId ? { accountId: capture.accountId } : {}) };
    } finally {
      if (value && typeof value === 'object') for (const key of Object.keys(value)) (value as Record<string, unknown>)[key] = '';
    }
  } catch { throw new Error('AWS_PRIVATE_COLLECTION_FAILED'); }
}
