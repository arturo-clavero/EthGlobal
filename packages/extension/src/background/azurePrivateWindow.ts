interface Sender { id?: string; url?: string; tab?: unknown }
interface Tab { id?: number; windowId?: number }

/** Offscreen retains this pair only for the popup its compiled Azure run opened. */
export async function closeAzurePrivateWindow(raw: unknown, sender: Sender, deps: {
  extensionId: string; offscreenUrl: string;
  getTab: (id: number) => Promise<Tab>;
  getWindow: (id: number) => Promise<{ id?: number; type?: string; tabs?: Tab[] }>;
  removeTab: (id: number) => Promise<unknown>;
}) {
  try {
    if (sender.id !== deps.extensionId || sender.url !== deps.offscreenUrl || sender.tab !== undefined ||
        !raw || typeof raw !== 'object' || Array.isArray(raw)) return false;
    const value = raw as Record<string, unknown>;
    if (Reflect.ownKeys(value).length !== 4 || value.type !== 'CLOSE_AZURE_PRIVATE_WINDOW' ||
        typeof value.requestId !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value.requestId) ||
        !Number.isSafeInteger(value.windowId) || (value.windowId as number) < 0 ||
        !Number.isSafeInteger(value.tabId) || (value.tabId as number) < 0) return false;
    const windowId = value.windowId as number, tabId = value.tabId as number;
    const tab = await deps.getTab(tabId), window = await deps.getWindow(windowId);
    if (tab.id !== tabId || tab.windowId !== windowId || window.id !== windowId || window.type !== 'popup' ||
        window.tabs?.length !== 1 || window.tabs[0].id !== tabId || window.tabs[0].windowId !== windowId) return false;
    await deps.removeTab(tabId);
    return true;
  } catch { return false; }
}
