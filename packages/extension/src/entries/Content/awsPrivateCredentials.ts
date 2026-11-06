import { awsPrivateCredentials, readAwsPrivateResponse } from '../../aws-private/browser-client.mjs';

/** Runs only in the isolated content world on the exact Console origin; no window.postMessage response. */
export async function readConsoleCredentials(raw: unknown, sender: { id?: string; tab?: unknown; url?: string }, deps: {
  extensionId: string; backgroundUrl: string; origin: string; top: boolean; fetchAws?: typeof fetch;
}) {
  try {
    const message = raw as { type?: unknown; url?: unknown; csrfToken?: unknown };
    if (!message || Object.keys(message).length !== 3 || message.type !== 'AWS_PRIVATE_CONSOLE_CREDENTIALS' ||
        sender.id !== deps.extensionId || sender.tab !== undefined || (sender.url && sender.url !== deps.backgroundUrl) || !deps.top ||
        typeof message.url !== 'string' || !/^https:\/\/(?:(\d{12})-[a-z0-9]{8}\.)?ap-southeast-2\.console\.aws\.amazon\.com\/cloudtrailv2\/tb\/creds$/.test(message.url) ||
        new URL(message.url).origin !== deps.origin || typeof message.csrfToken !== 'string' ||
        !message.csrfToken || message.csrfToken.length > 4096 || /[\r\n\0]/.test(message.csrfToken)) throw new Error();
    const body = await readAwsPrivateResponse(message.url, { method: 'POST', mode: 'same-origin', credentials: 'include',
      headers: { 'x-csrf-token': message.csrfToken } }, { fetchAws: deps.fetchAws });
    return awsPrivateCredentials(JSON.parse(body));
  } catch { throw new Error('AWS_PRIVATE_COLLECTION_FAILED'); }
}
