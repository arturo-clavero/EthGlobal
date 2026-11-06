/** Only start after background has acknowledged this pending Azure run. */
export function startAzurePrivatePageHeartbeat(attempt: { proofId: string; pluginSha256: string; nonceMac: string },
  send: (message: unknown) => Promise<unknown>, lost: () => void) {
  const message = { type: 'AZURE_PRIVATE_PAGE_HEARTBEAT', requestId: attempt.proofId,
    pluginSha256: attempt.pluginSha256, nonceMac: attempt.nonceMac };
  let active = true, pending = false;
  let deadline: ReturnType<typeof setTimeout> | undefined;
  const stop = () => { active = false; clearInterval(timer); clearTimeout(deadline); };
  const fail = () => { if (active) { stop(); lost(); } };
  const timer = setInterval(() => {
    if (!active || pending) return;
    pending = true;
    deadline = setTimeout(fail, 5000);
    Promise.resolve().then(() => send(message)).then(reply => {
      if (!reply || typeof reply !== 'object' || !('ok' in reply) || reply.ok !== true) fail();
    }).catch(fail).finally(() => { clearTimeout(deadline); pending = false; });
  }, 20_000);
  return stop;
}
