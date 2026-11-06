/**
 * The runner tells the verifier which
 * plugin build produced a proof. The offscreen runner (Offscreen/index.tsx)
 * puts the sha256 of the packaged plugin it read, checked and ran
 * (prepareBuiltInRun) into the run's sessionData under PLUGIN_SHA256_KEY;
 * every prove() of that run sends it to the verifier AFTER the plugin's own
 * sessionData, so a plugin can neither set nor override it. The verifier
 * forwards sessionData to the server, which can accept only pinned builds.
 *
 * Honest limit: this is the extension's own statement. It holds for an honest
 * build of this extension (a modified plugin file is refused before it runs, and a
 * plugin cannot report another hash); a modified extension can report anything.
 */
export const PLUGIN_SHA256_KEY = 'pluginSha256';

/** Run-level sessionData for a built-in run: the background's keys, then the runner's plugin sha256. */
export function runSessionData(
  sessionData: Record<string, string> | undefined,
  pluginSha256: string,
): Record<string, string> {
  return { ...(sessionData ?? {}), [PLUGIN_SHA256_KEY]: pluginSha256 };
}

/**
 * The sessionData one prove() sends: the run's keys, then the plugin's, then
 * the runner's plugin sha256 again (only from the run; a plugin-supplied value
 * is dropped, also when the run has none).
 */
export function proveSessionData(
  runData: Record<string, string> | null | undefined,
  pluginData: Record<string, string> | undefined,
): Record<string, string> {
  const merged: Record<string, string> = { ...(runData ?? {}), ...(pluginData ?? {}) };
  delete merged[PLUGIN_SHA256_KEY];
  const runner = runData?.[PLUGIN_SHA256_KEY];
  if (typeof runner === 'string') merged[PLUGIN_SHA256_KEY] = runner;
  return merged;
}
