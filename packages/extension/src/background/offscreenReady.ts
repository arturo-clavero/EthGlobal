/** Page load can finish before React installs the offscreen message listener. */
export function waitForOffscreenReady(probe: () => Promise<unknown>): Promise<void> {
  return new Promise((resolve, reject) => {
    let done = false;
    let retry: ReturnType<typeof setTimeout> | undefined;
    const finish = (ready: boolean) => {
      if (done) return;
      done = true;
      clearTimeout(deadline);
      if (retry !== undefined) clearTimeout(retry);
      if (ready) resolve();
      else reject(new Error('OFFSCREEN_NOT_READY'));
    };
    const deadline = setTimeout(() => finish(false), 5_000);
    const attempt = async () => {
      let ready = false;
      try {
        const response = await probe();
        ready = !!response && typeof response === 'object' && !Array.isArray(response) &&
          Object.keys(response).length === 2 &&
          (response as { success?: unknown }).success === true &&
          (response as { data?: unknown }).data === 'Processed in offscreen';
      } catch { /* A cold document may not have a receiving listener yet. */ }
      if (done) return;
      if (ready) finish(true);
      else retry = setTimeout(attempt, 100);
    };
    void attempt();
  });
}
