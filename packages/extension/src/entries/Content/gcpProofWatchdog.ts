/** Lives in the popup content script so loss of the offscreen task cannot freeze its status. */
export function watchGcpProofProgress(panel: HTMLElement): () => void {
  const receivedAt = Date.now();
  const timer = setInterval(() => {
    if (!panel.isConnected) { clearInterval(timer); return; }
    const seconds = Math.floor((Date.now() - receivedAt) / 1000);
    if (seconds < 30) return;
    const heading = panel.querySelector('#gcp-private-proof-heading');
    const clock = panel.querySelector('#gcp-private-proof-clock');
    const help = panel.querySelector('#gcp-private-proof-help');
    if (heading) heading.textContent = 'Verification stopped responding';
    if (clock) clock.textContent = `Last update received ${seconds} seconds ago.`;
    const lastPart = panel.querySelector('#gcp-private-proof-last-part');
    const explanation = panel.querySelector('#gcp-private-proof-explanation');
    const verification = panel.querySelector('#gcp-private-proof-verification');
    if (lastPart) lastPart.textContent = 'The completed-part count above is the last reported count.';
    if (explanation) explanation.textContent = 'Progress updates have stopped. This window cannot confirm whether verification finished.';
    if (verification) verification.textContent = '3. Server verification — check the page that started this proof for the result';
    if (help) {
      help.setAttribute('role', 'status');
      help.textContent = 'Return to the page that started this proof to check the attempt status. Closing this window cancels any remaining browser proof work.';
    }
  }, 1000);
  return () => clearInterval(timer);
}
