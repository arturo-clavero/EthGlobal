import type { DomJson } from '@tlsn/plugin-sdk';

export function gcpPrivateProgress(completed: number, elapsedSeconds: number, idleSeconds: number): DomJson {
  const line = (text: string, id?: string): DomJson => ({ type: 'div', options: { ...(id ? { id } : {}), style: { marginTop: '12px', lineHeight: '1.5' } }, children: [text] });
  return {
    type: 'div',
    options: { id: 'gcp-private-proof-progress', style: { position: 'fixed', inset: '0', display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: '24px', boxSizing: 'border-box', backgroundColor: 'rgba(15, 23, 42, 0.45)', zIndex: '9999999',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', fontSize: '14px', lineHeight: '1.5', color: '#1f2328' } },
    children: [{ type: 'div', options: { style: { width: '100%', maxWidth: '440px', boxSizing: 'border-box', padding: '28px',
      borderRadius: '12px', backgroundColor: '#ffffff', boxShadow: '0 12px 32px rgba(0, 0, 0, 0.18)' } }, children: [
      { type: 'div', options: { id: 'gcp-private-proof-heading', style: { fontSize: '22px', fontWeight: '600', lineHeight: '1.35', margin: '0 0 20px' } }, children: ['Creating your private proof'] },
      line('1. Collect Google Cloud activity — complete'),
      line(`2. Create private proof — ${completed} proof ${completed === 1 ? 'part' : 'parts'} completed`),
      line('3. Server verification — next', 'gcp-private-proof-verification'),
      line(`Time in this step: ${Math.floor(elapsedSeconds / 60)}m ${elapsedSeconds % 60}s.`, 'gcp-private-proof-clock'),
      line(completed ? `Last proof part completed ${idleSeconds}s ago.` : 'Preparing the first proof part.', 'gcp-private-proof-last-part'),
      line('Proof parts can take several minutes. The count updates when each part finishes; verification is not complete yet.', 'gcp-private-proof-explanation'),
      line('Keep this window open. It closes when browser processing ends; check the page that started this proof for the final result.', 'gcp-private-proof-help'),
    ] }],
  };
}
