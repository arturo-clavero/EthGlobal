import { authenticatedSourceTranscript } from '../gcp/authenticated-transcript.mjs';
import { parseHttpStructure } from '../gcp/http-structure.mjs';

const source = Object.freeze({ host: 'graph.microsoft.com', method: 'AZURE_WORK_PRIVATE', step: 'identity' });
const fail = () => { throw new Error('AZURE_PRIVATE_IDENTITY_RECEIPT_INVALID'); };

/** Use only a receipt pulled from the trusted native service, after checking the live attempt/replay ledger.
 * The returned obligations must ALL pass their ZK checks before this identity is accepted.
 */
export function inspectIdentityReceipt(receipt, expected) {
  try {
    const transcript = authenticatedSourceTranscript(receipt, expected, source);
    const recv = transcript.recv;
    if (recv.bytes.length > 1024 || recv.privateRanges.length !== 1 || recv.privateRanges[0].start !== 0 ||
        recv.privateRanges[0].end !== recv.bytes.length || recv.bytes.some(byte => byte !== 0)) fail();
    const request = parseHttpStructure(transcript.sent, { kind: 'request' });
    if (request.startLine.text !== 'GET /v1.0/me?$select=id HTTP/1.1' || request.body.bytes.length !== 0) fail();
    const fixed = new Map([
      ['host', 'graph.microsoft.com'], ['accept', 'application/json'], ['accept-encoding', 'identity'],
      ['connection', 'close'], ['x-azure-proof-nonce', expected.nonceMac], ['x-azure-proof-step', 'identity'],
    ]);
    if (request.headers.length !== fixed.size + 1) fail();
    const seen = new Set(), obligations = [];
    for (const header of request.headers) {
      if (seen.has(header.name)) fail();
      seen.add(header.name);
      if (fixed.has(header.name)) {
        if (header.value.text !== fixed.get(header.name)) fail();
      } else {
        if (header.name !== 'authorization' || header.value.text !== undefined) fail();
        const slots = request.privateRanges.filter(slot => slot.start >= header.value.start && slot.end <= header.value.end);
        let cursor = header.value.start;
        for (const slot of slots) {
          if (slot.start !== cursor || slot.end - slot.start > 2048) fail();
          obligations.push({ circuitId: 'header-v1', hash: slot.hash, length: slot.end - slot.start });
          cursor = slot.end;
        }
        if (cursor !== header.value.end || !slots.length) fail();
      }
    }
    if (obligations.length !== request.privateRanges.length || !seen.has('authorization')) fail();
    return { responseHash: recv.privateRanges[0].hash, responseLength: recv.bytes.length, headerObligations: obligations };
  } catch { fail(); }
}
