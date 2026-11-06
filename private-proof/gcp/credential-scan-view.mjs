import { authenticatedTranscript } from './authenticated-transcript.mjs';
import { parseHttpStructure } from './http-structure.mjs';
import { parseMultipartStructure } from './gcp-structure.mjs';

const credentialNames = {
  sent: new Set(['authorization', 'cookie', 'proxy-authorization', 'x-amz-security-token']),
  recv: new Set(['set-cookie']),
};

/** Scanner-only view after native authentication; never persist this altered view. */
export function gcpCredentialScanView(receipt, expected) {
  try {
    return privateCredentialScanView(receipt, authenticatedTranscript(receipt, expected), expected.step !== 'identity');
  } catch {
    throw new Error('GCP_PRIVATE_TRANSCRIPT_INVALID');
  }
}

/** directions must come from the provider's authenticated native receipt validator. */
export function privateCredentialScanView(receipt, directions, multipart) {
    const masks = {};
    for (const direction of ['sent', 'recv']) {
      const mask = masks[direction] = new Uint8Array(directions[direction].bytes.length);
      const mark = (message, wireIndices) => {
        for (const [index, header] of message.headers.entries()) {
          if (!credentialNames[direction].has(header.name) || header.value.end <= header.value.start) continue;
          let cursor = header.value.start;
          for (const range of message.privateRanges.filter(range => range.headerIndex === index)) {
            if (range.start !== cursor || range.end > header.value.end) break;
            cursor = range.end;
          }
          if (cursor !== header.value.end) continue;
          for (let at = header.nameSpan.start; at < header.nameSpan.end; at++) {
            mask[wireIndices ? wireIndices[at] : at] = 1;
          }
        }
      };
      const message = parseHttpStructure(directions[direction], { kind: direction === 'sent' ? 'request' : 'response' });
      mark(message);
      if (direction === 'recv' && multipart) {
        const types = message.headers.filter(header => header.name === 'content-type');
        const boundary = types.length === 1 && /^multipart\/mixed;[ \t]*boundary=(?:"([A-Za-z0-9_-]{1,70})"|([A-Za-z0-9_-]{1,70}))$/i.exec(types[0].value.text ?? '');
        if (boundary) for (const part of parseMultipartStructure(message.body, boundary[1] ?? boundary[2])) {
          mark(parseHttpStructure(part.direction, { kind: 'response' }), part.wireIndices);
        }
      }
    }
    const maskText = (text, direction, start = 0) => Array.from(text, (byte, offset) =>
      masks[direction][start + offset] ? '\0' : byte).join('');
    const positions = { sent: 0, recv: 0 };
    return {
      ...receipt,
      transcript: { ...receipt.transcript,
        sent: maskText(receipt.transcript.sent, 'sent'), recv: maskText(receipt.transcript.recv, 'recv') },
      results: receipt.results.map(result => {
        const direction = result.type.toLowerCase(), range = receipt.config[direction][positions[direction]++];
        return { ...result, value: result.action.kind === 'REVEAL'
          ? maskText(result.value, direction, range.start) : result.value };
      }),
    };
}
