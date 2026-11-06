/** Strict, bounded HTTP/1.1 framing over authenticated ASCII and private holes.
 *
 * Authentication and private-byte predicates MUST be verified by the caller.
 * Header/reason holes need the header ASCII/no-CRLF proof. Request-target holes
 * additionally need target grammar (no space/control bytes and correct scope).
 * This module does not associate responses with requests or accept GCP claims;
 * callers must exclude responses to HEAD/CONNECT, whose framing differs.
 * Chunk extensions, trailers, compression and hidden framing are unsupported.
 * A contiguous private commitment cannot cross HTTP chunk framing; supporting
 * such atoms would require a separately bound range-set commitment/API.
 */

export const HTTP_STRUCTURE_LIMITS = Object.freeze({ bytes: 16384, headers: 64, chunks: 64, slots: 256 });
const token = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const framingNames = new Set(['content-length', 'transfer-encoding', 'content-encoding']);
const whitespace = byte => byte === 0x20 || byte === 0x09;
const decoder = new TextDecoder('utf-8', { fatal: true });

export class HttpStructureError extends Error {
  constructor(code, offset = 0) {
    super(`HTTP structure ${code} at byte ${offset}`);
    this.name = 'HttpStructureError';
    this.code = code;
    this.offset = offset;
  }
}

/**
 * @param {{bytes:Uint8Array,privateRanges:{start:number,end:number,hash:string}[]}} direction
 * @param {{kind:'request'|'response'}} options
 * @returns {object} Public startLine/header spans; body.bytes and body.wireIndices
 *   map each decoded byte to its wire offset. body.privateRanges use decoded
 *   offsets plus wireStart/wireEnd/sourceIndex. privateRanges classify EVERY
 *   original slot once, retaining its native wire offsets and requiredPredicate.
 *   A span has text only when entirely public. Line end offsets include CRLF;
 *   target/reason/header-value spans exclude delimiters and public header OWS.
 */
export function parseHttpStructure(direction, options) {
  const fail = (code, offset = 0) => { throw new HttpStructureError(code, offset); };
  const kind = options?.kind;
  if (kind !== 'request' && kind !== 'response') fail('MESSAGE_KIND');
  if (!(direction?.bytes instanceof Uint8Array)) fail('INPUT_TYPE');
  if (!direction.bytes.length || direction.bytes.length > HTTP_STRUCTURE_LIMITS.bytes) fail('INPUT_LIMIT');
  if (!Array.isArray(direction.privateRanges) || direction.privateRanges.length > HTTP_STRUCTURE_LIMITS.slots) fail('SLOT_LIMIT');
  const bytes = new Uint8Array(direction.bytes);
  const owner = new Int16Array(bytes.length).fill(-1);
  const ranges = [];
  let previousEnd = 0;
  for (const original of direction.privateRanges) {
    if (!original || typeof original !== 'object') fail('SLOT_METADATA');
    const { start, end, hash } = original;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < previousEnd || start >= end || end > bytes.length) {
      fail('SLOT_RANGE');
    }
    if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)) fail('SLOT_HASH', start);
    const index = ranges.length;
    for (let at = start; at < end; at++) {
      if (bytes[at] !== 0) fail('PRIVATE_NOT_ZERO', at);
      owner[at] = index;
    }
    ranges.push({ start, end, hash, index });
    previousEnd = end;
  }
  for (let at = 0; at < bytes.length; at++) {
    if (owner[at] < 0 && !(bytes[at] === 9 || bytes[at] === 10 || bytes[at] === 13 || (bytes[at] >= 32 && bytes[at] <= 126))) {
      fail('PUBLIC_ASCII', at);
    }
  }
  const isPublic = (start, end) => {
    for (let at = start; at < end; at++) if (owner[at] >= 0) return false;
    return true;
  };
  const publicText = (start, end) => {
    if (start < 0 || end < start || end > bytes.length || !isPublic(start, end)) fail('PRIVATE_FRAMING', start);
    return decoder.decode(bytes.subarray(start, end));
  };
  const span = (start, end) => ({ start, end, ...(isPublic(start, end) ? { text: publicText(start, end) } : {}) });
  const classify = (start, end, location, headerIndex) => {
    const indices = [];
    for (const range of ranges) {
      if (range.end <= start || range.start >= end) continue;
      if (range.start < start || range.end > end || range.location) fail('SLOT_BOUNDARY', range.start);
      range.location = location;
      range.requiredPredicate = location === 'request-target' ? 'request-target-grammar'
        : location === 'body' ? 'body-grammar' : 'header-ascii';
      if (headerIndex !== undefined) range.headerIndex = headerIndex;
      indices.push(range.index);
    }
    return indices;
  };
  const line = start => {
    for (let at = start; at < bytes.length;) {
      if (owner[at] >= 0) { at = ranges[owner[at]].end; continue; }
      if (bytes[at] === 13) {
        if (at + 1 >= bytes.length || bytes[at + 1] !== 10 || owner[at + 1] >= 0) fail('LINE_END', at);
        return { start, contentEnd: at, end: at + 2 };
      }
      if (bytes[at] === 10) fail('LINE_END', at);
      at++;
    }
    fail('TRUNCATED_LINE', start);
  };

  const first = line(0);
  const startLine = { start: 0, end: first.end, version: 'HTTP/1.1' };
  if (isPublic(0, first.contentEnd)) startLine.text = publicText(0, first.contentEnd);
  if (kind === 'request') {
    const separator = bytes.indexOf(32);
    if (separator < 1 || separator >= first.contentEnd) fail('REQUEST_LINE');
    const method = publicText(0, separator);
    if (!token.test(method)) fail('REQUEST_METHOD');
    const versionStart = first.contentEnd - 8;
    const targetEnd = versionStart - 1;
    if (targetEnd <= separator + 1 || bytes[targetEnd] !== 32 || owner[targetEnd] >= 0 ||
        publicText(versionStart, first.contentEnd) !== 'HTTP/1.1') fail('REQUEST_LINE');
    for (let at = separator + 1; at < targetEnd; at++) {
      if (owner[at] < 0 && (bytes[at] < 33 || bytes[at] > 126)) fail('REQUEST_TARGET', at);
    }
    startLine.method = method;
    startLine.target = span(separator + 1, targetEnd);
    classify(separator + 1, targetEnd, 'request-target');
  } else {
    if (first.contentEnd < 13 || publicText(0, 9) !== 'HTTP/1.1 ' ||
        !/^[1-5][0-9]{2}$/.test(publicText(9, 12)) || publicText(12, 13) !== ' ') fail('STATUS_LINE');
    startLine.status = Number(publicText(9, 12));
    startLine.reason = span(13, first.contentEnd);
    classify(13, first.contentEnd, 'reason-phrase');
  }

  const headers = [];
  const framing = new Map();
  let position = first.end;
  while (true) {
    const current = line(position);
    position = current.end;
    if (current.contentEnd === current.start) break;
    if (headers.length >= HTTP_STRUCTURE_LIMITS.headers) fail('HEADER_LIMIT', current.start);
    const colon = bytes.indexOf(58, current.start);
    if (colon <= current.start || colon >= current.contentEnd) fail('HEADER_NAME', current.start);
    const nameText = publicText(current.start, colon);
    if (!token.test(nameText)) fail('HEADER_NAME', current.start);
    const name = nameText.toLowerCase();
    let valueStart = colon + 1;
    let valueEnd = current.contentEnd;
    while (valueStart < valueEnd && owner[valueStart] < 0 && whitespace(bytes[valueStart])) valueStart++;
    while (valueEnd > valueStart && owner[valueEnd - 1] < 0 && whitespace(bytes[valueEnd - 1])) valueEnd--;
    const value = span(valueStart, valueEnd);
    if (framingNames.has(name)) {
      publicText(current.start, current.end);
      if (framing.has(name)) fail('DUPLICATE_FRAMING', current.start);
      framing.set(name, value.text);
    }
    const privateIndices = classify(colon + 1, current.contentEnd, 'header-value', headers.length);
    headers.push({ name, start: current.start, end: current.end, nameSpan: span(current.start, colon), value, privateIndices });
  }

  const contentLength = framing.get('content-length');
  const transfer = framing.get('transfer-encoding');
  const encoding = framing.get('content-encoding');
  if (contentLength !== undefined && transfer !== undefined) fail('AMBIGUOUS_FRAMING');
  if (transfer !== undefined && transfer.toLowerCase() !== 'chunked') fail('TRANSFER_ENCODING');
  if (encoding !== undefined && encoding.toLowerCase() !== 'identity') fail('CONTENT_ENCODING');
  if (contentLength !== undefined && (!/^[0-9]+$/.test(contentLength) || !Number.isSafeInteger(Number(contentLength)) ||
      Number(contentLength) > HTTP_STRUCTURE_LIMITS.bytes)) fail('CONTENT_LENGTH');

  const wireIndices = [];
  const bodyRanges = [];
  const chunks = [];
  const bodyStart = position;
  const append = (start, end) => {
    const offset = wireIndices.length;
    const indices = classify(start, end, 'body');
    for (const index of indices) {
      const range = ranges[index];
      bodyRanges.push({ start: offset + range.start - start, end: offset + range.end - start,
        hash: range.hash, wireStart: range.start, wireEnd: range.end, sourceIndex: index });
    }
    for (let at = start; at < end; at++) wireIndices.push(at);
  };
  let bodyFraming;
  const noBodyStatus = kind === 'response' && (startLine.status < 200 || startLine.status === 204 || startLine.status === 304);
  if (noBodyStatus) {
    if (position !== bytes.length) fail('BODY_FORBIDDEN', position);
    if (startLine.status !== 304 && (contentLength !== undefined || transfer !== undefined)) fail('BODY_FORBIDDEN', position);
    bodyFraming = 'none';
  } else if (transfer !== undefined) {
    bodyFraming = 'chunked';
    while (true) {
      const sizeLine = line(position);
      const sizeText = publicText(position, sizeLine.contentEnd);
      if (!/^[0-9a-fA-F]{1,8}$/.test(sizeText)) fail('CHUNK_SIZE', position);
      const size = Number.parseInt(sizeText, 16);
      position = sizeLine.end;
      if (size === 0) {
        if (position + 2 !== bytes.length || publicText(position, position + 2) !== '\r\n') fail('CHUNK_TRAILER', position);
        position += 2;
        break;
      }
      if (chunks.length >= HTTP_STRUCTURE_LIMITS.chunks) fail('CHUNK_LIMIT', position);
      const end = position + size;
      if (end + 2 > bytes.length || publicText(end, end + 2) !== '\r\n') fail('CHUNK_LENGTH', position);
      chunks.push({ start: position, end, bodyStart: wireIndices.length });
      append(position, end);
      position = end + 2;
    }
  } else if (contentLength !== undefined) {
    bodyFraming = 'content-length';
    if (bytes.length - position !== Number(contentLength)) fail('CONTENT_LENGTH_MISMATCH', position);
    append(position, bytes.length);
  } else {
    bodyFraming = kind === 'request' ? 'none' : 'eof';
    if (kind === 'request' && position !== bytes.length) fail('REQUEST_BODY_FRAMING', position);
    append(position, bytes.length);
  }
  if (ranges.some(range => !range.location)) fail('UNCLASSIFIED_SLOT');
  return { kind, startLine, headers, bodyStart, framing: bodyFraming, chunks, privateRanges: ranges,
    body: { bytes: Uint8Array.from(wireIndices, index => bytes[index]), wireIndices: Uint32Array.from(wireIndices), privateRanges: bodyRanges } };
}
