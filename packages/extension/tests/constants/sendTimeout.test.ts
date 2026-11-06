/**
 * The prover's send timeout is 300 s in Proxy mode (leaves headroom for large reveal batches)
 * and stays 60 s in MPC mode; the worker uses this choice per request.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  MPC_SEND_REQUEST_TIMEOUT_MS,
  PROXY_SEND_REQUEST_TIMEOUT_MS,
  sendRequestTimeoutMs,
} from '../../src/constants/sendTimeout';

describe('send timeout', () => {
  it('Proxy (no websockify URL): 300 s', () => {
    expect(PROXY_SEND_REQUEST_TIMEOUT_MS).toBe(300_000);
    expect(sendRequestTimeoutMs(undefined)).toBe(300_000);
    expect(sendRequestTimeoutMs('')).toBe(300_000);
  });

  it('MPC (websockify URL): 60 s as upstream', () => {
    expect(MPC_SEND_REQUEST_TIMEOUT_MS).toBe(60_000);
    expect(sendRequestTimeoutMs('ws://localhost:55688/?token=github.com')).toBe(60_000);
  });

  it('the worker races send_request against that timeout (no other fixed value)', () => {
    const worker = readFileSync(
      path.resolve(__dirname, '../../src/offscreen/ProveManager/worker.ts'),
      'utf8',
    );
    expect(worker).toMatch(
      /const timeoutMs = sendRequestTimeoutMs\(proxyUrl\);\s*try \{\s*await Promise\.race\(\[\s*prover\.send_request\(serverIo, request\),[\s\S]{0,300}?timeoutMs,\s*\),/,
    );
    expect(worker).not.toMatch(/SEND_REQUEST_TIMEOUT_MS = /);
  });
});
