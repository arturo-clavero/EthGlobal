/**
 * The allowed-origin gate for window.tlsn.extensionId
 * and helperStatus().
 */
import { describe, it, expect } from 'vitest';
import {
  isProductOrigin,
  parseProductOrigins,
  PRODUCT_ORIGINS,
} from '../../src/constants/productOrigins';

const DEV =
  'http://localhost:5173,http://127.0.0.1:5173,http://localhost:5175,http://127.0.0.1:5175';

describe('parseProductOrigins', () => {
  it('keeps the dev list as given', () => {
    expect(parseProductOrigins(DEV)).toEqual([
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'http://localhost:5175',
      'http://127.0.0.1:5175',
    ]);
  });

  it('keeps https origins and drops duplicates and blanks', () => {
    expect(parseProductOrigins(' https://app.example.com, ,https://app.example.com ')).toEqual([
      'https://app.example.com',
    ]);
  });

  it('drops anything that is not an exact origin', () => {
    expect(
      parseProductOrigins(
        [
          'https://app.example.com/', // trailing slash
          'https://app.example.com/apply', // path
          'https://user@app.example.com', // userinfo
          'https://app.example.com:443', // default port spelled out
          'http://app.example.com', // plain http off loopback
          'chrome-extension://abc', // not a web origin
          '*.example.com',
          'null',
          'not a url',
        ].join(','),
      ),
    ).toEqual([]);
  });

  it('is empty (fail closed) without a build-time list', () => {
    expect(parseProductOrigins('')).toEqual([]);
    // vitest has no __FORK_PRODUCT_ORIGINS__ define: nothing is allowed
    expect(PRODUCT_ORIGINS).toEqual([]);
    expect(isProductOrigin('http://localhost:5173')).toBe(false);
  });
});

describe('isProductOrigin', () => {
  const allowed = parseProductOrigins(`${DEV},https://app.example.com`);

  it('accepts exactly the listed origins', () => {
    for (const o of allowed) expect(isProductOrigin(o, allowed)).toBe(true);
  });

  it('refuses everything else', () => {
    for (const o of [
      'http://localhost:5174', // other port
      'http://localhost',
      'https://localhost:5173',
      'http://localhost:5173.evil.com',
      'https://app.example.com.evil.com',
      'https://evil.app.example.com',
      'https://example.com',
      'https://github.com',
      'null',
      '',
      null,
      undefined,
    ]) {
      expect(isProductOrigin(o as string | null | undefined, allowed)).toBe(false);
    }
  });
});
