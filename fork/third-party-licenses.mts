// Shared license rules for THIRD_PARTY_NOTICES.txt (third-party-notices.mts for npm packages, wasm-crates.mts
// for the Rust crates in tlsn-wasm).

/** Licenses we ship under without further obligations than keeping the notices (SPDX ids, case-insensitive). */
const PERMISSIVE = new Set(
  [
    "MIT", "MIT-0", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "ISC", "Zlib",
    "Unlicense", "CC0-1.0", "Unicode-3.0", "Unicode-DFS-2016", "CDLA-Permissive-2.0", "BlueOak-1.0.0", "Python-2.0",
  ].map((l) => l.toLowerCase()),
);

/**
 * Whether an SPDX expression (also the old `A/B` form) can be used under permissive terms only: an OR needs one
 * permissive side, an AND needs both. Anything unknown (GPL, LGPL, MPL, a custom string, "UNLICENSED") is false.
 */
export function isPermissive(expr: string): boolean {
  const tokens = expr.replace(/\//g, " OR ").replace(/\(/g, " ( ").replace(/\)/g, " ) ").trim().split(/\s+/);
  let i = 0;
  const atom = (): boolean => {
    if (tokens[i] === "(") {
      i++;
      const v = or();
      if (tokens[i++] !== ")") throw new Error("unbalanced license expression: " + expr);
      return v;
    }
    let id = tokens[i++] ?? "";
    if (tokens[i] === "WITH") id += ` WITH ${tokens[(i += 2) - 1]}`;
    return PERMISSIVE.has(id.toLowerCase());
  };
  const and = (): boolean => {
    let v = atom();
    while (tokens[i] === "AND") { i++; v = atom() && v; }
    return v;
  };
  const or = (): boolean => {
    let v = and();
    while (tokens[i] === "OR") { i++; v = and() || v; }
    return v;
  };
  try {
    const v = or();
    return i === tokens.length && v;
  } catch {
    return false;
  }
}

/**
 * The license files to reproduce for a package: every NOTICE file (Apache-2.0 §4d), plus its license files; where the
 * expression lets us choose MIT and the package has an MIT file, that file instead of the Apache/Unlicense/Zlib ones
 * (we use dual-licensed packages under MIT).
 */
export function pickLicenseFiles<F extends { name: string }>(expr: string, files: F[]): F[] {
  const notices = files.filter((f) => /^notice/i.test(f.name));
  const licenses = files.filter((f) => !/^notice/i.test(f.name));
  const mitChoice = /\bMIT\b/.test(expr) && /\sOR\s|\//.test(expr) && licenses.some((f) => /mit/i.test(f.name));
  const chosen = mitChoice ? licenses.filter((f) => !/apache|unlicense|zlib/i.test(f.name)) : licenses;
  return [...chosen, ...notices].sort((a, b) => a.name.localeCompare(b.name));
}

export const MIT_TEMPLATE = `MIT License

Copyright (c) <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.`;
