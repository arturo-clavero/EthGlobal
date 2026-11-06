// Browser replacements for node:net and node:util in the portal discovery bundle.
// isIP is derived from Node.js internal/net.js. Copyright Node.js contributors.
// MIT license: permission is granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is furnished
// to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// shortcut: equality supports parsed JSON/plain records only; use a full platform
// adapter before accepting class instances or other structured-clone values.
const RegExpPrototypeTest=(r,s)=>RegExp.prototype.test.call(r,s);
// IPv4 Segment
const v4Seg = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])';
const v4Str = `(?:${v4Seg}\\.){3}${v4Seg}`;
const IPv4Reg = new RegExp(`^${v4Str}$`);

// IPv6 Segment
const v6Seg = '(?:[0-9a-fA-F]{1,4})';
const IPv6Reg = new RegExp('^(?:' +
  `(?:${v6Seg}:){7}(?:${v6Seg}|:)|` +
  `(?:${v6Seg}:){6}(?:${v4Str}|:${v6Seg}|:)|` +
  `(?:${v6Seg}:){5}(?::${v4Str}|(?::${v6Seg}){1,2}|:)|` +
  `(?:${v6Seg}:){4}(?:(?::${v6Seg}){0,1}:${v4Str}|(?::${v6Seg}){1,3}|:)|` +
  `(?:${v6Seg}:){3}(?:(?::${v6Seg}){0,2}:${v4Str}|(?::${v6Seg}){1,4}|:)|` +
  `(?:${v6Seg}:){2}(?:(?::${v6Seg}){0,3}:${v4Str}|(?::${v6Seg}){1,5}|:)|` +
  `(?:${v6Seg}:){1}(?:(?::${v6Seg}){0,4}:${v4Str}|(?::${v6Seg}){1,6}|:)|` +
  `(?::(?:(?::${v6Seg}){0,5}:${v4Str}|(?::${v6Seg}){1,7}|:))` +
')(?:%[0-9a-zA-Z-.:]{1,})?$');

/**
 * @param {string} s
 * @returns {boolean}
 */
function isIPv4(s) {
  // TODO(aduh95): Replace RegExpPrototypeTest with RegExpPrototypeExec when it
  // no longer creates a perf regression in the dns benchmark.
  // eslint-disable-next-line node-core/avoid-prototype-pollution
  return RegExpPrototypeTest(IPv4Reg, s);
}

/**
 * @param {string} s
 * @returns {boolean}
 */
function isIPv6(s) {
  // TODO(aduh95): Replace RegExpPrototypeTest with RegExpPrototypeExec when it
  // no longer creates a perf regression in the dns benchmark.
  // eslint-disable-next-line node-core/avoid-prototype-pollution
  return RegExpPrototypeTest(IPv6Reg, s);
}

/**
 * @param {string} s
 * @returns {4|6|0}
 */
function isIP(s) {
  if (isIPv4(s)) return 4;
  if (isIPv6(s)) return 6;
  return 0;
}


function isDeepStrictEqual(a,b) {
  if(Object.is(a,b))return true;
  if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const proto=Object.getPrototypeOf(a);
  if(proto!==Object.getPrototypeOf(b)||![Object.prototype,Array.prototype,null].includes(proto))throw new Error('unsupported-value');
  if(Array.isArray(a)&&a.length!==b.length)return false;
  if(Object.getOwnPropertySymbols(a).length||Object.getOwnPropertySymbols(b).length)throw new Error('unsupported-value');
  const keys=Object.keys(a);
  return keys.length===Object.keys(b).length&&keys.every(k=>Object.hasOwn(b,k)&&isDeepStrictEqual(a[k],b[k]));
}

export {isIP,isDeepStrictEqual};
