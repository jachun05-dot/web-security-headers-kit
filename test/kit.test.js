import test from 'node:test';
import assert from 'node:assert/strict';
import { buildHeaders, FORMATS, inlineHashes, checkHeaders } from '../src/index.js';

test('strict preset blocks framing, plugins and foreign scripts', () => {
  const h = buildHeaders();
  const csp = h['Content-Security-Policy'];
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /base-uri 'self'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  assert.equal(h['X-Frame-Options'], 'DENY');
  assert.match(h['Strict-Transport-Security'], /max-age=63072000/);
});

test('services add exactly their sources, and popups stay possible for ads', () => {
  const h = buildHeaders({ services: ['google-analytics', 'google-adsense'] });
  assert.match(h['Content-Security-Policy'], /script-src 'self' https:\/\/www\.googletagmanager\.com/);
  assert.match(h['Content-Security-Policy'], /frame-src [^;]*doubleclick/);
  assert.equal(h['Cross-Origin-Opener-Policy'], 'same-origin-allow-popups');
  assert.throws(() => buildHeaders({ services: ['nope'] }), /Unknown service/);
});

test('report-only mode and hashes', () => {
  const h = buildHeaders({ reportOnly: true, scriptHashes: ['sha256-abc='] });
  assert.ok(h['Content-Security-Policy-Report-Only']);
  assert.match(h['Content-Security-Policy-Report-Only'], /'sha256-abc='/);
  assert.throws(() => buildHeaders({ scriptHashes: ['alert(1)'] }), /Not a CSP hash/);
});

test('inline hashes skip external scripts and JSON-LD', () => {
  const html = '<script>console.log(1)</script><script src="/a.js"></script><script type="application/ld+json">{"a":1}</script><style>p{color:red}</style>';
  const h = inlineHashes(html);
  assert.deepEqual(h.scripts, ['sha256-CihokcEcBW4atb/CW/XWsvWwbTjqwQlE9nj9ii5ww5M=']);
  assert.equal(h.styles.length, 1);
});

test('every format renders every header', () => {
  const h = buildHeaders({ services: ['google-fonts'] });
  for (const [name, fmt] of Object.entries(FORMATS)) {
    const text = fmt(h);
    for (const key of Object.keys(h)) assert.ok(text.includes(key), `${name} misses ${key}`);
  }
});

test('the checker gives our own headers A+ and a bare site F', () => {
  assert.equal(checkHeaders(buildHeaders()).grade, 'A+');
  assert.equal(checkHeaders({}).grade, 'F');
  const weak = checkHeaders({ ...buildHeaders(), 'Content-Security-Policy': "script-src 'self' 'unsafe-inline'" });
  assert.ok(weak.findings.some((f) => /unsafe-inline/.test(f.message)));
});
