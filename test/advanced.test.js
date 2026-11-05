import test from 'node:test';
import assert from 'node:assert/strict';
import { buildHeaders, createNonce, auditSite, sriHash, parseCspReports, buildSecurityTxt, securityHeaders, checkHeaders } from '../src/index.js';
import { secureResponse } from '../src/worker.js';

test('nonce, strict-dynamic and Trusted Types', () => {
  const nonce = createNonce();
  assert.match(nonce, /^[A-Za-z0-9+/]{22}==$/);
  assert.notEqual(nonce, createNonce());
  const csp = buildHeaders({ nonce, strictDynamic: true, trustedTypes: ['default'] })['Content-Security-Policy'];
  assert.match(csp, new RegExp(`script-src 'self' 'nonce-${nonce.replace(/[+/]/g, '\\$&')}' 'strict-dynamic'`));
  assert.match(csp, /require-trusted-types-for 'script'; trusted-types default/);
  assert.throws(() => buildHeaders({ strictDynamic: true }), /needs a nonce/);
  assert.throws(() => buildHeaders({ nonce: 'short' }), /at least 16/);
  assert.equal(checkHeaders(buildHeaders({ nonce, strictDynamic: true })).grade, 'A+');
});

test('reporting adds report-uri, report-to and Reporting-Endpoints', () => {
  const h = buildHeaders({ reportUri: 'https://example.com/csp' });
  assert.match(h['Content-Security-Policy'], /report-uri https:\/\/example\.com\/csp; report-to csp-endpoint/);
  assert.equal(h['Reporting-Endpoints'], 'csp-endpoint="https://example.com/csp"');
});

test('Express middleware sets a new nonce per request', () => {
  const mw = securityHeaders({ strictDynamic: true });
  const run = () => {
    const set = {};
    const res = { locals: {}, setHeader: (k, v) => (set[k] = v), removeHeader: () => {} };
    mw({}, res, () => {});
    return { set, nonce: res.locals.cspNonce };
  };
  const a = run();
  const b = run();
  assert.notEqual(a.nonce, b.nonce);
  assert.ok(a.set['Content-Security-Policy'].includes(`'nonce-${a.nonce}'`));
});

test('Worker helper stamps the nonce on scripts and styles of HTML only', async () => {
  const seen = [];
  class FakeRewriter {
    on(sel, h) { seen.push(sel); this.h = h; return this; }
    transform(r) { const el = { setAttribute: (k, v) => (this.attr = [k, v]) }; this.h.element(el); return r; }
  }
  const html = new Response('<p>hi</p>', { headers: { 'content-type': 'text/html', 'x-powered-by': 'php' } });
  const out = await secureResponse(html, { nonce: true, strictDynamic: true }, { Rewriter: FakeRewriter });
  assert.match(out.headers.get('content-security-policy'), /'nonce-[^']+' 'strict-dynamic'/);
  assert.equal(out.headers.get('x-powered-by'), null);
  assert.deepEqual(seen, ['script', 'style', 'link[rel="stylesheet"]']);
  const css = await secureResponse(new Response('a{}', { headers: { 'content-type': 'text/css' } }), { nonce: true });
  assert.doesNotMatch(css.headers.get('content-security-policy'), /nonce/);
});

test('SRI hashes match the standard', () => {
  assert.equal(sriHash('alert(1)', 'sha256'), 'sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI=');
  assert.match(sriHash('x'), /^sha384-/);
});

test('CSP reports from both formats, extensions filtered out', () => {
  const legacy = JSON.stringify({ 'csp-report': { 'document-uri': 'https://a.com/', 'violated-directive': 'script-src', 'blocked-uri': 'https://evil.com/x.js' } });
  const modern = [{ type: 'csp-violation', body: { documentURL: 'https://a.com/', effectiveDirective: 'img-src', blockedURL: 'https://img.com/p.png' } }, { type: 'csp-violation', body: { blockedURL: 'chrome-extension://abc' } }];
  assert.deepEqual(parseCspReports(legacy).map((r) => r.blocked), ['https://evil.com/x.js']);
  assert.deepEqual(parseCspReports(modern).map((r) => r.directive), ['img-src']);
  assert.deepEqual(parseCspReports('not json'), []);
});

test('security.txt follows RFC 9116', () => {
  const txt = buildSecurityTxt({ contact: 'mailto:sec@example.com', expires: new Date(Date.now() + 30 * 86400000), preferredLanguages: ['en', 'ko'] });
  assert.match(txt, /^Contact: mailto:sec@example\.com\nExpires: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\nPreferred-Languages: en, ko\n$/);
  assert.throws(() => buildSecurityTxt({}), /Contact/);
  assert.throws(() => buildSecurityTxt({ contact: 'me@example.com' }), /mailto/);
});

test('site audit finds HTTP, cookie and content problems', async () => {
  const pages = {
    'https://shop.test/': () => new Response('<script src="https://cdn.other.test/lib.js"></script><img src="http://img.test/a.png"><button onclick="go()">x</button>', {
      headers: { 'content-type': 'text/html', 'set-cookie': 'sid=1; Path=/' },
    }),
    'http://shop.test/': () => new Response('', { status: 302, headers: { location: 'https://shop.test/' } }),
    'https://shop.test/.well-known/security.txt': () => new Response('', { status: 404 }),
  };
  const fakeFetch = async (u) => {
    const r = pages[u]();
    Object.defineProperty(r, 'url', { value: u });
    return r;
  };
  const res = await auditSite('shop.test', { fetch: fakeFetch });
  const text = res.findings.map((f) => `${f.level} ${f.header}: ${f.message}`).join('\n');
  assert.match(text, /warn HTTPS: .*temporary 302/);
  assert.match(text, /fail Set-Cookie: Cookie "sid" lacks Secure/);
  assert.match(text, /fail Mixed content/);
  assert.match(text, /info Subresource Integrity/);
  assert.match(text, /info Inline handlers/);
  assert.match(text, /info security\.txt/);
  assert.equal(res.grade, 'F');

  const good = buildHeaders();
  const clean = await auditSite('https://good.test/', {
    fetch: async (u) => {
      const r = u.startsWith('http://') ? new Response('', { status: 301, headers: { location: 'https://good.test/' } }) : u.endsWith('security.txt') ? new Response('Contact: mailto:a@good.test\n') : new Response('<p>ok</p>', { headers: { ...good, 'content-type': 'text/html' } });
      Object.defineProperty(r, 'url', { value: u });
      return r;
    },
  });
  assert.equal(clean.grade, 'A+', JSON.stringify(clean.findings));
});
