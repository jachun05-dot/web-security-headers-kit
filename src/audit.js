// Full check of a live site: headers, HTTPS redirect, cookies, page content
// (mixed content, scripts without integrity, inline handlers) and security.txt.
import { checkHeaders, gradeOf } from './check.js';

export async function auditSite(input, { fetch: f = globalThis.fetch } = {}) {
  const url = new URL(/^https?:\/\//.test(input) ? input : `https://${input}`);
  const findings = [];
  const add = (level, header, message) => findings.push({ level, header, message });

  const res = await f(url.href, { redirect: 'follow' });
  const final = new URL(res.url || url.href);
  findings.push(...checkHeaders(Object.fromEntries(res.headers)).findings);

  // 1. Plain HTTP must redirect to HTTPS.
  try {
    const plain = await f(`http://${url.host}${url.pathname}`, { redirect: 'manual' });
    const loc = plain.headers.get('location') || '';
    if (plain.status >= 300 && plain.status < 400) {
      if (!loc.startsWith('https://')) add('fail', 'HTTPS', `http:// redirects to ${loc || 'nowhere'} instead of https://.`);
      else if (![301, 308].includes(plain.status)) add('warn', 'HTTPS', `http:// uses a temporary ${plain.status} redirect; use 301 or 308.`);
    } else add('fail', 'HTTPS', `http:// is served directly (status ${plain.status}) instead of redirecting to https://.`);
  } catch {
    add('info', 'HTTPS', 'Could not reach the http:// version (that is fine if port 80 is closed).');
  }

  // 2. Cookies.
  const cookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [res.headers.get('set-cookie')].filter(Boolean);
  for (const c of cookies) {
    const name = c.split('=')[0].trim();
    if (!/;\s*secure/i.test(c)) add('fail', 'Set-Cookie', `Cookie "${name}" lacks Secure.`);
    if (!/;\s*httponly/i.test(c)) add('warn', 'Set-Cookie', `Cookie "${name}" lacks HttpOnly (scripts can read it).`);
    if (!/;\s*samesite=/i.test(c)) add('warn', 'Set-Cookie', `Cookie "${name}" has no SameSite attribute.`);
    else if (/;\s*samesite=none/i.test(c) && !/;\s*secure/i.test(c)) add('fail', 'Set-Cookie', `Cookie "${name}" is SameSite=None without Secure.`);
  }

  // 3. Page content.
  if (/text\/html/i.test(res.headers.get('content-type') || '')) {
    const html = await res.text();
    const mixed = [...html.matchAll(/<(script|link|img|iframe|audio|video|source)\b[^>]*\s(src|href)=["']http:\/\/[^"']+/gi)].length;
    if (mixed) add('fail', 'Mixed content', `${mixed} resource(s) load over plain http://.`);
    let noSri = 0;
    for (const m of html.matchAll(/<script\b[^>]*\ssrc=["'](https?:\/\/[^"']+)["'][^>]*>/gi)) {
      const host = new URL(m[1]).host;
      if (host !== final.host && !/\sintegrity=/i.test(m[0])) noSri++;
    }
    if (noSri) add('info', 'Subresource Integrity', `${noSri} external script(s) without integrity="…". Add SRI for files from public CDNs (run the "sri" command). Scripts that change on purpose, like analytics and ads, can't use it.`);
    const handlers = [...html.matchAll(/\son(click|load|error|submit|change|input|mouseover|focus|blur)\s*=/gi)].length;
    if (handlers) add('info', 'Inline handlers', `${handlers} inline event handler(s) like onclick="…". They can't be allowed by hash or nonce; move them into script files before enforcing a strict CSP.`);
    if (/<form\b[^>]*action=["']http:\/\//i.test(html)) add('fail', 'Forms', 'A form posts to plain http://.');
  }

  // 4. security.txt
  try {
    const st = await f(`${final.origin}/.well-known/security.txt`, { redirect: 'follow' });
    const text = st.ok ? await st.text() : '';
    if (!st.ok || !/^contact:/im.test(text)) add('info', 'security.txt', 'No /.well-known/security.txt. Add one so people can report problems (run the "securitytxt" command).');
  } catch {
    add('info', 'security.txt', 'Could not check /.well-known/security.txt.');
  }

  return { url: final.href, grade: gradeOf(findings), findings };
}
