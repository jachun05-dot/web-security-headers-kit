// Grades a set of response headers. Works on any header map, so it can be
// tested offline; bin/cli.js feeds it headers fetched from a live URL.
export function checkHeaders(raw) {
  const h = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k.toLowerCase(), String(v)]));
  const findings = [];
  const add = (level, header, message) => findings.push({ level, header, message });

  const csp = h['content-security-policy'];
  if (!csp) {
    if (h['content-security-policy-report-only']) add('warn', 'Content-Security-Policy', 'Only a report-only policy is set. Good for testing; switch to enforcing once reports are clean.');
    else add('fail', 'Content-Security-Policy', 'Missing. This is the main defense against injected scripts (XSS).');
  } else {
    const dirs = Object.fromEntries(csp.split(';').map((d) => d.trim().split(/\s+/)).filter((p) => p[0]).map(([k, ...v]) => [k.toLowerCase(), v]));
    const scripts = dirs['script-src'] || dirs['default-src'] || [];
    if (scripts.includes("'unsafe-inline'") && !scripts.some((s) => /^'(nonce|sha\d+)-/.test(s) || s === "'strict-dynamic'")) add('warn', 'Content-Security-Policy', "script-src allows 'unsafe-inline', which lets injected inline scripts run. Use hashes or nonces instead.");
    if (scripts.includes("'unsafe-eval'")) add('warn', 'Content-Security-Policy', "script-src allows 'unsafe-eval'.");
    if (scripts.some((s) => s === '*' || s === 'https:' || s === 'http:')) add('warn', 'Content-Security-Policy', 'script-src allows scripts from any host.');
    if (!dirs['object-src'] && !(dirs['default-src'] || []).includes("'none'")) add('warn', 'Content-Security-Policy', "Add object-src 'none' to block plugins.");
    if (!dirs['base-uri']) add('warn', 'Content-Security-Policy', "Add base-uri 'self' so injected <base> tags can't redirect relative URLs.");
    if (!dirs['frame-ancestors'] && !h['x-frame-options']) add('fail', 'Content-Security-Policy', 'No frame-ancestors (or X-Frame-Options): pages can be framed for clickjacking.');
    if (!dirs['default-src']) add('warn', 'Content-Security-Policy', "No default-src, so anything a directive doesn't mention is allowed. Start from default-src 'self'.");
    if (scripts.includes('data:')) add('warn', 'Content-Security-Policy', 'script-src allows data: URLs, which can carry injected code.');
    if ((dirs['default-src'] || []).includes('*')) add('warn', 'Content-Security-Policy', 'default-src allows any host.');
    if (dirs['require-trusted-types-for']) add('info', 'Content-Security-Policy', 'Trusted Types are on: DOM XSS sinks are locked down.');
    if (scripts.includes("'strict-dynamic'")) add('info', 'Content-Security-Policy', "Uses 'strict-dynamic' with nonces or hashes (the strongest CSP style).");
  }
  const acao = h['access-control-allow-origin'];
  if (acao === '*' && /true/i.test(h['access-control-allow-credentials'] || '')) add('fail', 'Access-Control-Allow-Origin', 'Wildcard origin with credentials: any site could read logged-in responses.');

  const hsts = h['strict-transport-security'];
  if (!hsts) add('fail', 'Strict-Transport-Security', 'Missing. Browsers may still try plain HTTP first.');
  else {
    const age = Number((/max-age=(\d+)/i.exec(hsts) || [])[1] || 0);
    if (age < 15552000) add('warn', 'Strict-Transport-Security', `max-age is ${age}s; use at least 6 months (15552000).`);
  }
  if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') add('fail', 'X-Content-Type-Options', 'Should be "nosniff".');
  if (!h['referrer-policy']) add('warn', 'Referrer-Policy', 'Missing. Use strict-origin-when-cross-origin or stricter.');
  else if (/unsafe-url|no-referrer-when-downgrade/i.test(h['referrer-policy'])) add('warn', 'Referrer-Policy', 'Leaks full URLs to other sites.');
  if (!h['permissions-policy']) add('warn', 'Permissions-Policy', 'Missing. Turn off features you do not use, like camera and microphone.');
  if (!h['cross-origin-opener-policy']) add('warn', 'Cross-Origin-Opener-Policy', 'Missing. same-origin isolates your window from pop-ups and openers.');
  if (h['x-powered-by']) add('warn', 'X-Powered-By', `Reveals "${h['x-powered-by']}". Remove it.`);
  if (/\d/.test(h.server || '')) add('info', 'Server', `Reveals a version: "${h.server}".`);

  return { grade: gradeOf(findings), findings };
}

export function gradeOf(findings) {
  const fails = findings.filter((f) => f.level === 'fail').length;
  const warns = findings.filter((f) => f.level === 'warn').length;
  return fails >= 3 ? 'F' : fails === 2 ? 'D' : fails === 1 ? 'C' : warns >= 3 ? 'B' : warns >= 1 ? 'A' : 'A+';
}
