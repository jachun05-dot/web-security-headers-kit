// Turns a header map into ready-to-paste config for each platform.
const esc = (v, q) => v.replace(new RegExp(q, 'g'), `\\${q}`);

export const FORMATS = {
  // Netlify and Cloudflare Pages: a file named _headers in the publish folder.
  netlify: (h) => `/*\n${Object.entries(h).map(([k, v]) => `  ${k}: ${v}`).join('\n')}\n`,
  'cloudflare-pages': (h) => FORMATS.netlify(h),
  vercel: (h) => `${JSON.stringify({ headers: [{ source: '/(.*)', headers: Object.entries(h).map(([key, value]) => ({ key, value })) }] }, null, 2)}\n`,
  nginx: (h) => `# Inside your server { } block (HTTPS only). "always" adds the headers to error pages too.\n${Object.entries(h).map(([k, v]) => `add_header ${k} "${esc(v, '"')}" always;`).join('\n')}\n`,
  apache: (h) => `# In .htaccess or your VirtualHost. Needs mod_headers.\n<IfModule mod_headers.c>\n${Object.entries(h).map(([k, v]) => `  Header always set ${k} "${esc(v, '"')}"`).join('\n')}\n</IfModule>\n`,
  express: (h) => `// Express / Connect middleware. Put it before your routes: app.use(securityHeaders);\nconst HEADERS = ${JSON.stringify(h, null, 2)};\n\nexport function securityHeaders(req, res, next) {\n  for (const [name, value] of Object.entries(HEADERS)) res.setHeader(name, value);\n  res.removeHeader('X-Powered-By');\n  next();\n}\n`,
  'cloudflare-worker': (h) => `// Cloudflare Worker that adds security headers to every response from your origin or static assets.\nconst HEADERS = ${JSON.stringify(h, null, 2)};\n\nexport default {\n  async fetch(request, env) {\n    const upstream = env.ASSETS ? await env.ASSETS.fetch(request) : await fetch(request);\n    const response = new Response(upstream.body, upstream);\n    for (const [name, value] of Object.entries(HEADERS)) response.headers.set(name, value);\n    response.headers.delete('X-Powered-By');\n    return response;\n  },\n};\n`,
  json: (h) => `${JSON.stringify(h, null, 2)}\n`,
};
