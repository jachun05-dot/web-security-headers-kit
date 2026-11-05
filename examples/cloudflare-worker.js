// Cloudflare Worker that adds security headers to every response from your origin or static assets.
const HEADERS = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Permitted-Cross-Domain-Policies": "none",
  "Origin-Agent-Cluster": "?1",
  "X-Frame-Options": "DENY"
};

export default {
  async fetch(request, env) {
    const upstream = env.ASSETS ? await env.ASSETS.fetch(request) : await fetch(request);
    const response = new Response(upstream.body, upstream);
    for (const [name, value] of Object.entries(HEADERS)) response.headers.set(name, value);
    response.headers.delete('X-Powered-By');
    return response;
  },
};
