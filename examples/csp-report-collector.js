// A tiny Cloudflare Worker that receives CSP violation reports and logs them.
// Point --report-uri at it, then read the logs with `wrangler tail`.
import { parseCspReports } from 'web-security-headers-kit';

export default {
  async fetch(request) {
    if (request.method !== 'POST') return new Response('POST CSP reports here', { status: 405 });
    const body = await request.text();
    if (body.length > 64 * 1024) return new Response('Too large', { status: 413 });
    for (const r of parseCspReports(body)) console.log(JSON.stringify(r));
    return new Response(null, { status: 204 });
  },
};
