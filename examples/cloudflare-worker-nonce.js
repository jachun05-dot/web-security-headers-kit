// Cloudflare Worker in front of static assets: every HTML response gets a fresh
// nonce stamped on its <script> and <style> tags, plus the full header set.
// wrangler.jsonc: "main": "worker.js", "assets": { "directory": "./public", "binding": "ASSETS", "run_worker_first": true }
import { secureResponse } from 'web-security-headers-kit/worker';

export default {
  async fetch(request, env) {
    const res = await env.ASSETS.fetch(request);
    return secureResponse(res, { services: ['google-fonts'], nonce: true, strictDynamic: true });
  },
};
