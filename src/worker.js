// Cloudflare Workers helper: adds security headers to any Response, and for
// HTML can stamp a fresh nonce on every <script> and <style> tag.
//
//   import { secureResponse } from 'web-security-headers-kit/worker';
//   export default {
//     async fetch(request, env) {
//       const res = await env.ASSETS.fetch(request);
//       return secureResponse(res, { services: ['google-analytics'], nonce: true, strictDynamic: true });
//     },
//   };
import { buildHeaders, createNonce } from './policy.js';

export function secureResponse(response, options = {}, { Rewriter = globalThis.HTMLRewriter } = {}) {
  const isHtml = /text\/html/i.test(response.headers.get('content-type') || '');
  const wantNonce = options.nonce === true && isHtml;
  if (options.nonce === true && isHtml && !Rewriter) throw new Error('nonce: true needs HTMLRewriter (Cloudflare Workers).');
  const nonce = wantNonce ? createNonce() : undefined;
  const { nonce: _ignored, ...rest } = options;
  const headers = buildHeaders({ ...rest, nonce, strictDynamic: wantNonce ? options.strictDynamic : options.strictDynamic && (rest.scriptHashes || []).length > 0 });
  let out = new Response(response.body, response);
  for (const [name, value] of Object.entries(headers)) out.headers.set(name, value);
  out.headers.delete('X-Powered-By');
  if (wantNonce) {
    const stamp = { element: (el) => el.setAttribute('nonce', nonce) };
    out = new Rewriter().on('script', stamp).on('style', stamp).on('link[rel="stylesheet"]', stamp).transform(out);
  }
  return out;
}
