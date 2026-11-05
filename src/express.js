// Express / Connect middleware with a fresh CSP nonce per request.
//   app.use(securityHeaders({ services: ['google-analytics'], strictDynamic: true }));
//   // in templates: <script nonce="<%= cspNonce %>">…</script>
import { buildHeaders, createNonce } from './policy.js';

export function securityHeaders(options = {}) {
  const useNonce = options.nonce !== false;
  const fixed = useNonce ? null : buildHeaders({ ...options, nonce: undefined });
  return function securityHeadersMiddleware(req, res, next) {
    let headers = fixed;
    if (useNonce) {
      const nonce = createNonce();
      res.locals = res.locals || {};
      res.locals.cspNonce = nonce;
      headers = buildHeaders({ ...options, nonce });
    }
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
    res.removeHeader('X-Powered-By');
    next();
  };
}
