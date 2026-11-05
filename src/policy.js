// Builds a full set of security headers from a few options. No dependencies.
import { SERVICES } from './services.js';

export const PRESETS = ['strict', 'balanced'];

const DIRECTIVE_ORDER = [
  'default-src', 'script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'media-src',
  'frame-src', 'worker-src', 'manifest-src', 'object-src', 'base-uri', 'form-action', 'frame-ancestors',
];

/**
 * @param {object} o
 * @param {'strict'|'balanced'} [o.preset]   strict: tightest defaults. balanced: allows popups and cross-site embedding of your files.
 * @param {string[]} [o.services]            keys from SERVICES, e.g. ['google-analytics', 'google-fonts']
 * @param {string[]} [o.scriptHashes]        'sha256-…' hashes of inline <script> blocks you trust
 * @param {string[]} [o.styleHashes]         'sha256-…' hashes of inline <style> blocks
 * @param {boolean}  [o.unsafeInlineStyles]  allow style="" attributes and unhashed <style> (common, low risk)
 * @param {object}   [o.extra]               extra sources per directive, e.g. { 'img-src': ['https://images.example.com'] }
 * @param {boolean}  [o.reportOnly]          send Content-Security-Policy-Report-Only instead (for a safe rollout)
 * @param {string}   [o.reportUri]           where browsers send violation reports
 * @param {boolean}  [o.hstsPreload]         add "preload" to HSTS (read the README before turning this on)
 * @param {boolean}  [o.allowFraming]        let other sites put your pages in an iframe
 * @param {boolean}  [o.crossOriginIsolated] add COEP require-corp (needed for SharedArrayBuffer; breaks most third parties)
 */
export function buildHeaders(o = {}) {
  const preset = o.preset || 'strict';
  if (!PRESETS.includes(preset)) throw new Error(`Unknown preset "${preset}". Use one of: ${PRESETS.join(', ')}`);
  const csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'"],
    'img-src': ["'self'", 'data:'],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
    'frame-src': [],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': [o.allowFraming ? '*' : "'none'"],
  };
  for (const key of o.services || []) {
    const svc = SERVICES[key];
    if (!svc) throw new Error(`Unknown service "${key}". Known: ${Object.keys(SERVICES).join(', ')}`);
    for (const [dir, sources] of Object.entries(svc)) if (dir !== 'label') (csp[dir] ||= []).push(...sources);
  }
  for (const h of o.scriptHashes || []) csp['script-src'].push(quoteHash(h));
  for (const h of o.styleHashes || []) csp['style-src'].push(quoteHash(h));
  if (o.unsafeInlineStyles) csp['style-src'].push("'unsafe-inline'");
  for (const [dir, sources] of Object.entries(o.extra || {})) (csp[dir] ||= []).push(...sources);
  if (!csp['frame-src'].length) csp['frame-src'] = ["'none'"];
  if (o.reportUri) csp['report-uri'] = [o.reportUri];

  const value = [...DIRECTIVE_ORDER, ...Object.keys(csp).filter((d) => !DIRECTIVE_ORDER.includes(d))]
    .filter((d) => csp[d] && csp[d].length)
    .map((d) => `${d} ${[...new Set(csp[d])].join(' ')}`)
    .concat(o.reportOnly ? [] : ['upgrade-insecure-requests'])
    .join('; ');

  const headers = {
    [o.reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy']: value,
    'Strict-Transport-Security': `max-age=63072000; includeSubDomains${o.hstsPreload ? '; preload' : ''}`,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
    'Cross-Origin-Opener-Policy': preset === 'strict' ? 'same-origin' : 'same-origin-allow-popups',
    'Cross-Origin-Resource-Policy': preset === 'strict' ? 'same-origin' : 'cross-origin',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Origin-Agent-Cluster': '?1',
  };
  if (!o.allowFraming) headers['X-Frame-Options'] = 'DENY';
  if (o.crossOriginIsolated) headers['Cross-Origin-Embedder-Policy'] = 'require-corp';
  // Ads and payment popups need to keep a link back to your page.
  if ((o.services || []).some((s) => ['google-adsense', 'stripe'].includes(s))) headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups';
  return headers;
}

function quoteHash(h) {
  const v = h.replace(/^'|'$/g, '');
  if (!/^sha(256|384|512)-[A-Za-z0-9+/=]+$/.test(v)) throw new Error(`Not a CSP hash: ${h}`);
  return `'${v}'`;
}
