// Regenerates examples/ so the README always matches the code.
import { writeFileSync, mkdirSync } from 'node:fs';
import { buildHeaders } from '../src/policy.js';
import { FORMATS } from '../src/formats.js';

const out = new URL('../examples/', import.meta.url);
mkdirSync(out, { recursive: true });
const names = { netlify: '_headers', vercel: 'vercel.json', nginx: 'nginx.conf', apache: '.htaccess', express: 'express-middleware.js', 'cloudflare-worker': 'cloudflare-worker.js', json: 'headers.json' };
const headers = buildHeaders({ services: ['google-fonts'] });
for (const [format, file] of Object.entries(names)) writeFileSync(new URL(file, out), FORMATS[format](headers));
console.log(`wrote ${Object.keys(names).length} examples`);
