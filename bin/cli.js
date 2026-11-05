#!/usr/bin/env node
// security-headers: build or check web security headers. No dependencies.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { buildHeaders } from '../src/policy.js';
import { FORMATS } from '../src/formats.js';
import { SERVICES } from '../src/services.js';
import { inlineHashes } from '../src/hash.js';
import { checkHeaders } from '../src/check.js';

const HELP = `security-headers <command> [options]

Commands
  build     Print a ready-to-paste header config
  check     Fetch a URL and grade its security headers
  hash      Print CSP hashes for inline <script>/<style> in HTML files or folders
  services  List the third-party services the CSP builder knows

build options
  --format <name>      ${Object.keys(FORMATS).join(' | ')} (default: json)
  --preset <name>      strict | balanced (default: strict)
  --services a,b       e.g. google-analytics,google-fonts
  --hash-from <path>   add hashes of inline scripts/styles found in this HTML file or folder
  --inline-styles      allow inline styles ('unsafe-inline' in style-src only)
  --extra dir=src,...  extra sources, e.g. --extra img-src=https://img.example.com
  --report-only        start in report-only mode (recommended for the first week)
  --report-uri <url>   where browsers send CSP violation reports
  --hsts-preload       add "preload" to HSTS (see README first)
  --allow-framing      let other sites embed your pages in iframes

Examples
  npx security-headers build --format netlify --services google-analytics,google-fonts
  npx security-headers check https://example.com`;

function parse(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) out._.push(a);
    else if (['--inline-styles', '--report-only', '--hsts-preload', '--allow-framing', '--help'].includes(a)) out[a.slice(2)] = true;
    else out[a.slice(2)] = argv[++i];
  }
  return out;
}

function htmlFiles(path) {
  if (statSync(path).isFile()) return [path];
  return readdirSync(path).flatMap((f) => (statSync(join(path, f)).isDirectory() ? htmlFiles(join(path, f)) : f.endsWith('.html') ? [join(path, f)] : []));
}

function hashesFrom(path) {
  const scripts = new Set();
  const styles = new Set();
  for (const file of htmlFiles(path)) {
    const h = inlineHashes(readFileSync(file, 'utf8'));
    h.scripts.forEach((x) => scripts.add(x));
    h.styles.forEach((x) => styles.add(x));
  }
  return { scripts: [...scripts], styles: [...styles] };
}

async function main() {
  const args = parse(process.argv.slice(2));
  const cmd = args._[0];
  if (!cmd || args.help) return console.log(HELP);
  if (cmd === 'services') {
    for (const [k, v] of Object.entries(SERVICES)) console.log(`${k.padEnd(26)} ${v.label}`);
    return;
  }
  if (cmd === 'hash') {
    const h = hashesFrom(args._[1] || '.');
    console.log(`script hashes (${h.scripts.length}):\n${h.scripts.map((x) => `  '${x}'`).join('\n')}`);
    console.log(`style hashes (${h.styles.length}):\n${h.styles.map((x) => `  '${x}'`).join('\n')}`);
    return;
  }
  if (cmd === 'build') {
    const format = args.format || 'json';
    if (!FORMATS[format]) throw new Error(`Unknown format "${format}". Use one of: ${Object.keys(FORMATS).join(', ')}`);
    const extra = {};
    if (args.extra) for (const part of String(args.extra).split(';')) {
      const [dir, list] = part.split('=');
      extra[dir.trim()] = list.split(',').map((s) => s.trim()).filter(Boolean);
    }
    const hashes = args['hash-from'] ? hashesFrom(args['hash-from']) : { scripts: [], styles: [] };
    const headers = buildHeaders({
      preset: args.preset,
      services: args.services ? String(args.services).split(',').map((s) => s.trim()).filter(Boolean) : [],
      scriptHashes: hashes.scripts,
      styleHashes: hashes.styles,
      unsafeInlineStyles: args['inline-styles'],
      extra,
      reportOnly: args['report-only'],
      reportUri: args['report-uri'],
      hstsPreload: args['hsts-preload'],
      allowFraming: args['allow-framing'],
    });
    process.stdout.write(FORMATS[format](headers));
    return;
  }
  if (cmd === 'check') {
    const url = args._[1];
    if (!url) throw new Error('Usage: security-headers check https://example.com');
    const res = await fetch(url, { redirect: 'follow' });
    const result = checkHeaders(Object.fromEntries(res.headers));
    console.log(`${res.url}  →  grade ${result.grade}\n`);
    for (const f of result.findings) console.log(`${f.level.toUpperCase().padEnd(5)} ${f.header}: ${f.message}`);
    if (!result.findings.length) console.log('No problems found.');
    process.exitCode = /^[A]/.test(result.grade) ? 0 : 1;
    return;
  }
  throw new Error(`Unknown command "${cmd}". Run with --help.`);
}

main().catch((e) => {
  console.error(e.message);
  process.exitCode = 2;
});
