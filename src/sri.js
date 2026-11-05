// Subresource Integrity: lets the browser refuse a CDN file that was changed.
import { createHash } from 'node:crypto';

export function sriHash(content, algorithm = 'sha384') {
  if (!['sha256', 'sha384', 'sha512'].includes(algorithm)) throw new Error(`Unsupported algorithm ${algorithm}`);
  return `${algorithm}-${createHash(algorithm).update(content).digest('base64')}`;
}

export async function sriForUrl(url, { fetch: f = globalThis.fetch, algorithm = 'sha384' } = {}) {
  const res = await f(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const integrity = sriHash(buf, algorithm);
  const tag = /\.css(\?|$)/.test(url) ? `<link rel="stylesheet" href="${url}" integrity="${integrity}" crossorigin="anonymous">` : `<script src="${url}" integrity="${integrity}" crossorigin="anonymous"></script>`;
  return { url, integrity, tag };
}
