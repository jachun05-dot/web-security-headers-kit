// Finds inline <script> and <style> blocks in HTML and returns their CSP hashes.
import { createHash } from 'node:crypto';

const sha = (text) => `sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}`;

export function inlineHashes(html) {
  const scripts = [];
  const styles = [];
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const attrs = m[1];
    if (/\bsrc\s*=/i.test(attrs)) continue; // external file, allowed by URL instead
    const type = (/\btype\s*=\s*["']?([^"'\s>]+)/i.exec(attrs) || [])[1];
    // JSON-LD and other data blocks are not executed, so CSP ignores them.
    if (type && !/^(text\/javascript|module|application\/javascript)$/i.test(type)) continue;
    if (m[2].trim()) scripts.push(sha(m[2]));
  }
  for (const m of html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) if (m[1].trim()) styles.push(sha(m[1]));
  return { scripts: [...new Set(scripts)], styles: [...new Set(styles)] };
}
