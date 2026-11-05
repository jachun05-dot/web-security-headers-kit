# web-security-headers-kit

Strong, ready-to-paste **HTTP security headers** for any website, with:

- configs for **Cloudflare (Pages and Workers), Netlify, Vercel, Nginx, Apache and Express**
- a **Content Security Policy builder** that knows what common services need (Google Analytics, AdSense, Google Fonts, YouTube, Stripe and more)
- a **hasher** that finds your inline `<script>` and `<style>` blocks and allows exactly those, so you don't need `'unsafe-inline'`
- a **checker** that grades any live URL

No dependencies. Node 18 or newer. MIT licensed.

[한국어 설명서 (README.ko.md)](README.ko.md)

## What this does and doesn't protect

Security headers tell the browser to refuse dangerous behavior on your pages. They are one of the cheapest, highest-value protections a site can add:

| Header | Stops |
| --- | --- |
| `Content-Security-Policy` | Injected scripts (XSS), data sent to unknown hosts, your page being framed |
| `Strict-Transport-Security` | Downgrades to plain HTTP and cookie theft on public Wi-Fi |
| `X-Frame-Options` + `frame-ancestors` | Clickjacking (your page hidden inside another site) |
| `X-Content-Type-Options` | Browsers treating an upload as a script |
| `Referrer-Policy` | Full URLs (with tokens or search terms) leaking to other sites |
| `Permissions-Policy` | Camera, microphone, location and similar APIs being used without reason |
| `Cross-Origin-Opener-Policy` / `-Resource-Policy` | Cross-window attacks and other sites reading your files |

They **do not** fix bugs in your server code: SQL injection, broken login or access control, outdated dependencies, leaked secrets or weak passwords. See the [checklist](#beyond-headers-checklist) at the end.

## Quick start

1. **Check where you are now**

   ```bash
   npx github:YOUR_NAME/web-security-headers-kit check https://your-site.com
   ```

   (Or clone the repository and run `node bin/cli.js check https://your-site.com`.)

2. **List the outside services your pages load**

   ```bash
   node bin/cli.js services
   ```

3. **Build a config for your platform, in report-only mode first**

   ```bash
   node bin/cli.js build --format netlify \
     --services google-analytics,google-fonts \
     --hash-from ./public \
     --report-only
   ```

   `--hash-from` scans your built HTML and allows each inline script and style by its hash. Re-run it whenever an inline script changes.

4. **Deploy, then browse your site with the developer console open.** Report-only mode never breaks anything; it only prints a warning for anything the policy would block. Add what's missing with `--services` or `--extra`, rebuild, and repeat.

5. **Remove `--report-only`, deploy again, and re-run `check`.** Aim for grade A or A+.

## Formats

| `--format` | Where it goes |
| --- | --- |
| `netlify` / `cloudflare-pages` | A file named `_headers` in your publish folder |
| `vercel` | Merge into `vercel.json` |
| `nginx` | Inside your HTTPS `server { }` block |
| `apache` | `.htaccess` or your `VirtualHost` (needs `mod_headers`) |
| `express` | A middleware function: `app.use(securityHeaders)` |
| `cloudflare-worker` | A Worker in front of your site or static assets |
| `json` | Plain header map for anything else |

Ready-made examples (with Google Fonts allowed) are in [`examples/`](examples).

## Options

| Option | Meaning |
| --- | --- |
| `--preset strict` | Default. Tightest settings: no framing, same-origin isolation. |
| `--preset balanced` | Allows pop-ups (OAuth, payments) and lets other sites embed your images and files. |
| `--services a,b` | Adds what each service needs. Run `services` to list them. |
| `--hash-from <path>` | Allows the inline scripts and styles found in that HTML file or folder. |
| `--inline-styles` | Allows inline styles (`style=""`). Low risk and often needed. Scripts stay locked down. |
| `--extra "img-src=https://cdn.example.com;connect-src=https://api.example.com"` | Any other sources. |
| `--report-only` | Sends `Content-Security-Policy-Report-Only`, which reports but never blocks. |
| `--report-uri <url>` | Endpoint that receives violation reports. |
| `--hsts-preload` | Adds `preload` to HSTS. Read the warning below first. |
| `--allow-framing` | Lets other sites put your pages in an iframe. |

### Use it from code

```js
import { buildHeaders, checkHeaders } from 'web-security-headers-kit';

const headers = buildHeaders({ services: ['google-analytics'], scriptHashes: ["sha256-…"] });
console.log(checkHeaders(headers).grade); // "A+"
```

## Common problems

- **Something stopped working after enforcing CSP.** Open the browser console. Each blocked item names the directive and the URL. Add the host with `--extra`, or the service with `--services`, then rebuild.
- **An inline script was blocked.** Its contents changed, so its hash changed. Re-run `build` with `--hash-from`. Inline event handlers like `onclick="…"` can't be hashed; move them into a script file.
- **Ads don't show.** Ad networks load from many changing domains. Use `--services google-adsense`, and expect to need report-only mode for a while to catch new hosts.
- **OAuth or payment pop-ups break.** Use `--preset balanced`.
- **Other sites can't show your images.** Use `--preset balanced` (it sets `Cross-Origin-Resource-Policy: cross-origin`).

### About HSTS preload

`--hsts-preload` lets you submit your domain to the browsers' built-in HTTPS-only list at hstspreload.org. Once listed, **every subdomain must work over HTTPS for years**, and removal takes months. Turn it on only when you are sure.

## Beyond headers: checklist

Headers are the browser's half of the job. For the server's half:

- [ ] Keep frameworks and dependencies updated (`npm audit`, Dependabot)
- [ ] Parameterized queries everywhere (no string-built SQL)
- [ ] Escape all user content in HTML; validate all input on the server
- [ ] Cookies: `Secure; HttpOnly; SameSite=Lax` (or `Strict`)
- [ ] CSRF protection on state-changing requests
- [ ] Rate limiting on logins and forms; strong password hashing (Argon2id or bcrypt)
- [ ] Secrets in environment variables, never in the repository
- [ ] Least-privilege access for databases and cloud accounts; two-factor authentication on admin accounts
- [ ] Backups that you have actually restored once
- [ ] A `/.well-known/security.txt` so people can report problems to you

## Development

```bash
npm test           # runs the test suite
npm run examples   # regenerates examples/
```

Contributions of new services are welcome: add an entry to `src/services.js` with the minimum sources the vendor documents, and a test.

## License

MIT
