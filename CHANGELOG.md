# Changelog

## 1.1.0

- Per-request nonces (`createNonce`), `'strict-dynamic'`, and Trusted Types
- Express middleware (`web-security-headers-kit/express`) and Cloudflare Worker helper (`web-security-headers-kit/worker`) that stamp nonces automatically
- Violation reporting: `report-uri` + `report-to` with `Reporting-Endpoints`, and `parseCspReports` for both report formats
- `check` is now a full site audit: HTTPS redirect, cookie flags, mixed content, missing SRI, inline handlers, CORS and security.txt; `--json` for CI
- New commands: `sri` (Subresource Integrity) and `securitytxt` (RFC 9116)
- More CSP checks: missing `default-src`, `data:` scripts, wildcard defaults
- CI on Node 20, 22 and 24; SECURITY.md; requires Node 20+

## 1.0.0

- Header builder with strict and balanced presets, service-aware CSP, inline hashing, platform configs and a header checker
