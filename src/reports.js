// Normalizes CSP violation reports from both formats browsers send:
//   application/csp-report      {"csp-report": {...}}           (report-uri, all browsers)
//   application/reports+json    [{"type":"csp-violation","body":{...}}]  (report-to, Chromium)
export function parseCspReports(body) {
  let data = body;
  if (typeof body === 'string') {
    try {
      data = JSON.parse(body);
    } catch {
      return [];
    }
  }
  const items = Array.isArray(data) ? data : [data];
  const out = [];
  for (const item of items) {
    if (item && item['csp-report']) {
      const r = item['csp-report'];
      out.push({ page: r['document-uri'], directive: r['effective-directive'] || r['violated-directive'], blocked: r['blocked-uri'], source: r['source-file'], line: r['line-number'], sample: r['script-sample'], disposition: r.disposition });
    } else if (item && item.type === 'csp-violation' && item.body) {
      const r = item.body;
      out.push({ page: r.documentURL, directive: r.effectiveDirective, blocked: r.blockedURL, source: r.sourceFile, line: r.lineNumber, sample: r.sample, disposition: r.disposition });
    }
  }
  // Browser extensions trigger noisy reports that are not about your site.
  return out.filter((r) => !/^(chrome|moz|safari|safari-web)-extension:/.test(r.blocked || '') && !/^(chrome|moz)-extension:/.test(r.source || ''));
}
