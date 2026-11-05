// RFC 9116 security.txt: tells researchers how to report a problem to you.
// Serve it at /.well-known/security.txt.
export function buildSecurityTxt({ contact, expires, preferredLanguages, canonical, policy, acknowledgments, hiring } = {}) {
  const contacts = [].concat(contact || []);
  if (!contacts.length) throw new Error('security.txt needs at least one Contact (mailto: or https: URL).');
  for (const c of contacts) if (!/^(mailto:|https:\/\/|tel:)/.test(c)) throw new Error(`Contact must be a mailto:, https: or tel: URI: ${c}`);
  const exp = expires ? new Date(expires) : new Date(Date.now() + 365 * 86400000);
  if (Number.isNaN(exp.getTime())) throw new Error('Expires is not a valid date.');
  if (exp.getTime() - Date.now() > 366 * 86400000) throw new Error('RFC 9116 recommends Expires less than a year away.');
  const lines = [...contacts.map((c) => `Contact: ${c}`), `Expires: ${exp.toISOString().replace(/\.\d{3}Z$/, 'Z')}`];
  if (preferredLanguages) lines.push(`Preferred-Languages: ${[].concat(preferredLanguages).join(', ')}`);
  if (canonical) lines.push(`Canonical: ${canonical}`);
  if (policy) lines.push(`Policy: ${policy}`);
  if (acknowledgments) lines.push(`Acknowledgments: ${acknowledgments}`);
  if (hiring) lines.push(`Hiring: ${hiring}`);
  return `${lines.join('\n')}\n`;
}
